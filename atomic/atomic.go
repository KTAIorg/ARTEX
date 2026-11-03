// Package atomic 实现 ARTEX 的「原子操作层」——授权渗透测试平台的确定性工具底座。
//
// 战略背景：ARTEX 是 AI 自主渗透测试系统，agent 用 LLM 做规划与决策。历史路径把
// 「确定性动作」（探测指纹、验证弱口令、执行 PoC）也放在 LLM 循环里执行，任何一次
// 执行偏差都会吃掉前面所有环节的成功率。成功率先验公式：
//
//	P(拿下) = P(指纹正确) × P(EXP可用) × P(前置满足) × P(执行无误)
//
// 本包修最后一项 P(执行无误)：把确定性动作拆出 LLM 循环，做成带类型契约的原子操作
// ——key + 描述 + JSON Schema（typed input/output）+ 幂等执行函数。LLM（无论贵贱、
// 是否受限）只负责决策与武器编写；执行一律走这里，同样的输入必然得到同样结构的输出。
//
// 合规语境：这些操作只能用于授权渗透测试范围内（engagement 授权）的目标。操作本身
// 不做越权判断——授权边界由上层任务/资产 scoping 管（与 Bash/自定义工具同一信任模型：
// 平台侧可信、目标侧受授权约束）。每个结果的 evidence 字段就是「做过什么」的留痕。
//
// 接入方式见 server/atomic_tools.go：注册表整体转成 actool.CoreTool、经 hostTools()
// 注入 agent 工具集，tools 表按 agent 绑定过滤（默认绑 worker + pentest），与
// customtool（command/script/http）体系并存、互不影响。
package atomic

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// objSchema / strParam 与 server 包同名助手同构：包内自持，避免反向依赖 server。
func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		m["required"] = req
	}
	return m
}

func strParam(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// Result 是所有原子操作的统一输出契约（输出 envelope）。三个必备字段：
//   - ok：动作是否成立（命中/验证通过/凭据有效）。执行失败与「结论为否」是两回事：
//     前者 error 非空、ok 恒为 false；后者 ok=false 且 error 为空。
//   - evidence：可留痕的输出片段——一句话能进报告、能进审计日志的判定依据。
//   - error：执行层失败原因（网络不可达、参数非法等），成功时为空。
//
// data 承载操作自身的结构化字段（由各操作的 OutputSchema 描述），duration_ms 由
// Execute 统一注入，调用方不需要也不应该自己计时。
type Result struct {
	OK         bool           `json:"ok"`
	Evidence   string         `json:"evidence"`
	Error      string         `json:"error,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	DurationMS int64          `json:"duration_ms"`
}

// Op 是一个原子操作的注册单元。Run 必须是幂等的确定性函数：同一输入在同一目标状态
// 下重复执行，输出一致（弱口令尝试这类「目标状态会被自身改变」的操作按语义近似：
// 结果要么命中要么未命中，重复执行结论不翻转）。
type Op struct {
	Key          string
	Description  string         // 面向模型的描述（含输出契约说明）
	InputSchema  map[string]any // 入参 JSON Schema
	OutputSchema map[string]any // 输出 envelope 的类型化描述（文档级契约）
	Run          func(ctx context.Context, in json.RawMessage) Result
}

// registry 是进程级注册表。操作在各自文件的 init() 里 Register，进程内不可变。
var (
	mu  sync.RWMutex
	ops = map[string]Op{}
)

// reOpKey 与 tools 表/agent key 同一命名规则：小写字母开头 + 小写字母/数字/下划线。
const reOpKeySrc = `^[a-z][a-z0-9_]*$`

func validKey(k string) bool {
	if len(k) < 3 || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		case c == '_' && i > 0:
		default:
			return false
		}
	}
	return true
}

// Register 登记一个原子操作。key 非法、重名、Run 为空都会报错——注册期失败要在
// 启动/测试期就炸出来，不带病运行。
func Register(op Op) error {
	if !validKey(op.Key) {
		return fmt.Errorf("atomic: key %q 非法（需小写字母开头，仅小写字母/数字/下划线，长度 3-64）", op.Key)
	}
	if op.Run == nil {
		return fmt.Errorf("atomic: op %s 缺少 Run 函数", op.Key)
	}
	if op.InputSchema == nil {
		return fmt.Errorf("atomic: op %s 缺少 InputSchema", op.Key)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := ops[op.Key]; dup {
		return fmt.Errorf("atomic: key %q 已注册", op.Key)
	}
	ops[op.Key] = op
	return nil
}

// Get 按 key 取操作（不存在时 ok=false）。
func Get(key string) (Op, bool) {
	mu.RLock()
	defer mu.RUnlock()
	op, ok := ops[key]
	return op, ok
}

// List 返回全部已注册操作，按 key 排序（seed 与工具装配顺序确定）。
func List() []Op {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Op, 0, len(ops))
	for _, op := range ops {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Execute 按 key 执行一个原子操作，是唯一推荐入口。它保证 envelope 契约：
//   - 操作不存在 → ok=false + error（而不是 panic/空结果）；
//   - Run panic → 恢复为 ok=false + error（单次调用失败不拖垮进程，对齐 server 侧
//     guardPanic 的哲学，但在这里就把边界封死，调用方拿到的永远是合法 Result）；
//   - evidence 为空时补一句兜底文案（契约要求 evidence 永远可留痕）；
//   - duration_ms 统一注入。
func Execute(ctx context.Context, key string, in json.RawMessage) (res Result) {
	op, ok := Get(key)
	if !ok {
		return Failf("原子操作 %q 未注册", key)
	}
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			res = Failf("原子操作 %s 内部错误：%v", key, r)
		}
		res.DurationMS = time.Since(start).Milliseconds()
		if res.Evidence == "" {
			res.Evidence = fmt.Sprintf("atomic.%s 执行完毕（无输出片段）", key)
		}
	}()
	return op.Run(ctx, in)
}

// Fail / Failf 构造执行失败的 Result（error 非空，ok 恒为 false）。
func Fail(err error) Result { return Failf("%v", err) }

func Failf(format string, args ...any) Result {
	return Result{OK: false, Error: fmt.Sprintf(format, args...)}
}

// OK 构造成功/命中 Result：evidence 必填，data 可为 nil。
func OK(evidence string, data map[string]any) Result {
	return Result{OK: true, Evidence: evidence, Data: data}
}

// OutputSchema 构造统一输出 envelope 的 JSON Schema 描述：三个必备字段 + 各操作
// 自身的 data 字段。它是文档级契约（服务端不据此反序列化校验），把「输出长什么样」
// 和输入 schema 一样显式写进代码，避免口头契约漂移。
func OutputSchema(dataProps map[string]any) map[string]any {
	if dataProps == nil {
		dataProps = map[string]any{}
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"ok":          map[string]any{"type": "boolean", "description": "动作是否成立（命中/验证通过/凭据有效）；false 且 error 为空表示结论为否"},
			"evidence":    map[string]any{"type": "string", "description": "可留痕的输出片段（判定依据，可直接进报告/审计日志）"},
			"error":       map[string]any{"type": "string", "description": "执行层失败原因（网络不可达/参数非法），成功或结论为否时为空"},
			"duration_ms": map[string]any{"type": "integer", "description": "执行耗时（毫秒），由执行器统一注入"},
			"data":        map[string]any{"type": "object", "properties": dataProps},
		},
		"required": []string{"ok", "evidence"},
	}
}

// decodeIn 把入参 JSON 解到目标结构（忽略未知字段）。解析失败返回错误——原子操作
// 的入参契约是硬边界，不猜。
func decodeIn(in json.RawMessage, v any) error {
	if len(in) == 0 {
		return nil
	}
	if err := json.Unmarshal(in, v); err != nil {
		return fmt.Errorf("入参不是合法 JSON 或类型不符：%w", err)
	}
	return nil
}
