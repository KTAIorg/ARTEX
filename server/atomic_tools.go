package server

// 原子操作层接入（docs/原子操作设计.md）：atomic 包的注册表整体转成 actool.CoreTool，
// 经 hostTools() 注入 agent 工具集；tools 表 seed（system=true、kind=builtin）后由
// ToolResolve 按 agent 绑定过滤，默认绑 worker + pentest（动手执行的两个 agent）。
//
// 与 customtool 的关系：customtool 的 kind(command/script/http) 描述的是「数据驱动的
// 执行规格」——exec JSON 存在 tools 表里、运行时渲染分派；原子操作的执行体是 Go 代码
// （确定性、类型化契约），走 builtin 通道（key+handler 在代码层，tools 行只承载描述/
// schema/绑定/开关）。两条通道在 hostTools() 汇合，互不影响。

import (
	"context"
	"encoding/json"
	"log"

	"github.com/Autumn-27/artex/atomic"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// atomicTools 把注册表里的每个原子操作包成一个 CoreTool。Run 只做一层薄封包：
// atomic.Execute 保证输出 envelope 契约（含 panic 恢复），这里序列化成 JSON 文本结果。
// 主动探测类动作：ReadOnly=false（对目标有副作用语义）、Concurrent=false（避免对
// 同一目标并发轰炸——限速语义靠单工具串行 + 操作内 delay 双保险）。
func (s *Server) atomicTools() []actool.CoreTool {
	ops := atomic.List()
	out := make([]actool.CoreTool, 0, len(ops))
	for _, op := range ops {
		out = append(out, atomicCoreTool(op))
	}
	return out
}

func atomicCoreTool(op atomic.Op) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        op.Key,
		Description: op.Description,
		Schema:      op.InputSchema,
		ReadOnly:    func(json.RawMessage) bool { return false },
		Concurrent:  func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			// 与 customtool 同一信任模型：平台侧可信工具（授权边界由任务/资产 scoping 管）。
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			res := atomic.Execute(ctx, op.Key, in)
			b, err := json.Marshal(res)
			if err != nil {
				return actool.Errorf("原子操作结果序列化失败: " + err.Error()), nil
			}
			return actool.Text(string(b)), nil
		},
	})
}

// seedAtomicTools 开机幂等 seed 原子操作进 tools 表（首插入生效，页面编辑不被覆盖）。
func (s *Server) seedAtomicTools() {
	agents, _ := json.Marshal([]string{"worker", "pentest"})
	for _, op := range atomic.List() {
		schema, err := json.Marshal(op.InputSchema)
		if err != nil {
			log.Printf("[atomic] seed %s schema 序列化失败: %v", op.Key, err)
			continue
		}
		if err := s.m.PG().SeedTool(op.Key, op.Description, schema, agents); err != nil {
			log.Printf("[atomic] seed %s 失败: %v", op.Key, err)
		}
	}
}
