// Package vrange 实现靶场靶标与 EXP 回归执行器——授权渗透测试平台的
// EXP 质量闸门，防能力腐烂。
//
// 战略背景：EXP 资产库（db/exp_assets.go）的复利前提是「库里的 EXP 真能打下来」。
// 上游组件升级、路径改版、判据漂移都会让一条 EXP 静默失效——没有靶场回归，
// 命中率统计会慢慢腐烂，复利就是假的。所以：EXP 入库（或更新）前必须在
// 受控靶标上真的打一遍，至少一个靶标 Pass 才放行（ValidateExpAgainstRange）。
//
// 包放置决策（任务口径是 `range/` 新包）：
//   - 目录按任务口径叫 range/，但 `range` 是 Go 关键字、不能作包名，
//     故包名为 vrange（vuln range）。导入方写：
//     `import vrange "github.com/Autumn-27/artex/range"`。
//   - 不放 db/：靶场是执行层关注点（起 HTTP 服务、跑请求模板），不是持久化；
//     db 反而被它依赖（ExpAsset 类型 + 指纹匹配器），放 db 会造成分层倒挂。
//   - 不放 server/：闸门是纯 Go 逻辑（httptest 靶标、无 PG、无 HTTP 路由），
//     server 只在写路径上调用它；独立成包让它与 atomic/ 同级——都是
//     「确定性执行层」。
//
// 合规语境：靶标全部是进程内自起的 mock（httptest），不打外网、不需要 docker；
// 回归执行只发生在本机回环地址上。EXP 对真实目标的使用边界由任务 scope 与
// 拦截层把关，与本包无关。
package vrange

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
)

// VulnTarget 是一个回归靶标：受控环境里的一份「带已知漏洞/特征的模拟资产」。
// 它声明两件质量闸门关心的事：
//   - 预期 EXP 应命中的指纹（Fingerprint，db.AssetFingerprint 形态）——
//     正确 EXP 的 fingerprint_match 必须命中它，这是「EXP 找对了目标」的判据；
//   - 预期成功判据（SuccessOracle，与 db.ExpAsset.success_oracle 同构的
//     status_codes/keywords/regex）——正确 EXP 打出来的响应必须满足它，
//     这是「EXP 真的触发了漏洞效果」的靶标侧 ground truth，防 EXP 把
//     success_oracle 写得过松（打到任意 200 页面就自称成功）。
type VulnTarget struct {
	// Name 靶标唯一标识（kebab-case，进回归报告）。
	Name string `json:"name"`
	// Component / Version 靶标模拟的组件与版本（指纹维度，与 EXP 指纹条件的
	// components.name / version_range 对齐）。
	Component string `json:"component"`
	Version   string `json:"version"`
	// Desc 靶标说明：模拟什么漏洞、验证路径覆盖哪个原子操作。
	Desc string `json:"description"`
	// Launch 启动方式说明：builtin-httptest（内置纯 Go，默认）| docker（未来扩展）。
	// 内置靶标由 Start() 在进程内起 httptest 服务，无需 docker、无外网。
	Launch string `json:"launch"`

	// Fingerprint 靶标作为「资产」的指纹 JSON（db.AssetFingerprint 形态：
	// technologies/components/port/path）。回归时执行器会把运行实例的 URL
	// 合并进来再做匹配，EXP 的 paths 维度条件因此可用。
	Fingerprint json.RawMessage `json:"fingerprint"`

	// SuccessOracle 靶标侧 ground-truth 成功判据 JSON。
	SuccessOracle json.RawMessage `json:"success_oracle"`

	// start 启动靶标实例（内置实现为 httptest；不导出，统一走 Start()）。
	start func() (*TargetInstance, error)
}

// TargetInstance 是一个运行中的靶标实例。BaseURL 注入 EXP 执行模板的
// {target} 占位符；用完必须 Stop（httptest 服务器占着回环端口）。
type TargetInstance struct {
	// Target 指向起实例的靶标定义（只读）。
	Target *VulnTarget
	// BaseURL 完整基地址（http://127.0.0.1:port）。
	BaseURL string

	stop func()
}

// Stop 关停实例（幂等：httptest.Close 自身幂等，二次调用为 no-op）。
func (i *TargetInstance) Stop() {
	if i != nil && i.stop != nil {
		i.stop()
	}
}

// Start 启动靶标（内置靶标 = 进程内 httptest 服务器）。靶标定义不可变、
// 可重复 Start，每次返回独立实例——回归矩阵可以随意复用同一靶标定义。
func (t *VulnTarget) Start() (*TargetInstance, error) {
	if t == nil || t.start == nil {
		return nil, fmt.Errorf("靶标 %q 没有可用的启动器", t.Name)
	}
	return t.start()
}

// httptestTarget 构造一个内置纯 Go 靶标：handler 进程内起 httptest，
// Launch 标注 builtin-httptest。
func httptestTarget(name, component, version, desc, fingerprint, oracle string, h http.Handler) *VulnTarget {
	var t *VulnTarget
	t = &VulnTarget{
		Name:          name,
		Component:     component,
		Version:       version,
		Desc:          desc,
		Launch:        "builtin-httptest",
		Fingerprint:   json.RawMessage(fingerprint),
		SuccessOracle: json.RawMessage(oracle),
		start: func() (*TargetInstance, error) {
			srv := httptest.NewServer(h)
			return &TargetInstance{Target: t, BaseURL: srv.URL, stop: srv.Close}, nil
		},
	}
	return t
}
