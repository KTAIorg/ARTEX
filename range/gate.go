package vrange

// 入库闸门：EXP 进库（或更新）前的强制质量检查——至少一个内置靶标 Pass
// 才放行。这是 EXP 资产库「防能力腐烂」的执行点：上游组件升级、路径改版、
// 判据漂移都会让 EXP 静默失效；闸门把「失效」在写路径上变成显式失败，
// 而不是等 agent 在真实目标上碰一鼻子灰、把失败沉淀进台账才发现。
//
// 接线方式见 server/exp_library.go：Create/Update 的可选参数 WithRangeGate()。
// 刻意做成可选（而非无条件强制）：存量 EXP 与 command/script 类 EXP 尚无
// 对应靶标，一刀切会把库锁死；新登记/迭代 http 类 EXP 时应默认带上。

import (
	"context"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// GateResult 是一次闸门判定的结果（Allowed + 人类可读原因 + 全量报告留痕）。
type GateResult struct {
	// Allowed 是否放行：至少一个内置靶标 Pass。
	Allowed bool `json:"allowed"`
	// Reason 拒绝原因（放行为空）。
	Reason string `json:"reason,omitempty"`
	// PassedTargets 通过的靶标名（放行依据，进审计留痕）。
	PassedTargets []string `json:"passed_targets,omitempty"`
	// Report 全量回归报告（含每个靶标的失败原因，供 EXP 作者修模板）。
	Report *Report `json:"report"`
}

// ValidateExpAgainstRange 对一条 EXP 跑内置靶标全集，执行入库闸门判定。
// 纯 Go（httptest 靶标、回环流量、单请求默认 10s 超时），无 PG、无外网。
// 语义校验（形状是否合法）不在这里——那是 server.validateExpAsset 的职责；
// 这里只回答一个问题：这条 EXP 在受控靶场上「真的能打下来吗」。
func ValidateExpAgainstRange(ctx context.Context, e *db.ExpAsset) *GateResult {
	rep := RunRegression(ctx, []*db.ExpAsset{e}, BuiltinTargets())
	res := &GateResult{Report: rep}
	for _, c := range rep.Cases {
		if c.Pass {
			res.PassedTargets = append(res.PassedTargets, c.Target)
		}
	}
	res.Allowed = len(res.PassedTargets) > 0
	if res.Allowed {
		return res
	}
	// 拒绝原因分层：一个靶标都没命中指纹（指纹面写歪或太窄）vs 命中了
	// 却没打下来（模板/判据有 bug）——修复方向完全不同。
	if rep.FailedApplicable == 0 {
		res.Reason = fmt.Sprintf(
			"EXP %q 未命中任何内置靶标的指纹（%s）——指纹条件与靶场靶标对不上，无法验证。"+
				"EXP 库只收经靶场验证的能力，防上游升级后能力腐烂", e.Name, strings.Join(builtinTargetNames(), "、"))
		return res
	}
	var fails []string
	for _, c := range rep.Cases {
		if !c.Applicable || c.Pass {
			continue
		}
		why := c.ExecError
		if why == "" {
			why = c.ExpOracleFail
			if c.TargetOracleFail != "" {
				why += "；" + c.TargetOracleFail
			}
		}
		fails = append(fails, fmt.Sprintf("%s：%s", c.Target, why))
	}
	res.Reason = fmt.Sprintf(
		"EXP %q 在 %d 个适用靶标上全部失败（%s）——执行模板或成功判据有误。"+
			"EXP 库只收经靶场验证的能力，防上游升级后能力腐烂", e.Name, rep.FailedApplicable, strings.Join(fails, "；"))
	return res
}

func builtinTargetNames() []string {
	names := make([]string, 0, 3)
	for _, t := range BuiltinTargets() {
		names = append(names, t.Name)
	}
	return names
}
