// Package valuesched 实现授权渗透测试平台的价值矩阵调度器：给每个
// (资产 × CVE × EXP) 候选打分并产出优先级队列，供平台每天取 Top N 任务执行
// （艾维利工作法内建进调度——先做最重要的 N 件，方向错了，成功率再高也是负资产）。
//
// 核心公式（授权渗透测试平台的任务优先级）：
//
//	score = asset_value × P(success) ÷ cost
//	价值 = 资产重要性 × 成功概率 ÷ 成本
//
// 本包是纯函数库：只依赖标准库，不 import db/server，调用方（每日调度循环/
// 任务下发侧）负责组装候选、消费排序结果。每个分数都带完整因子分解
// （Breakdown），可解释"为什么今天先打它"。
//
// 放置理由（独立顶层包而非 server 内聚模块）：打分与排序是纯计算，无
// HTTP/DB 依赖；server → valuesched 单向依赖不引入环；无需 Postgres 即可
// 全量测试（server/db 包测试依赖 DSN，缺失时会 skip）；与 guard/evidence/
// enrich 等聚焦职责的顶层包布局一致。集成点见 docs/价值矩阵调度.md。
package valuesched

import (
	"fmt"
	"math"
	"strings"
)

// tierBaseValues 是价值分层 → 基础价值映射，取值与 kt-vuln 资产目录的 tier
// 字段对齐（见 server/vuln_tools.go：tier S>A>B>C>D>E,exclude）。未识别/缺省 1.0。
var tierBaseValues = map[string]float64{
	"S": 4.0, // 战略级资产
	"A": 3.0,
	"B": 2.0,
	"C": 1.5,
	"D": 1.0,
	"E": 0.5,
	// exclude：明确排除的资产没有调度价值，基础价值记 0，自然沉底为 P4。
	"EXCLUDE": 0,
}

// 控制平面距离系数：拿下离控制平面越近的资产，横向移动杠杆越大。
// 任务口径：1 跳 ×2、2 跳 ×1.5、无图信息 1.0；这里补齐两档——0 跳（资产
// 自身即控制平面）与 1 跳同档 ×2，≥3 跳衰减回基线 1.0。
const (
	ControlPlaneSelfFactor    = 2.0 // 0 跳：资产自身即控制平面
	ControlPlaneOneHopFactor  = 2.0 // 1 跳
	ControlPlaneTwoHopFactor  = 1.5 // 2 跳
	ControlPlaneFarFactor     = 1.0 // ≥3 跳
	ControlPlaneUnknownFactor = 1.0 // 无图信息（hops 为 nil）
)

// 模型预算系数（cost 因子）：确定性收割直接跑 EXP 记 1.0；
// 需 LLM 猎杀的候选消耗模型预算，成本 ×3。
const (
	ModelBudgetDeterministic = 1.0
	ModelBudgetLLMHunt       = 3.0
)

// 未知概率因子的缺省值：P(指纹正确)/P(EXP可用) 无输入时按五五开。
const unknownProbability = 0.5

// 前置满足度概率（三态）：布尔 → 1/0.3，未验证折中 0.5。
const (
	prereqMetProbability     = 1.0 // 前置已满足
	prereqUnmetProbability   = 0.3 // 前置明确不满足（仍可打，但大幅折价）
	prereqUnknownProbability = 0.5 // 未验证
)

// maxRawScore 是归一化基准：理论最高 raw 分 = S 层基础价值(4.0) × 控制平面
// 最大系数(2.0) × P(success)=1 ÷ 最小成本(1.0) = 8.0。raw ÷ 8.0 × 100 → 0-100。
const maxRawScore = 4.0 * 2.0 * 1.0 / 1.0

// 优先级分档（基于 0-100 归一化分数）。
const (
	PriorityP0 = "P0" // ≥80：立即执行
	PriorityP1 = "P1" // ≥60：优先执行
	PriorityP2 = "P2" // ≥40：正常排入
	PriorityP3 = "P3" // ≥20：靠后
	PriorityP4 = "P4" // <20：垫底/暂缓
)

// Candidate 是一个待打分的 (资产 × CVE × EXP) 候选。组装方负责从 kt-vuln
// 资产目录（tier/指纹/verdict）与 EXP 元数据（命中率、前置、预估操作数）
// 填充；未知项留零值即可，内部有缺省规则，任何候选都能得出可解释的分数。
type Candidate struct {
	// 标识。去重键 = AssetID+CVE（同一资产同一 CVE 只保留最高分 EXP），
	// ExpID 用于多 EXP 竞争后追溯"最终选了哪个 EXP"。
	AssetID int64  `json:"asset_id"` // kt-vuln vuln_asset_id 或本地 assets.id
	CVE     string `json:"cve"`
	ExpID   string `json:"exp_id,omitempty"`

	// ── asset_value 因子 ──
	Tier              string  `json:"tier,omitempty"`                // 价值分层 S/A/B/C/D/E/exclude；空 = 未知 → 基础价值 1.0
	BaseValueOverride float64 `json:"base_value_override,omitempty"` // >0 时直接作为基础价值（如按 kt-vuln score 换算），否则按 Tier 映射
	ControlPlaneHops  *int    `json:"control_plane_hops,omitempty"`  // 与最近控制平面资产的图距离：nil = 无图信息 → 1.0；0 = 自身即控制平面；1/2/≥3 跳

	// ── P(success) 因子（指针 nil = 未知 → 0.5）──
	FingerprintConfidence *float64 `json:"fingerprint_confidence,omitempty"` // P(指纹正确)：资产指纹 vs CVE affected 范围匹配度，0-1
	ExpMaturity           *float64 `json:"exp_maturity,omitempty"`           // P(EXP可用)：EXP 历史命中率，0-1；无历史默认 0.5
	PrereqMet             *bool    `json:"prereq_met,omitempty"`             // 前置满足度：true→1.0 false→0.3 nil(未验证)→0.5

	// ── cost 因子 ──
	AtomicOps         int     `json:"atomic_ops"`          // 预估原子操作数（<1 钳制为 1）
	ModelBudgetFactor float64 `json:"model_budget_factor"` // 模型预算系数（<=0 → 1.0 确定性收割）；需 LLM 猎杀填 ModelBudgetLLMHunt
}

// Breakdown 是打分的完整因子分解（可解释性输出）：每一项都能对回输入字段，
// 供人工复核与任务快照留痕。
type Breakdown struct {
	// asset_value = 基础价值 × 控制平面距离系数
	BaseValue          float64 `json:"base_value"`            // 基础价值（Tier 映射或显式覆盖；缺省 1.0）
	HopsToControlPlane int     `json:"hops_to_control_plane"` // 解析后的图距离；-1 表示无图信息（输入 hops 为 nil）
	ControlPlaneFactor float64 `json:"control_plane_factor"`  // 控制平面距离系数
	AssetValue         float64 `json:"asset_value"`           // BaseValue × ControlPlaneFactor

	// P(success) = P(指纹正确) × P(EXP可用) × P(前置满足)
	PFingerprint float64 `json:"p_fingerprint"`
	PExp         float64 `json:"p_exp"`
	PPrereq      float64 `json:"p_prereq"`
	PSuccess     float64 `json:"p_success"` // 三者乘积

	// cost = 原子操作数(min 1) × 模型预算系数（effective_ 前缀 = 钳定后生效值，
	// 与 Candidate 同名输入字段区分开，避免嵌入后选择器/JSON 歧义）
	EffectiveOps         int     `json:"effective_ops"`          // 钳制后的原子操作数（>=1）
	EffectiveModelBudget float64 `json:"effective_model_budget"` // 钳定后的模型预算系数（>0，缺省 1.0）
	Cost                 float64 `json:"cost"`                   // EffectiveOps × EffectiveModelBudget

	// 汇总
	RawScore float64 `json:"raw_score"` // asset_value × P(success) ÷ cost（未归一化）
	Score    float64 `json:"score"`     // 0-100 归一化分数（两位小数）
	Priority string  `json:"priority"`  // P0-P4
}

// Scored 是打分结果：候选原样带回 + 分数与完整分解。
type Scored struct {
	Candidate
	Breakdown
}

// Ptr 返回指向 v 的指针，便于调用方内联构造可选因子（如 valuesched.Ptr(0.9)）。
func Ptr[T any](v T) *T { return &v }

// Score 对单个候选打分并给出完整因子分解。纯函数、不返回错误：所有未知/
// 非法输入按缺省规则收敛（详见各因子注释），保证任何候选都能得出可解释的分数。
func Score(c Candidate) Scored {
	var b Breakdown

	// asset_value = 基础价值 × 控制平面距离系数
	b.BaseValue = baseValue(c)
	b.HopsToControlPlane = -1
	if c.ControlPlaneHops != nil {
		b.HopsToControlPlane = *c.ControlPlaneHops
	}
	b.ControlPlaneFactor = controlPlaneFactor(b.HopsToControlPlane)
	b.AssetValue = b.BaseValue * b.ControlPlaneFactor

	// P(success) = P(指纹正确) × P(EXP可用) × P(前置满足)
	b.PFingerprint = clampProbability(c.FingerprintConfidence)
	b.PExp = clampProbability(c.ExpMaturity)
	b.PPrereq = prereqProbability(c.PrereqMet)
	b.PSuccess = b.PFingerprint * b.PExp * b.PPrereq

	// cost = 原子操作数(min 1) × 模型预算系数（>0）
	b.EffectiveOps = max(c.AtomicOps, 1)
	if c.ModelBudgetFactor <= 0 {
		b.EffectiveModelBudget = ModelBudgetDeterministic
	} else {
		b.EffectiveModelBudget = c.ModelBudgetFactor
	}
	b.Cost = float64(b.EffectiveOps) * b.EffectiveModelBudget

	// raw ÷ 理论满分 → 0-100；cost 结构上恒 >0，除零分支仅作防御（非法输入不 panic）。
	if b.Cost > 0 {
		b.RawScore = b.AssetValue * b.PSuccess / b.Cost
	}
	b.Score = round2(clamp01(b.RawScore/maxRawScore) * 100)
	b.Priority = priorityOf(b.Score)
	return Scored{Candidate: c, Breakdown: b}
}

// baseValue 计算基础价值：显式覆盖（>0）> Tier 映射 > 缺省 1.0。
func baseValue(c Candidate) float64 {
	if c.BaseValueOverride > 0 {
		return c.BaseValueOverride
	}
	if v, ok := tierBaseValues[tierKey(c.Tier)]; ok {
		return v
	}
	return 1.0
}

func tierKey(tier string) string { return strings.ToUpper(strings.TrimSpace(tier)) }

// controlPlaneFactor 按与最近控制平面资产的图距离取系数：
// <0 无图信息 1.0；0 跳（自身即控制平面）与 1 跳 ×2；2 跳 ×1.5；≥3 跳 1.0。
func controlPlaneFactor(hops int) float64 {
	switch {
	case hops < 0:
		return ControlPlaneUnknownFactor
	case hops <= 1:
		return ControlPlaneOneHopFactor
	case hops == 2:
		return ControlPlaneTwoHopFactor
	default:
		return ControlPlaneFarFactor
	}
}

// clampProbability 把可选概率收敛到 [0,1]；nil = 未知 → 0.5。
func clampProbability(v *float64) float64 {
	if v == nil {
		return unknownProbability
	}
	return math.Min(1, math.Max(0, *v))
}

// prereqProbability 前置满足度三态：true→1.0 false→0.3 nil(未验证)→0.5。
func prereqProbability(met *bool) float64 {
	switch {
	case met == nil:
		return prereqUnknownProbability
	case *met:
		return prereqMetProbability
	default:
		return prereqUnmetProbability
	}
}

func priorityOf(score float64) string {
	switch {
	case score >= 80:
		return PriorityP0
	case score >= 60:
		return PriorityP1
	case score >= 40:
		return PriorityP2
	case score >= 20:
		return PriorityP3
	default:
		return PriorityP4
	}
}

func clamp01(v float64) float64 { return math.Min(1, math.Max(0, v)) }

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// Explain 输出单行中文因子链，用于日志/任务快照里直接回答"为什么先打它"。
func (s Scored) Explain() string {
	hops := "无图信息"
	if s.HopsToControlPlane >= 0 {
		hops = fmt.Sprintf("%d跳", s.HopsToControlPlane)
	}
	return fmt.Sprintf(
		"资产#%d %s %s：%.1f分(%s) = 资产价值%.2g[基础%.2g×控制平面%.2g(%s)] × P(成功)%.2g[指纹%.2g×EXP%.2g×前置%.2g] ÷ 成本%.2g[%d操作×系数%.2g]",
		s.AssetID, s.CVE, s.ExpID, s.Score, s.Priority,
		s.AssetValue, s.BaseValue, s.ControlPlaneFactor, hops,
		s.PSuccess, s.PFingerprint, s.PExp, s.PPrereq,
		s.Cost, s.EffectiveOps, s.EffectiveModelBudget)
}
