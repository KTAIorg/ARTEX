package valuesched

import (
	"math"
	"strings"
	"testing"
)

// almostEqual 容忍二进制浮点误差（因子取值 0.5/1.5/2/3/4 均为精确值，
// 0.3/0.9/0.8 这类输入的乘积有微小舍入）。
func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// cmpBreakdown 逐因子对比分解明细，返回第一个不一致的字段名（可解释性输出的
// 正确性靠它保证：每个分数都能对回每个因子）。
func cmpBreakdown(got, want Breakdown) string {
	floats := []struct {
		name  string
		gotV  float64
		wantV float64
	}{
		{"BaseValue", got.BaseValue, want.BaseValue},
		{"ControlPlaneFactor", got.ControlPlaneFactor, want.ControlPlaneFactor},
		{"AssetValue", got.AssetValue, want.AssetValue},
		{"PFingerprint", got.PFingerprint, want.PFingerprint},
		{"PExp", got.PExp, want.PExp},
		{"PPrereq", got.PPrereq, want.PPrereq},
		{"PSuccess", got.PSuccess, want.PSuccess},
		{"EffectiveModelBudget", got.EffectiveModelBudget, want.EffectiveModelBudget},
		{"Cost", got.Cost, want.Cost},
		{"RawScore", got.RawScore, want.RawScore},
		{"Score", got.Score, want.Score},
	}
	for _, f := range floats {
		if !almostEqual(f.gotV, f.wantV) {
			return f.name
		}
	}
	ints := []struct {
		name  string
		gotV  int
		wantV int
	}{
		{"HopsToControlPlane", got.HopsToControlPlane, want.HopsToControlPlane},
		{"EffectiveOps", got.EffectiveOps, want.EffectiveOps},
	}
	for _, f := range ints {
		if f.gotV != f.wantV {
			return f.name
		}
	}
	if got.Priority != want.Priority {
		return "Priority"
	}
	return ""
}

func TestScoreFactorBreakdown(t *testing.T) {
	tests := []struct {
		name string
		c    Candidate
		want Breakdown
	}{
		{
			name: "全因子明确：S层+1跳+高概率+LLM猎杀",
			c: Candidate{
				AssetID: 101, CVE: "CVE-2023-46604", ExpID: "exp-atomic",
				Tier:                  "S",
				ControlPlaneHops:      Ptr(1),
				FingerprintConfidence: Ptr(0.9),
				ExpMaturity:           Ptr(0.8),
				PrereqMet:             Ptr(true),
				AtomicOps:             2,
				ModelBudgetFactor:     ModelBudgetLLMHunt,
			},
			// 4.0×2.0=8.0；0.9×0.8×1.0=0.72；2×3.0=6.0；raw=8.0×0.72/6.0=0.96 → 12.00
			want: Breakdown{
				BaseValue: 4.0, HopsToControlPlane: 1, ControlPlaneFactor: 2.0, AssetValue: 8.0,
				PFingerprint: 0.9, PExp: 0.8, PPrereq: 1.0, PSuccess: 0.72,
				EffectiveOps: 2, EffectiveModelBudget: 3.0, Cost: 6.0,
				RawScore: 0.96, Score: 12.0, Priority: PriorityP4,
			},
		},
		{
			name: "全部 unknown：零值候选走缺省",
			c:    Candidate{AssetID: 1, CVE: "CVE-2024-0001"},
			// 1.0×1.0=1.0；0.5³=0.125；1×1.0=1.0；raw=0.125 → 1.56
			want: Breakdown{
				BaseValue: 1.0, HopsToControlPlane: -1, ControlPlaneFactor: 1.0, AssetValue: 1.0,
				PFingerprint: 0.5, PExp: 0.5, PPrereq: 0.5, PSuccess: 0.125,
				EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0,
				RawScore: 0.125, Score: 1.56, Priority: PriorityP4,
			},
		},
		{
			name: "理论满分：S层+1跳+全概率1+最小成本",
			c: Candidate{
				Tier:                  "S",
				ControlPlaneHops:      Ptr(1),
				FingerprintConfidence: Ptr(1.0),
				ExpMaturity:           Ptr(1.0),
				PrereqMet:             Ptr(true),
				AtomicOps:             1,
			},
			want: Breakdown{
				BaseValue: 4.0, HopsToControlPlane: 1, ControlPlaneFactor: 2.0, AssetValue: 8.0,
				PFingerprint: 1.0, PExp: 1.0, PPrereq: 1.0, PSuccess: 1.0,
				EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0,
				RawScore: 8.0, Score: 100.0, Priority: PriorityP0,
			},
		},
		{
			name: "exclude 层沉底",
			c:    Candidate{Tier: "exclude"},
			want: Breakdown{
				BaseValue: 0, HopsToControlPlane: -1, ControlPlaneFactor: 1.0, AssetValue: 0,
				PFingerprint: 0.5, PExp: 0.5, PPrereq: 0.5, PSuccess: 0.125,
				EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0,
				RawScore: 0, Score: 0, Priority: PriorityP4,
			},
		},
		{
			name: "tier 小写带空格归一",
			c:    Candidate{Tier: "  a "},
			want: Breakdown{
				BaseValue: 3.0, HopsToControlPlane: -1, ControlPlaneFactor: 1.0, AssetValue: 3.0,
				PFingerprint: 0.5, PExp: 0.5, PPrereq: 0.5, PSuccess: 0.125,
				EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0,
				RawScore: 0.375, Score: 4.69, Priority: PriorityP4,
			},
		},
		{
			name: "基础价值显式覆盖优先于 tier 映射",
			c:    Candidate{Tier: "E", BaseValueOverride: 2.5},
			want: Breakdown{
				BaseValue: 2.5, HopsToControlPlane: -1, ControlPlaneFactor: 1.0, AssetValue: 2.5,
				PFingerprint: 0.5, PExp: 0.5, PPrereq: 0.5, PSuccess: 0.125,
				EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0,
				RawScore: 0.3125, Score: 3.91, Priority: PriorityP4,
			},
		},
		{
			name: "前置三态：true→1.0",
			c:    Candidate{PrereqMet: Ptr(true)},
			want: Breakdown{PPrereq: 1.0, PSuccess: 0.25, RawScore: 0.25, Score: 3.13, Priority: PriorityP4,
				BaseValue: 1.0, HopsToControlPlane: -1, ControlPlaneFactor: 1.0, AssetValue: 1.0,
				PFingerprint: 0.5, PExp: 0.5, EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0},
		},
		{
			name: "前置三态：false→0.3",
			c:    Candidate{PrereqMet: Ptr(false)},
			want: Breakdown{PPrereq: 0.3, PSuccess: 0.075, RawScore: 0.075, Score: 0.94, Priority: PriorityP4,
				BaseValue: 1.0, HopsToControlPlane: -1, ControlPlaneFactor: 1.0, AssetValue: 1.0,
				PFingerprint: 0.5, PExp: 0.5, EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0},
		},
		{
			name: "前置三态：nil 未验证→0.5",
			c:    Candidate{PrereqMet: nil},
			want: Breakdown{PPrereq: 0.5, PSuccess: 0.125, RawScore: 0.125, Score: 1.56, Priority: PriorityP4,
				BaseValue: 1.0, HopsToControlPlane: -1, ControlPlaneFactor: 1.0, AssetValue: 1.0,
				PFingerprint: 0.5, PExp: 0.5, EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0},
		},
		{
			name: "概率越界钳制到 [0,1]：1.7→1.0、-0.5→0",
			c:    Candidate{FingerprintConfidence: Ptr(1.7), ExpMaturity: Ptr(-0.5)},
			want: Breakdown{PFingerprint: 1.0, PExp: 0, PSuccess: 0, RawScore: 0, Score: 0, Priority: PriorityP4,
				BaseValue: 1.0, HopsToControlPlane: -1, ControlPlaneFactor: 1.0, AssetValue: 1.0,
				PPrereq: 0.5, EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0},
		},
		{
			name: "原子操作数 min 1：0 与负数都钳为 1",
			c:    Candidate{AtomicOps: -3},
			want: Breakdown{EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0, RawScore: 0.125, Score: 1.56,
				Priority: PriorityP4, BaseValue: 1.0, HopsToControlPlane: -1, ControlPlaneFactor: 1.0,
				AssetValue: 1.0, PFingerprint: 0.5, PExp: 0.5, PPrereq: 0.5, PSuccess: 0.125},
		},
		{
			name: "模型预算系数 0/负 → 确定性 1.0（除零防御，不 panic）",
			c:    Candidate{ModelBudgetFactor: -2},
			want: Breakdown{EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0, RawScore: 0.125, Score: 1.56,
				Priority: PriorityP4, BaseValue: 1.0, HopsToControlPlane: -1, ControlPlaneFactor: 1.0,
				AssetValue: 1.0, PFingerprint: 0.5, PExp: 0.5, PPrereq: 0.5, PSuccess: 0.125},
		},
		{
			name: "归一化封顶：显式覆盖基础价值超理论满分 → 100",
			c: Candidate{
				BaseValueOverride:     100,
				ControlPlaneHops:      Ptr(1),
				FingerprintConfidence: Ptr(1.0),
				ExpMaturity:           Ptr(1.0),
				PrereqMet:             Ptr(true),
			},
			want: Breakdown{BaseValue: 100, HopsToControlPlane: 1, ControlPlaneFactor: 2.0, AssetValue: 200,
				PFingerprint: 1.0, PExp: 1.0, PPrereq: 1.0, PSuccess: 1.0,
				EffectiveOps: 1, EffectiveModelBudget: 1.0, Cost: 1.0,
				RawScore: 200, Score: 100, Priority: PriorityP0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Score(tt.c)
			if field := cmpBreakdown(got.Breakdown, tt.want); field != "" {
				t.Fatalf("分解字段 %s 不匹配：got=%+v want=%+v", field, got.Breakdown, tt.want)
			}
		})
	}
}

func TestControlPlaneFactor(t *testing.T) {
	tests := []struct {
		hops int
		want float64
	}{
		{-2, 1.0}, // 负数与 nil 同档：无图信息
		{-1, 1.0},
		{0, 2.0}, // 自身即控制平面
		{1, 2.0}, // 1 跳 ×2
		{2, 1.5}, // 2 跳 ×1.5
		{3, 1.0}, // ≥3 跳衰减回基线
		{9, 1.0},
	}
	for _, tt := range tests {
		if got := controlPlaneFactor(tt.hops); got != tt.want {
			t.Errorf("controlPlaneFactor(%d)=%v, want %v", tt.hops, got, tt.want)
		}
	}
	// nil hops（无图信息）必须走 1.0：零值候选绝不能被误加成 ×2。
	if got := Score(Candidate{}).ControlPlaneFactor; got != 1.0 {
		t.Fatalf("nil hops coefficient=%v, want 1.0", got)
	}
}

func TestPriorityBands(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0, PriorityP4},
		{19.99, PriorityP4},
		{20, PriorityP3},
		{39.99, PriorityP3},
		{40, PriorityP2},
		{59.99, PriorityP2},
		{60, PriorityP1},
		{79.99, PriorityP1},
		{80, PriorityP0},
		{100, PriorityP0},
	}
	for _, tt := range tests {
		if got := priorityOf(tt.score); got != tt.want {
			t.Errorf("priorityOf(%v)=%q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestExplain(t *testing.T) {
	s := Score(Candidate{
		AssetID: 101, CVE: "CVE-2023-46604", ExpID: "exp-atomic",
		Tier:                  "S",
		ControlPlaneHops:      Ptr(1),
		FingerprintConfidence: Ptr(0.9),
		ExpMaturity:           Ptr(0.8),
		PrereqMet:             Ptr(true),
		AtomicOps:             2,
		ModelBudgetFactor:     ModelBudgetLLMHunt,
	})
	got := s.Explain()
	for _, want := range []string{"资产#101", "CVE-2023-46604", "exp-atomic", "12.0分(P4)", "指纹0.9", "EXP0.8", "前置1", "1跳"} {
		if !strings.Contains(got, want) {
			t.Errorf("Explain() 缺少片段 %q：%s", want, got)
		}
	}
}
