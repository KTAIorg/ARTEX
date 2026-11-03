package valuesched

import "testing"

// 高分候选：确定性收割、前置满足、指纹/EXP 全明确。
func highScore(assetID int64, cve, expID string) Candidate {
	return Candidate{
		AssetID: assetID, CVE: cve, ExpID: expID,
		Tier:                  "S",
		ControlPlaneHops:      Ptr(1),
		FingerprintConfidence: Ptr(0.9),
		ExpMaturity:           Ptr(0.8),
		PrereqMet:             Ptr(true),
		AtomicOps:             1,
	}
}

// 低分候选：E 层、无图信息、全 unknown、LLM 猎杀。
func lowScore(assetID int64, cve, expID string) Candidate {
	return Candidate{
		AssetID: assetID, CVE: cve, ExpID: expID,
		Tier:                  "E",
		FingerprintConfidence: Ptr(0.4),
		ExpMaturity:           Ptr(0.3),
		PrereqMet:             Ptr(false),
		AtomicOps:             4,
		ModelBudgetFactor:     ModelBudgetLLMHunt,
	}
}

func TestRankDedupAndOrder(t *testing.T) {
	candidates := []Candidate{
		highScore(101, "CVE-2023-46604", "exp-b-second"), // 同资产同 CVE：低分 EXP，应被去重淘汰
		lowScore(101, "CVE-2023-46604", "exp-b-second"),
		highScore(101, "CVE-2024-21713", "exp-c"), // 同资产不同 CVE：保留
		highScore(202, "CVE-2023-46604", "exp-d"), // 不同资产同 CVE：保留
	}
	ranked := Rank(candidates)
	if len(ranked) != 3 {
		t.Fatalf("去重后队列长度=%d, want 3：%+v", len(ranked), ranked)
	}
	// 三个高分候选因子完全一致 → 同分，靠 (AssetID,CVE) 字典序稳定排序。
	wantKeys := [3]dedupKey{
		{101, "CVE-2023-46604"},
		{101, "CVE-2024-21713"},
		{202, "CVE-2023-46604"},
	}
	for i, s := range ranked {
		if got := (dedupKey{s.AssetID, s.CVE}); got != wantKeys[i] {
			t.Errorf("排名 %d = %v, want %v", i, got, wantKeys[i])
		}
	}
	// 淘汰的是低分 EXP：101+CVE-2023-46604 只剩 highScore 的 exp id（空串，
	// highScore 未设 ExpID——用指纹因子区分）：保留项 PSuccess 必须 0.72 而非低分的 0.4*0.3*0.3。
	kept := ranked[0]
	if !almostEqual(kept.PSuccess, 0.72) {
		t.Errorf("去重保留了低分 EXP：PSuccess=%v, want 0.72", kept.PSuccess)
	}
}

func TestRankDedupKeepsFirstOnEqualScore(t *testing.T) {
	// 两个完全同分的 EXP：保留输入顺序里的第一个，结果可预期、不随机。
	candidates := []Candidate{
		{AssetID: 303, CVE: "CVE-2025-0001", ExpID: "exp-first"},
		{AssetID: 303, CVE: "CVE-2025-0001", ExpID: "exp-second"},
	}
	ranked := Rank(candidates)
	if len(ranked) != 1 {
		t.Fatalf("去重后队列长度=%d, want 1", len(ranked))
	}
	if ranked[0].ExpID != "exp-first" {
		t.Errorf("同分去重保留了 %q, want 先输入的 exp-first", ranked[0].ExpID)
	}
}

func TestRankTieBreakDeterministic(t *testing.T) {
	// 同分不同 P(success)：成功概率高者优先（B 层×0.125 == 缺省层×0.25）。
	byPSuccess := []Candidate{
		{AssetID: 1, CVE: "CVE-1", Tier: "B"},            // PS=0.125, assetValue=2.0 → raw 0.25
		{AssetID: 2, CVE: "CVE-2", PrereqMet: Ptr(true)}, // PS=0.25,  assetValue=1.0 → raw 0.25
	}
	ranked := Rank(byPSuccess)
	if len(ranked) != 2 || ranked[0].AssetID != 2 {
		t.Fatalf("同分应按 P(success) 高者优先：got %+v", ranked)
	}
	// 同分同 P(success)：成本低者优先（4.0/2.0 == 2.0/1.0）。
	byCost := []Candidate{
		{AssetID: 1, CVE: "CVE-1", Tier: "S", AtomicOps: 2}, // cost 2.0 → raw 4.0×0.125/2=0.25
		{AssetID: 2, CVE: "CVE-2", Tier: "B", AtomicOps: 1}, // cost 1.0 → raw 2.0×0.125/1=0.25
	}
	ranked = Rank(byCost)
	if len(ranked) != 2 || ranked[0].AssetID != 2 {
		t.Fatalf("同分同概率应按成本低者优先：got %+v", ranked)
	}
}

func TestSelectTopN(t *testing.T) {
	tests := []struct {
		name         string
		candidates   []Candidate
		n            int
		wantAssetIDs []int64
	}{
		{name: "空输入", candidates: nil, n: 5, wantAssetIDs: nil},
		{name: "n<=0 今日不派任务", candidates: []Candidate{highScore(1, "CVE-1", "")}, n: 0, wantAssetIDs: nil},
		{name: "n 为负", candidates: []Candidate{highScore(1, "CVE-1", "")}, n: -3, wantAssetIDs: nil},
		{
			name: "截断到 Top N（按分数降序）",
			candidates: []Candidate{
				highScore(3, "CVE-3", ""), // 与 1/2 同分 → 字典序最后
				highScore(1, "CVE-1", ""),
				highScore(2, "CVE-2", ""),
				lowScore(9, "CVE-9", ""),
			},
			n:            2,
			wantAssetIDs: []int64{1, 2},
		},
		{
			name: "n 超过队列长度返回全量",
			candidates: []Candidate{
				lowScore(5, "CVE-5", ""),
				highScore(1, "CVE-1", ""),
			},
			n:            10,
			wantAssetIDs: []int64{1, 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SelectTopN(tt.candidates, tt.n)
			if len(got) != len(tt.wantAssetIDs) {
				t.Fatalf("SelectTopN 长度=%d, want %d：got %+v", len(got), len(tt.wantAssetIDs), got)
			}
			for i, s := range got {
				if s.AssetID != tt.wantAssetIDs[i] {
					t.Errorf("Top[%d].AssetID=%d, want %d", i, s.AssetID, tt.wantAssetIDs[i])
				}
			}
		})
	}
}

func TestRankInputOrderIndependence(t *testing.T) {
	// 打乱输入顺序，队列输出必须一致（确定性排序，日间可比）。
	base := []Candidate{
		highScore(1, "CVE-1", ""),
		lowScore(2, "CVE-2", ""),
		Candidate{AssetID: 3, CVE: "CVE-3", Tier: "B", AtomicOps: 2},
	}
	shuffled := []Candidate{base[2], base[0], base[1]}
	a, b := Rank(base), Rank(shuffled)
	if len(a) != len(b) {
		t.Fatalf("长度不一致：%d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].AssetID != b[i].AssetID || a[i].CVE != b[i].CVE {
			t.Fatalf("排名 %d 不一致：%+v vs %+v", i, a[i], b[i])
		}
	}
}
