package valuesched

import "sort"

// dedupKey 是去重键：同一资产 + 同一 CVE 只保留最高分的 EXP。
type dedupKey struct {
	AssetID int64
	CVE     string
}

// Rank 对候选全量打分，去重（同一 资产+CVE 只保留最高分 EXP）后按分数降序
// 输出完整优先级队列。这是价值矩阵的排序层，位于 agent/planner 任务内规划
// 之上：planner 决定"一个任务里怎么打"，Rank 决定"今天先打哪个资产"。
//
// 排序确定性（避免同分候选日间抖动）：分数 ↓ → P(success) ↓ → 成本 ↑ →
// (AssetID, CVE, ExpID) 字典序 ↑。被去重淘汰的 EXP 不出现在结果里；需要
// 复核淘汰原因可对原候选逐个调 Score。
func Rank(candidates []Candidate) []Scored {
	scored := make([]Scored, 0, len(candidates))
	best := make(map[dedupKey]int, len(candidates)) // 键 → 该键当前最优在 scored 中的下标
	for _, c := range candidates {
		s := Score(c)
		key := dedupKey{AssetID: c.AssetID, CVE: c.CVE}
		idx, ok := best[key]
		if !ok {
			best[key] = len(scored)
			scored = append(scored, s)
			continue
		}
		// 同分保留先出现的 EXP（输入顺序即调用方给出的 EXP 优先序）。
		if s.Score > scored[idx].Score {
			scored[idx] = s
		}
	}
	sort.SliceStable(scored, func(i, j int) bool {
		a, b := scored[i], scored[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.PSuccess != b.PSuccess {
			return a.PSuccess > b.PSuccess
		}
		if a.Cost != b.Cost {
			return a.Cost < b.Cost
		}
		if a.AssetID != b.AssetID {
			return a.AssetID < b.AssetID
		}
		if a.CVE != b.CVE {
			return a.CVE < b.CVE
		}
		return a.ExpID < b.ExpID
	})
	return scored
}

// SelectTopN 是每日调度的入口：Rank 后截取前 n 条（艾维利工作法——每天只
// 做最重要的 N 件）。n<=0 返回 nil（今日不派任务）；n 超过队列长度返回全量。
//
// 集成点（配合现有任务下发机制，见 docs/价值矩阵调度.md）：
//  1. 组装候选：kt-vuln 资产目录（tier/verdict=cve 命中）× 关注 CVE 清单 × EXP 元数据；
//  2. 每日调度循环调 SelectTopN(candidates, N)；
//  3. 把返回的 Top N 逐条下发为任务（可经 P3 的 vuln-workset 快照接口
//     pinTaskVulnWorkset 把资产快照钉到任务上），Breakdown/Explain 随任务留痕。
func SelectTopN(candidates []Candidate, n int) []Scored {
	if n <= 0 {
		return nil
	}
	ranked := Rank(candidates)
	if n > len(ranked) {
		return ranked
	}
	return ranked[:n]
}
