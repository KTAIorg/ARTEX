package db

// 复利指标（CompoundMetrics）：EXP 资产库的核心 KPI 面。
//
// 战略口径：EXP 库的价值 = 复利率（经 EXP 库完成的拿下占比）。靶场闸门
// （range 包）守住「库里的 EXP 真能打」的质量面，这一层度量「复利真的
// 在发生吗」——数据源就是 exp_attempts 台账（成功与失败都沉淀的那张表），
// 由 ExpAssetStats 的既有查询面扩展而来。
//
// 指标定义：
//   - 复利率 compound_rate = exp_success / total_success：
//     分子 = 窗口内 exp_attempts 的 success 行（经 EXP 库完成的成功）；
//     分母 = 平台全部成功拿下数。台账只覆盖 EXP 库路径，单看 exp_attempts
//     时分母退化 = 分子（率恒为 1）；接平台 findings（拿下）口径后用
//     SetTotalSuccess 注入真实分母，复利率才有区分度。这是刻意保留的
//     显式接线点，而不是在本层猜一个全平台数字。
//   - EXP 命中率 exp_hit_rate = exp_success / total_attempts（P(EXP可用)
//     的窗口化实然测量）。
//   - top 失败原因分布 / 按天趋势：喂给看板与匹配修正（如 version_mismatch
//     扎堆 → 对应 EXP 的指纹版本区间该收紧）。

import "time"

// CompoundWindow 是指标的时间窗口（闭开区间：[Since, Until)）。
type CompoundWindow struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

// CompoundDailyPoint 是趋势数组里的一天：attempt 量、成功量与当日命中率。
type CompoundDailyPoint struct {
	Date     string  `json:"date"` // YYYY-MM-DD（库端时区）
	Attempts int     `json:"attempts"`
	Success  int     `json:"success"`
	HitRate  float64 `json:"hit_rate"` // success/attempts；当日无 attempt 为 0
}

// FailureReasonCount 是一个失败原因的窗口内计数。
type FailureReasonCount struct {
	Reason ExpAttemptFailureReason `json:"reason"`
	Count  int                     `json:"count"`
}

// CompoundMetrics 是一次复利指标查询的结构化结果（可直出 JSON 供 web 看板）。
type CompoundMetrics struct {
	Window CompoundWindow `json:"window"`

	// TotalAttempts 窗口内 attempt 总数（exp_attempts 行数）。
	TotalAttempts int `json:"total_attempts"`
	// ExpSuccess 窗口内经 EXP 库完成的成功数（复利率分子）。
	ExpSuccess int `json:"exp_success"`
	// TotalSuccess 平台全部成功拿下数（复利率分母）。默认 = ExpSuccess
	// （台账内自洽），接 findings 口径后用 SetTotalSuccess 覆盖。
	TotalSuccess int `json:"total_success"`
	// CompoundRate 复利率：ExpSuccess / TotalSuccess。
	CompoundRate float64 `json:"compound_rate"`
	// ExpHitRate EXP 命中率：ExpSuccess / TotalAttempts。
	ExpHitRate float64 `json:"exp_hit_rate"`

	// TopFailureReasons 失败原因分布 Top N（按计数降序，N=5）。
	TopFailureReasons []FailureReasonCount `json:"top_failure_reasons"`
	// Trend 按天趋势（窗口内有数据的天，升序）。
	Trend []CompoundDailyPoint `json:"trend"`
}

// compoundDefaultWindow 是 since 为零值时的默认窗口：最近 30 天。
const compoundDefaultWindow = 30 * 24 * time.Hour

// compoundTopFailures 是 top 失败原因的截断条数。
const compoundTopFailures = 5

// CompoundMetrics computes 复利指标 over exp_attempts since the given time
// （零值 = 最近 30 天）。一条 GROUP BY 覆盖总量与按天趋势，失败原因单独
// 一条聚合——都是台账表上的轻查询。
func (s *ExpStore) CompoundMetrics(since time.Time) (*CompoundMetrics, error) {
	if since.IsZero() {
		since = time.Now().Add(-compoundDefaultWindow)
	}
	m := &CompoundMetrics{
		Window:            CompoundWindow{Since: since, Until: time.Now()},
		TopFailureReasons: []FailureReasonCount{},
		Trend:             []CompoundDailyPoint{},
	}

	// 总量 + 按天趋势：一次分组查询同时喂三个字段。
	rows, err := s.db.Query(`
SELECT date_trunc('day', created_at) AS day,
       count(*),
       count(*) FILTER (WHERE status = 'success')
FROM exp_attempts
WHERE created_at >= $1
GROUP BY 1
ORDER BY 1`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var day time.Time
		var attempts, success int
		if err := rows.Scan(&day, &attempts, &success); err != nil {
			return nil, err
		}
		m.TotalAttempts += attempts
		m.ExpSuccess += success
		p := CompoundDailyPoint{Date: day.Format("2006-01-02"), Attempts: attempts, Success: success}
		if attempts > 0 {
			p.HitRate = float64(success) / float64(attempts)
		}
		m.Trend = append(m.Trend, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 失败原因分布 Top N。
	distRows, err := s.db.Query(`
SELECT failure_reason, count(*)
FROM exp_attempts
WHERE created_at >= $1 AND failure_reason IS NOT NULL
GROUP BY failure_reason
ORDER BY count(*) DESC, failure_reason
LIMIT $2`, since, compoundTopFailures)
	if err != nil {
		return nil, err
	}
	defer distRows.Close()
	for distRows.Next() {
		var fc FailureReasonCount
		if err := distRows.Scan(&fc.Reason, &fc.Count); err != nil {
			return nil, err
		}
		m.TopFailureReasons = append(m.TopFailureReasons, fc)
	}
	if err := distRows.Err(); err != nil {
		return nil, err
	}

	// 复利率分母默认退化为台账口径（恒 1）；外部总成功数经 SetTotalSuccess 注入。
	m.TotalSuccess = m.ExpSuccess
	m.recomputeRates()
	return m, nil
}

// SetTotalSuccess 注入平台全部成功拿下数（findings 口径），重算复利率分母。
// total <= 0 视为未知：回退台账口径（TotalSuccess = ExpSuccess）。
// 返回自身以便链式调用：lib.CompoundMetrics(s).SetTotalSuccess(n)。
func (m *CompoundMetrics) SetTotalSuccess(total int) *CompoundMetrics {
	if total > 0 {
		m.TotalSuccess = total
	} else {
		m.TotalSuccess = m.ExpSuccess
	}
	m.recomputeRates()
	return m
}

func (m *CompoundMetrics) recomputeRates() {
	if m.TotalSuccess > 0 {
		m.CompoundRate = float64(m.ExpSuccess) / float64(m.TotalSuccess)
	}
	if m.TotalAttempts > 0 {
		m.ExpHitRate = float64(m.ExpSuccess) / float64(m.TotalAttempts)
	}
}
