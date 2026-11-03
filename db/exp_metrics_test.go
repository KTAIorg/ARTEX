package db

// CompoundMetrics 真库测试：台账灌入已知分布的成功/失败 attempt，校验
// 复利率、命中率、top 失败原因与按天趋势。无 PG 配置时跳过（与 db 包
// 同一套 testDSN 约定）。断言用 ≥ 口径——测试库可能残留其他用例的台账
// 行，窗口内混入只会让计数变多，不会变少。

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCompoundMetrics(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	st := d.Exps()
	name := fmt.Sprintf("exp_metrics_%d", time.Now().UnixNano())
	if old, _ := st.GetExpAssetByName(name); old != nil {
		_ = st.DeleteExpAsset(old.ID)
	}
	id, err := st.CreateExpAsset(newTestExpAsset(name))
	if err != nil {
		t.Fatalf("create exp: %v", err)
	}
	t.Cleanup(func() { _ = st.DeleteExpAsset(id) })

	// 灌台账：3 成功 + 2 oracle_not_matched + 1 timeout（失败必带 detail）。
	mk := func(status string, reason ExpAttemptFailureReason) *ExpAttempt {
		a := &ExpAttempt{ExpID: id, Target: "10.8.8.8:8080", Status: status, Detail: "metrics-test"}
		if status == ExpAttemptFailed {
			a.FailureReason = reason
		}
		return a
	}
	since := time.Now().Add(-time.Minute) // 窗口起点在灌数之前
	for i := 0; i < 3; i++ {
		if _, err := st.RecordExpAttempt(mk(ExpAttemptSuccess, "")); err != nil {
			t.Fatalf("record success: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := st.RecordExpAttempt(mk(ExpAttemptFailed, ExpFailOracleNotMatched)); err != nil {
			t.Fatalf("record oracle failure: %v", err)
		}
	}
	if _, err := st.RecordExpAttempt(mk(ExpAttemptFailed, ExpFailTimeout)); err != nil {
		t.Fatalf("record timeout failure: %v", err)
	}

	m, err := st.CompoundMetrics(since)
	if err != nil {
		t.Fatalf("compound metrics: %v", err)
	}
	if m.TotalAttempts < 6 || m.ExpSuccess < 3 {
		t.Fatalf("window counts too small (shared db noise expected, not loss): %+v", m)
	}
	// 台账口径下复利率分母退化 = 分子 → 恒为 1。
	if m.CompoundRate != 1 {
		t.Fatalf("default denominator compound rate want 1, got %f", m.CompoundRate)
	}
	if m.ExpHitRate <= 0 || m.ExpHitRate > 1 {
		t.Fatalf("hit rate out of range: %f", m.ExpHitRate)
	}
	// 趋势：窗口内至少今天一个点，且今天的点包含灌入的量。
	if len(m.Trend) == 0 {
		t.Fatal("trend must have at least one day point")
	}
	today := time.Now().Format("2006-01-02")
	if m.Trend[len(m.Trend)-1].Date != today || m.Trend[len(m.Trend)-1].Attempts < 6 {
		t.Fatalf("today trend point wrong: %+v", m.Trend[len(m.Trend)-1])
	}
	// top 失败原因：oracle_not_matched ≥2、timeout ≥1，且按计数降序。
	counts := map[ExpAttemptFailureReason]int{}
	for _, fc := range m.TopFailureReasons {
		counts[fc.Reason] = fc.Count
	}
	if counts[ExpFailOracleNotMatched] < 2 || counts[ExpFailTimeout] < 1 {
		t.Fatalf("failure dist missing seeded reasons: %+v", m.TopFailureReasons)
	}
	for i := 1; i < len(m.TopFailureReasons); i++ {
		if m.TopFailureReasons[i-1].Count < m.TopFailureReasons[i].Count {
			t.Fatalf("failure dist not descending: %+v", m.TopFailureReasons)
		}
	}

	// 注入平台总成功数（findings 口径）：复利率分母生效，且数学精确。
	m.SetTotalSuccess(m.ExpSuccess * 10)
	if m.TotalSuccess != m.ExpSuccess*10 {
		t.Fatalf("SetTotalSuccess not applied: %+v", m)
	}
	want := float64(m.ExpSuccess) / float64(m.ExpSuccess*10)
	if m.CompoundRate != want {
		t.Fatalf("compound rate want %f, got %f", want, m.CompoundRate)
	}
	// 未知分母（<=0）回退台账口径。
	m.SetTotalSuccess(0)
	if m.TotalSuccess != m.ExpSuccess || m.CompoundRate != 1 {
		t.Fatalf("unknown denominator should fall back to ledger scope: %+v", m)
	}

	// 结构化 JSON：核心字段都在（供 web 看板直接消费）。
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"compound_rate"`, `"total_attempts"`, `"exp_success"`, `"total_success"`,
		`"exp_hit_rate"`, `"top_failure_reasons"`, `"trend"`, `"since"`, `"until"`,
	} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("metrics JSON missing %s: %s", key, raw)
		}
	}
}

// TestCompoundMetricsEmptyWindow 空窗口（起点在未来）：全零、率恒 0、
// 数组字段为空切片而非 null（看板消费约定）。
func TestCompoundMetricsEmptyWindow(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	m, err := d.Exps().CompoundMetrics(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalAttempts != 0 || m.ExpSuccess != 0 || m.TotalSuccess != 0 ||
		m.CompoundRate != 0 || m.ExpHitRate != 0 {
		t.Fatalf("empty window must be all zero: %+v", m)
	}
	if m.Trend == nil || m.TopFailureReasons == nil {
		t.Fatalf("array fields must be empty slices, not nil: %+v", m)
	}
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), "null") {
		t.Fatalf("metrics JSON must not contain null arrays: %s", raw)
	}
}
