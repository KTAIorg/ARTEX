package db

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// jsonEqual 语义比较两段 JSON（JSONB 存储会规范化空白与键序）。
func jsonEqual(a, b json.RawMessage) bool {
	var va, vb any
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

// CVE 富化缓存读写往返（需要真实 PostgreSQL，无库自动 skip）。
func TestCVEEnrichCacheRoundtrip(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	const cveID = "CVE-2098-11223" // 测试专用编号，避免与真实缓存互踩
	t.Cleanup(func() { _ = d.DeleteCVEEnrichCache(cveID) })

	// 无缓存 → nil
	if row, err := d.GetCVEEnrichCache(cveID); err != nil || row != nil {
		t.Fatalf("未写入应返回 (nil,nil): row=%v err=%v", row, err)
	}

	// 写入（TTL 1h）→ 读回 payload 语义一致（JSONB 会规范化键序，不能比字节）
	payload := json.RawMessage(`{"cve_id":"CVE-2098-11223","verdict":{"priority":"P1","reason":"test"}}`)
	if err := d.SaveCVEEnrichCache(cveID, payload, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}
	row, err := d.GetCVEEnrichCache(cveID)
	if err != nil || row == nil {
		t.Fatalf("写入后应命中: row=%v err=%v", row, err)
	}
	if !jsonEqual(row.Payload, payload) {
		t.Errorf("payload 回读不一致: %s", row.Payload)
	}
	if time.Until(row.ExpiresAt) <= 0 || time.Until(row.ExpiresAt) > time.Hour {
		t.Errorf("expires_at 异常: %v", row.ExpiresAt)
	}

	// upsert 覆盖
	payload2 := json.RawMessage(`{"cve_id":"CVE-2098-11223","verdict":{"priority":"P0"}}`)
	if err := d.SaveCVEEnrichCache(cveID, payload2, time.Hour); err != nil {
		t.Fatalf("save2: %v", err)
	}
	if row, _ = d.GetCVEEnrichCache(cveID); row == nil || !jsonEqual(row.Payload, payload2) {
		t.Errorf("upsert 未覆盖: %s", row.Payload)
	}

	// 过期 → miss（顺带懒删除）
	if _, err := d.Exec(`UPDATE cve_enrich_cache SET expires_at = now() - interval '1 minute' WHERE cve_id=$1`, cveID); err != nil {
		t.Fatalf("拨过期: %v", err)
	}
	if row, err := d.GetCVEEnrichCache(cveID); err != nil || row != nil {
		t.Errorf("过期后应 miss: row=%v err=%v", row, err)
	}

	// TTL 0 → 立即过期
	if err := d.SaveCVEEnrichCache(cveID, payload, 0); err != nil {
		t.Fatalf("save ttl0: %v", err)
	}
	if row, _ := d.GetCVEEnrichCache(cveID); row != nil {
		t.Errorf("TTL 0 应立即过期: %+v", row)
	}
}
