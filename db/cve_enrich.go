package db

import (
	"database/sql"
	"encoding/json"
	"time"
)

// CVE 情报富化缓存（vuln_enrich_cve 工具）。富化一次要串 kt-vuln + NVD + GitHub
// Advisory + EPSS 多个外部接口（NVD 匿名限流 5req/30s），结果按 CVE 编号缓存
// TTL（默认 24h），重复查询直接回快照。表结构见 schema.sql §I；这里是读写层。

// CVEEnrichCacheRow 是一条富化缓存快照。
type CVEEnrichCacheRow struct {
	CveID     string
	Payload   json.RawMessage
	FetchedAt time.Time
	ExpiresAt time.Time
}

// GetCVEEnrichCache 取一条未过期的缓存快照；不存在或已过期返回 (nil, nil)。
// 过期行顺手懒删除（自愈，无需后台清理任务）。
func (d *DB) GetCVEEnrichCache(cveID string) (*CVEEnrichCacheRow, error) {
	row := d.QueryRow(`SELECT cve_id,payload,fetched_at,expires_at
FROM cve_enrich_cache WHERE cve_id=$1 AND expires_at > now()`, cveID)
	var r CVEEnrichCacheRow
	if err := row.Scan(&r.CveID, &r.Payload, &r.FetchedAt, &r.ExpiresAt); err != nil {
		if err == sql.ErrNoRows {
			// 懒清理：能走到 no rows 且行存在必是已过期，顺手删掉（best-effort，
			// 主键 DELETE 无命中时代价极低）。
			_ = d.DeleteCVEEnrichCache(cveID)
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// DeleteCVEEnrichCache 删除一条缓存（过期懒清理 + refresh=true 强制刷新时调用）。
func (d *DB) DeleteCVEEnrichCache(cveID string) error {
	_, err := d.Exec(`DELETE FROM cve_enrich_cache WHERE cve_id=$1`, cveID)
	return err
}

// SaveCVEEnrichCache upsert 一条富化快照，TTL 由调用方传入（工具层默认 24h，
// env VULN_ENRICH_CACHE_TTL_HOURS 可调）。
func (d *DB) SaveCVEEnrichCache(cveID string, payload json.RawMessage, ttl time.Duration) error {
	_, err := d.Exec(`
INSERT INTO cve_enrich_cache(cve_id,payload,fetched_at,expires_at)
VALUES ($1,$2,now(),now()+$3::interval)
ON CONFLICT (cve_id) DO UPDATE SET
  payload=EXCLUDED.payload, fetched_at=now(), expires_at=EXCLUDED.expires_at`,
		cveID, payload, ttl.String())
	return err
}
