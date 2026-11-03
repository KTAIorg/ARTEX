package db

// EXP 资产库（复利引擎）的 repository 层。
//
// 授权渗透测试平台的能力沉淀库：每次成功利用沉淀为一条参数化 EXP，
// agent 猎杀一次、全平台永久收割同类目标；失败也结构化沉淀（failure_reason
// 归因），反哺匹配准确度。EXP 只在授权范围内使用——授权边界由任务 scope 与
// 拦截层把关，本层只做能力沉淀与查询，不做放行判定。
//
// 表结构见 schema.sql §N；指纹匹配语义（版本区间/端口/路径）在 exp_match.go，
// 纯 Go、可脱离数据库测试。

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// =====================================================================
// 类型
// =====================================================================

// ExpAsset 是 exp_assets 的一行：一条参数化 EXP。
type ExpAsset struct {
	ID     int64           `json:"id"`
	Name   string          `json:"name"`
	Desc   string          `json:"description"`
	FP     json.RawMessage `json:"fingerprint_match"` // 指纹条件 JSON（语义见 exp_match.go）
	Pre    json.RawMessage `json:"preconditions"`     // 前置条件 JSON 数组
	Params json.RawMessage `json:"params_schema"`     // 参数模板 JSON Schema
	Exec   json.RawMessage `json:"exec_template"`     // 执行模板 JSON（http/command，与自定义工具 exec 同构）
	Oracle json.RawMessage `json:"success_oracle"`    // 成功判定 JSON（status_codes/keywords/regex）
	// Cleanup 清理动作 JSON；nil 表示无（列可空）。
	Cleanup   json.RawMessage `json:"cleanup,omitempty"`
	CveIDs    []string        `json:"cve_ids"`
	Tags      []string        `json:"tags"`
	Enabled   bool            `json:"enabled"`
	Version   int             `json:"version"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ExpAttemptFailureReason 是失败的归因枚举，与 exp_attempts.failure_reason 的
// CHECK 约束一一对应。闭合枚举：新增值要同时改 schema CHECK 与这里。
type ExpAttemptFailureReason string

const (
	ExpFailFingerprintMismatch ExpAttemptFailureReason = "fingerprint_mismatch" // 指纹不匹配（组件对不上）
	ExpFailVersionMismatch     ExpAttemptFailureReason = "version_mismatch"     // 版本不在声明区间
	ExpFailPrecondMissing      ExpAttemptFailureReason = "precondition_missing" // 前置条件不满足
	ExpFailTimeout             ExpAttemptFailureReason = "timeout"              // 执行超时
	ExpFailOracleNotMatched    ExpAttemptFailureReason = "oracle_not_matched"   // 执行完成但成功判定未命中
	ExpFailOther               ExpAttemptFailureReason = "other"                // 其他（detail 写清）
)

// ValidExpFailureReasons 是合法失败原因全集（校验用，防脏值进库）。
var ValidExpFailureReasons = map[ExpAttemptFailureReason]bool{
	ExpFailFingerprintMismatch: true,
	ExpFailVersionMismatch:     true,
	ExpFailPrecondMissing:      true,
	ExpFailTimeout:             true,
	ExpFailOracleNotMatched:    true,
	ExpFailOther:               true,
}

// ExpAttemptStatus 成功/失败。
const (
	ExpAttemptSuccess = "success"
	ExpAttemptFailed  = "failed"
)

// ExpAttempt 是 exp_attempts 的一行：一次执行尝试的台账（成功与失败都记）。
type ExpAttempt struct {
	ID            int64                   `json:"id"`
	ExpID         int64                   `json:"exp_id"`
	Target        string                  `json:"target"` // 资产标识 host[:port] 或 URL
	Status        string                  `json:"status"` // success | failed
	FailureReason ExpAttemptFailureReason `json:"failure_reason,omitempty"`
	Detail        string                  `json:"detail"`
	Evidence      json.RawMessage         `json:"evidence"`
	CreatedAt     time.Time               `json:"created_at"`
}

// ExpStats 是一条 EXP 的命中面统计：先验公式 P(EXP可用) 的实然测量。
type ExpStats struct {
	ExpID    int64   `json:"exp_id"`
	Name     string  `json:"name"`
	Attempts int     `json:"attempts"`
	Success  int     `json:"success"`
	Failed   int     `json:"failed"`
	HitRate  float64 `json:"hit_rate"` // success/attempts；无尝试时 0
	// FailureDist 最近失败原因分布（reason → 次数），全量口径。
	FailureDist   map[ExpAttemptFailureReason]int `json:"failure_dist"`
	LastAttemptAt *time.Time                      `json:"last_attempt_at,omitempty"`
}

// =====================================================================
// 存取
// =====================================================================

// ExpStore operates on exp_assets / exp_attempts.
type ExpStore struct{ db *DB }

// Exps returns the EXP asset store.
func (d *DB) Exps() *ExpStore { return &ExpStore{db: d} }

const expAssetCols = `id, name, description, fingerprint_match, preconditions, params_schema,
	exec_template, success_oracle, cleanup, array_to_json(cve_ids)::text, array_to_json(tags)::text,
	enabled, version, created_at, updated_at`

func rawJSON(v json.RawMessage, fallback string) json.RawMessage {
	if len(v) == 0 {
		return json.RawMessage(fallback)
	}
	return v
}

func scanExpAsset(rows interface{ Scan(...any) error }) (*ExpAsset, error) {
	var e ExpAsset
	var cves, tags []byte
	var cleanup []byte
	if err := rows.Scan(&e.ID, &e.Name, &e.Desc, &e.FP, &e.Pre, &e.Params, &e.Exec,
		&e.Oracle, &cleanup, &cves, &tags, &e.Enabled, &e.Version, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, err
	}
	if len(cleanup) > 0 && string(cleanup) != "null" {
		e.Cleanup = json.RawMessage(cleanup)
	}
	if len(cves) > 0 {
		_ = json.Unmarshal(cves, &e.CveIDs)
	}
	if len(tags) > 0 {
		_ = json.Unmarshal(tags, &e.Tags)
	}
	if e.CveIDs == nil {
		e.CveIDs = []string{}
	}
	if e.Tags == nil {
		e.Tags = []string{}
	}
	return &e, nil
}

// CreateExpAsset inserts a new EXP asset. Name must be unique; fingerprint/exec
// JSON blobs are stored as-is（语义校验在 service 层，这里只管存取）。
func (s *ExpStore) CreateExpAsset(e *ExpAsset) (int64, error) {
	if strings.TrimSpace(e.Name) == "" {
		return 0, fmt.Errorf("name is required")
	}
	var cleanup any
	if len(e.Cleanup) > 0 && string(e.Cleanup) != "null" {
		cleanup = e.Cleanup
	}
	var id int64
	err := s.db.QueryRow(`
INSERT INTO exp_assets(name, description, fingerprint_match, preconditions, params_schema,
    exec_template, success_oracle, cleanup, cve_ids, tags, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text[], $10::text[], $11)
RETURNING id`,
		strings.TrimSpace(e.Name), e.Desc,
		rawJSON(e.FP, "{}"), rawJSON(e.Pre, "[]"), rawJSON(e.Params, "{}"),
		rawJSON(e.Exec, "{}"), rawJSON(e.Oracle, "{}"), cleanup,
		marshalStringArray(e.CveIDs), marshalStringArray(e.Tags), e.Enabled).Scan(&id)
	return id, err
}

// GetExpAsset fetches one EXP by id (nil if absent).
func (s *ExpStore) GetExpAsset(id int64) (*ExpAsset, error) {
	row := s.db.QueryRow(`SELECT `+expAssetCols+` FROM exp_assets WHERE id=$1`, id)
	e, err := scanExpAsset(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

// GetExpAssetByName fetches one EXP by its unique name (nil if absent).
func (s *ExpStore) GetExpAssetByName(name string) (*ExpAsset, error) {
	row := s.db.QueryRow(`SELECT `+expAssetCols+` FROM exp_assets WHERE name=$1`, strings.TrimSpace(name))
	e, err := scanExpAsset(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

// ListExpAssets returns EXP rows, newest first; enabledOnly 过滤掉停用的。
func (s *ExpStore) ListExpAssets(enabledOnly bool) ([]*ExpAsset, error) {
	q := `SELECT ` + expAssetCols + ` FROM exp_assets`
	if enabledOnly {
		q += ` WHERE enabled`
	}
	q += ` ORDER BY id DESC`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ExpAsset
	for rows.Next() {
		e, err := scanExpAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpdateExpAsset saves the editable fields and bumps version（乐观锁水位 +
// 复利迭代计数）。expectVersion > 0 时做乐观并发控制：版本不符报错，防两个
// agent 基于同一旧版各改各的、互相覆盖。key(name) 不改。
func (s *ExpStore) UpdateExpAsset(e *ExpAsset, expectVersion int) error {
	if e.ID == 0 {
		return fmt.Errorf("id is required")
	}
	var cleanup any
	if len(e.Cleanup) > 0 && string(e.Cleanup) != "null" {
		cleanup = e.Cleanup
	}
	q := `
UPDATE exp_assets SET description=$2, fingerprint_match=$3, preconditions=$4,
    params_schema=$5, exec_template=$6, success_oracle=$7, cleanup=$8,
    cve_ids=$9::text[], tags=$10::text[], enabled=$11, version=version+1
WHERE id=$1`
	args := []any{e.ID, e.Desc, rawJSON(e.FP, "{}"), rawJSON(e.Pre, "[]"), rawJSON(e.Params, "{}"),
		rawJSON(e.Exec, "{}"), rawJSON(e.Oracle, "{}"), cleanup,
		marshalStringArray(e.CveIDs), marshalStringArray(e.Tags), e.Enabled}
	if expectVersion > 0 {
		q += ` AND version=$12`
		args = append(args, expectVersion)
	}
	res, err := s.db.Exec(q+` RETURNING 1`, args...)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		if cur, gerr := s.GetExpAsset(e.ID); gerr == nil && cur != nil {
			return fmt.Errorf("version conflict: expect %d, current %d", expectVersion, cur.Version)
		}
		return fmt.Errorf("exp asset %d not found", e.ID)
	}
	return nil
}

// DeleteExpAsset removes an EXP; its attempts cascade（台账随资产一起删，
// 库里不留指向虚无 EXP 的孤儿尝试）。
func (s *ExpStore) DeleteExpAsset(id int64) error {
	_, err := s.db.Exec(`DELETE FROM exp_assets WHERE id=$1`, id)
	return err
}

// SetExpAssetEnabled flips the on/off switch without bumping content version
// （启停不是迭代）。
func (s *ExpStore) SetExpAssetEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE exp_assets SET enabled=$2 WHERE id=$1`, id, enabled)
	return err
}

// =====================================================================
// 尝试台账（成功与失败都沉淀）
// =====================================================================

// RecordExpAttempt appends one attempt row. 失败必须带结构化 failure_reason
// （枚举校验在 service 层之外再兜一道，防脏值撞 CHECK 才报错）；成功不允许带。
// evidence 可空（存 {}）。
func (s *ExpStore) RecordExpAttempt(a *ExpAttempt) (int64, error) {
	if a.ExpID == 0 {
		return 0, fmt.Errorf("exp_id is required")
	}
	if strings.TrimSpace(a.Target) == "" {
		return 0, fmt.Errorf("target is required")
	}
	if a.Status != ExpAttemptSuccess && a.Status != ExpAttemptFailed {
		return 0, fmt.Errorf("status must be success|failed, got %q", a.Status)
	}
	if a.Status == ExpAttemptFailed && !ValidExpFailureReasons[a.FailureReason] {
		return 0, fmt.Errorf("failed attempt requires a valid failure_reason, got %q", a.FailureReason)
	}
	if a.Status == ExpAttemptSuccess && a.FailureReason != "" {
		return 0, fmt.Errorf("success attempt must not carry failure_reason")
	}
	var reason any
	if a.Status == ExpAttemptFailed {
		reason = string(a.FailureReason)
	}
	var id int64
	err := s.db.QueryRow(`
INSERT INTO exp_attempts(exp_id, target, status, failure_reason, detail, evidence)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id`,
		a.ExpID, strings.TrimSpace(a.Target), a.Status, reason, a.Detail,
		rawJSON(a.Evidence, "{}")).Scan(&id)
	return id, err
}

// ListExpAttempts returns attempts for one EXP, newest first; limit<=0 = 50。
func (s *ExpStore) ListExpAttempts(expID int64, limit int) ([]*ExpAttempt, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`
SELECT id, exp_id, target, status, COALESCE(failure_reason,''), detail, evidence, created_at
FROM exp_attempts WHERE exp_id=$1
ORDER BY id DESC LIMIT $2`, expID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ExpAttempt
	for rows.Next() {
		var a ExpAttempt
		var reason string
		if err := rows.Scan(&a.ID, &a.ExpID, &a.Target, &a.Status, &reason, &a.Detail, &a.Evidence, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.FailureReason = ExpAttemptFailureReason(reason)
		out = append(out, &a)
	}
	return out, rows.Err()
}

// =====================================================================
// 统计：命中率 + 失败原因分布
// =====================================================================

// ExpAssetStats computes per-EXP hit-rate stats over all attempts.
// 命中率 = success/attempts（P(EXP可用) 的实然测量）；失败原因分布喂给
// 匹配修正（如 version_mismatch 扎堆 → 指纹版本区间该收紧）。
func (s *ExpStore) ExpAssetStats() ([]*ExpStats, error) {
	// 总量口径：一条 GROUP BY 覆盖 attempts/success/failed/last。
	rows, err := s.db.Query(`
SELECT a.id, a.name,
       count(t.id),
       count(t.id) FILTER (WHERE t.status = 'success'),
       count(t.id) FILTER (WHERE t.status = 'failed'),
       max(t.created_at)
FROM exp_assets a
LEFT JOIN exp_attempts t ON t.exp_id = a.id
GROUP BY a.id, a.name
ORDER BY a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ExpStats{}
	byID := map[int64]*ExpStats{}
	for rows.Next() {
		var st ExpStats
		var last sql.NullTime
		var attempts, success, failed int64
		if err := rows.Scan(&st.ExpID, &st.Name, &attempts, &success, &failed, &last); err != nil {
			return nil, err
		}
		st.Attempts = int(attempts)
		st.Success = int(success)
		st.Failed = int(failed)
		if st.Attempts > 0 {
			st.HitRate = float64(st.Success) / float64(st.Attempts)
		}
		st.FailureDist = map[ExpAttemptFailureReason]int{}
		if last.Valid {
			t := last.Time
			st.LastAttemptAt = &t
		}
		byID[st.ExpID] = &st
		out = append(out, &st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 失败原因分布：单独按 (exp_id, failure_reason) 分组，合并进上面的结果。
	distRows, err := s.db.Query(`
SELECT exp_id, failure_reason, count(*)
FROM exp_attempts WHERE failure_reason IS NOT NULL
GROUP BY exp_id, failure_reason`)
	if err != nil {
		return nil, err
	}
	defer distRows.Close()
	for distRows.Next() {
		var expID int64
		var reason ExpAttemptFailureReason
		var n int
		if err := distRows.Scan(&expID, &reason, &n); err != nil {
			return nil, err
		}
		if st := byID[expID]; st != nil {
			st.FailureDist[reason] = n
		}
	}
	return out, distRows.Err()
}

// ExpAssetStatsByID returns one EXP's stats, or (nil, nil) when the EXP is absent.
func (s *ExpStore) ExpAssetStatsByID(id int64) (*ExpStats, error) {
	all, err := s.ExpAssetStats()
	if err != nil {
		return nil, err
	}
	for _, st := range all {
		if st.ExpID == id {
			return st, nil
		}
	}
	return nil, nil
}
