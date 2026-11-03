package server

// EXP 资产库（复利引擎）service 层。
//
// 授权渗透测试平台的能力沉淀库：把「一次性消耗」变成「可复用资产」——
// 成功利用沉淀为参数化 EXP，失败结构化沉淀（failure_reason 归因）反哺匹配
// 准确度。本层做语义校验与匹配编排，存取走 db.ExpStore，语义见
// db/exp_match.go 与 docs/EXP资产库设计.md。
//
// EXP 只在授权范围内使用：本层不判定目标是否在授权边界内（那是任务
// scope 与拦截层的职责），但所有对外输出都带上这一纪律说明。

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// ExpLibrary is the EXP asset-library service bound to the shared PG handle.
type ExpLibrary struct{ pg *db.DB }

// expLibrary returns the service (nil when PG is not initialized — callers
// surface a readable error instead of panicking).
func (s *Server) expLibrary() *ExpLibrary {
	if s.m == nil || s.m.PG() == nil {
		return nil
	}
	return &ExpLibrary{pg: s.m.PG()}
}

// validateExpAsset checks the semantic shape of an EXP before it enters the
// library. 坏条件进库会污染全平台的匹配面，所以在写路径上挡：
//   - fingerprint_match 必须能解析成指纹条件（版本区间语法合法）；
//   - exec_template 必须声明 kind（http | command | script），与其余字段
//     的语义由后续执行器接线时细化（见 docs/EXP资产库设计.md 接线计划）；
//   - success_oracle 至少声明一项判定（status_codes / keywords / regex），
//     没有成功判定的 EXP 无法沉淀「可信成功」，命中率统计也就失真。
func validateExpAsset(e *db.ExpAsset) error {
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("name 不能为空")
	}
	if _, err := db.ParseExpFingerprint(e.FP); err != nil {
		return err
	}
	if len(e.Exec) == 0 || string(e.Exec) == "null" || string(e.Exec) == "{}" {
		return fmt.Errorf("exec_template 不能为空")
	}
	var exec struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(e.Exec, &exec); err != nil {
		return fmt.Errorf("exec_template 不是合法 JSON: %w", err)
	}
	switch exec.Kind {
	case "http", "command", "script":
	default:
		return fmt.Errorf("exec_template.kind 需为 http / command / script，收到 %q", exec.Kind)
	}
	if len(e.Oracle) == 0 || string(e.Oracle) == "null" || string(e.Oracle) == "{}" {
		return fmt.Errorf("success_oracle 不能为空（没有成功判定的 EXP 无法沉淀可信成功）")
	}
	var oracle struct {
		StatusCodes []int    `json:"status_codes"`
		Keywords    []string `json:"keywords"`
		Regex       string   `json:"regex"`
	}
	if err := json.Unmarshal(e.Oracle, &oracle); err != nil {
		return fmt.Errorf("success_oracle 不是合法 JSON: %w", err)
	}
	if len(oracle.StatusCodes) == 0 && len(oracle.Keywords) == 0 && strings.TrimSpace(oracle.Regex) == "" {
		return fmt.Errorf("success_oracle 需至少声明 status_codes / keywords / regex 之一")
	}
	return nil
}

// CreateExpAsset validates and inserts a new EXP.
func (l *ExpLibrary) CreateExpAsset(e *db.ExpAsset) (int64, error) {
	if err := validateExpAsset(e); err != nil {
		return 0, err
	}
	return l.pg.Exps().CreateExpAsset(e)
}

// UpdateExpAsset validates and saves an edited EXP (optimistic version check
// when expectVersion > 0).
func (l *ExpLibrary) UpdateExpAsset(e *db.ExpAsset, expectVersion int) error {
	if err := validateExpAsset(e); err != nil {
		return err
	}
	return l.pg.Exps().UpdateExpAsset(e, expectVersion)
}

// DeleteExpAsset removes an EXP and cascades its attempts.
func (l *ExpLibrary) DeleteExpAsset(id int64) error { return l.pg.Exps().DeleteExpAsset(id) }

// GetExpAsset fetches one EXP (nil when absent).
func (l *ExpLibrary) GetExpAsset(id int64) (*db.ExpAsset, error) {
	return l.pg.Exps().GetExpAsset(id)
}

// ListExpAssets lists EXPs (enabled-only optional).
func (l *ExpLibrary) ListExpAssets(enabledOnly bool) ([]*db.ExpAsset, error) {
	return l.pg.Exps().ListExpAssets(enabledOnly)
}

// ExpMatchHit is one matched EXP in a MatchByFingerprint result：资产侧最
// 关心的形态——怎么打（参数模板/前置/执行模板）+ 该 EXP 的历史命中面。
type ExpMatchHit struct {
	Exp      *db.ExpAsset `json:"exp"`
	HitRate  float64      `json:"hit_rate"` // success/attempts；0 尝试为 0
	Attempts int          `json:"attempts"`
}

// MatchByFingerprint matches the input asset fingerprint against every enabled
// EXP and returns the hits (with param templates + hit-rate stats). 输入是
// 资产指纹 JSON（technologies/components/port/path/url，语义见 db/exp_match.go）。
func (l *ExpLibrary) MatchByFingerprint(fpRaw json.RawMessage) ([]*ExpMatchHit, error) {
	asset, err := db.ParseAssetFingerprint(fpRaw)
	if err != nil {
		return nil, err
	}
	exps, err := l.pg.Exps().ListExpAssets(true)
	if err != nil {
		return nil, err
	}
	stats, err := l.pg.Exps().ExpAssetStats()
	if err != nil {
		return nil, err
	}
	statsByID := make(map[int64]*db.ExpStats, len(stats))
	for _, st := range stats {
		statsByID[st.ExpID] = st
	}
	var hits []*ExpMatchHit
	for _, e := range exps {
		fp, perr := db.ParseExpFingerprint(e.FP)
		if perr != nil {
			// 坏条件不该出现在库里（写路径已挡）；命中面宁可跳过也不让一条脏数据
			// 打挂整个匹配循环。
			continue
		}
		if ok, _ := db.MatchExpFingerprint(fp, asset); ok {
			hit := &ExpMatchHit{Exp: e}
			if st := statsByID[e.ID]; st != nil {
				hit.HitRate = st.HitRate
				hit.Attempts = st.Attempts
			}
			hits = append(hits, hit)
		}
	}
	return hits, nil
}

// RecordAttempt appends an attempt (成功与失败都要记；失败必须带结构化
// failure_reason——这是失败沉淀反哺匹配准确度的数据面)。校验后走 db 层。
func (l *ExpLibrary) RecordAttempt(a *db.ExpAttempt) (int64, error) {
	if a.Status == db.ExpAttemptFailed && strings.TrimSpace(a.Detail) == "" {
		return 0, fmt.Errorf("失败尝试必须带 detail（结构化 failure_reason 之外的人类可读事实）")
	}
	return l.pg.Exps().RecordExpAttempt(a)
}

// ListAttempts returns one EXP's attempt ledger, newest first.
func (l *ExpLibrary) ListAttempts(expID int64, limit int) ([]*db.ExpAttempt, error) {
	return l.pg.Exps().ListExpAttempts(expID, limit)
}

// Stats returns per-EXP hit-rate + failure-reason distribution.
func (l *ExpLibrary) Stats() ([]*db.ExpStats, error) { return l.pg.Exps().ExpAssetStats() }
