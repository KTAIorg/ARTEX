package server

// EXP 资产库 service 层测试：写路径语义校验（纯逻辑）+ 有 PG 时的
// 匹配/沉淀端到端。授权渗透测试平台的能力沉淀库——EXP 只在授权范围内使用。

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func validExpForValidation() *db.ExpAsset {
	return &db.ExpAsset{
		Name:   "svc-test-exp",
		FP:     json.RawMessage(`{"components":[{"name":"tomcat","version_range":">=8.0,<10.0"}]}`),
		Params: json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"}}}`),
		Exec:   json.RawMessage(`{"kind":"http","method":"GET","url":"http://{target}/x"}`),
		Oracle: json.RawMessage(`{"status_codes":[200]}`),
		Enabled: true,
	}
}

// TestValidateExpAsset 写路径语义校验：坏 exec/oracle/指纹条件进不了库。
func TestValidateExpAsset(t *testing.T) {
	if err := validateExpAsset(validExpForValidation()); err != nil {
		t.Fatalf("valid exp rejected: %v", err)
	}

	bad := map[string]func(*db.ExpAsset){
		"empty name":        func(e *db.ExpAsset) { e.Name = " " },
		"empty exec":        func(e *db.ExpAsset) { e.Exec = nil },
		"exec bad kind":     func(e *db.ExpAsset) { e.Exec = json.RawMessage(`{"kind":"ftp"}`) },
		"exec not json":     func(e *db.ExpAsset) { e.Exec = json.RawMessage(`not-json`) },
		"empty oracle":      func(e *db.ExpAsset) { e.Oracle = json.RawMessage(`{}`) },
		"oracle no rule":    func(e *db.ExpAsset) { e.Oracle = json.RawMessage(`{"status_codes":[],"keywords":[]}`) },
		"bad fingerprint":   func(e *db.ExpAsset) { e.FP = json.RawMessage(`{"components":[{"name":"x","version_range":">=??"}]}`) },
		"fingerprint type":  func(e *db.ExpAsset) { e.FP = json.RawMessage(`{"components": 3}`) },
	}
	for name, mutate := range bad {
		e := validExpForValidation()
		mutate(e)
		if err := validateExpAsset(e); err == nil {
			t.Fatalf("%s should be rejected", name)
		}
	}
}

// TestExpLibraryMatchAndRecord service 层端到端：登记 → 指纹匹配 → 失败沉淀
// → 统计命中率。无 PG 配置时跳过（与 db 包同一套 DSN 约定）。
func TestExpLibraryMatchAndRecord(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	lib := &ExpLibrary{pg: pg}
	name := fmt.Sprintf("exp_svc_%d", time.Now().UnixNano())

	in := validExpForValidation()
	in.Name = name
	in.Tags = []string{"svc"}
	id, err := lib.CreateExpAsset(in)
	if err != nil {
		t.Fatalf("create via service: %v", err)
	}
	t.Cleanup(func() { _ = lib.DeleteExpAsset(id) })

	// 指纹命中：组件+版本在区间
	hits, err := lib.MatchByFingerprint(json.RawMessage(
		`{"technologies":["Apache Tomcat 9.0.30"],"port":8080,"path":"/manager/html"}`))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hits {
		if h.Exp.ID == id {
			found = true
			if string(h.Exp.Params) == "" || string(h.Exp.Exec) == "" {
				t.Fatal("matched exp must carry params/exec templates")
			}
		}
	}
	if !found {
		t.Fatal("created exp not matched")
	}

	// 指纹不命中：版本超区间
	hits, err = lib.MatchByFingerprint(json.RawMessage(
		`{"technologies":["Apache Tomcat 10.1.0"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if h.Exp.ID == id {
			t.Fatal("out-of-range version should not match")
		}
	}

	// 失败沉淀：detail 缺失要被拒，带齐后统计可见
	if _, err := lib.RecordAttempt(&db.ExpAttempt{
		ExpID: id, Target: "10.9.9.9:8080", Status: db.ExpAttemptFailed,
		FailureReason: db.ExpFailOracleNotMatched,
	}); err == nil {
		t.Fatal("failed attempt without detail should be rejected")
	}
	if _, err := lib.RecordAttempt(&db.ExpAttempt{
		ExpID: id, Target: "10.9.9.9:8080", Status: db.ExpAttemptFailed,
		FailureReason: db.ExpFailOracleNotMatched, Detail: "404",
	}); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	stats, err := lib.Stats()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range stats {
		if st.ExpID == id {
			if st.Attempts != 1 || st.Failed != 1 || st.HitRate != 0 {
				t.Fatalf("stats wrong: %+v", st)
			}
			if st.FailureDist[db.ExpFailOracleNotMatched] != 1 {
				t.Fatalf("failure dist wrong: %v", st.FailureDist)
			}
		}
	}
}
