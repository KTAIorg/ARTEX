package db

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// newTestExpAsset builds a valid EXP row with a unique name.
func newTestExpAsset(name string) *ExpAsset {
	return &ExpAsset{
		Name:   name,
		Desc:   "测试用参数化 EXP",
		FP:     json.RawMessage(`{"components":[{"name":"Tomcat","version_range":">=8.0,<10.0"}],"ports":[8080]}`),
		Pre:    json.RawMessage(`[{"kind":"path_exists","detail":"/manager/html"}]`),
		Params: json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"},"port":{"type":"integer","default":8080}},"required":["target"]}`),
		Exec:   json.RawMessage(`{"kind":"http","method":"GET","url":"http://{target}:{port}/manager/html"}`),
		Oracle: json.RawMessage(`{"status_codes":[200],"keywords":["Apache Tomcat"]}`),
		CveIDs: []string{"CVE-2020-1938"},
		Tags:   []string{"test", "tomcat"},
		Enabled: true,
	}
}

// TestExpAssetCRUD 建查改删 + 启停过滤 + 乐观版本。跳过条件：无 PG 配置。
func TestExpAssetCRUD(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	name := fmt.Sprintf("exp_crud_%d", time.Now().UnixNano())
	st := d.Exps()
	// clean slate（幂等）
	if old, _ := st.GetExpAssetByName(name); old != nil {
		_ = st.DeleteExpAsset(old.ID)
	}

	in := newTestExpAsset(name)
	id, err := st.CreateExpAsset(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = st.DeleteExpAsset(id) })

	got, err := st.GetExpAsset(id)
	if err != nil || got == nil {
		t.Fatalf("get after create: %v (nil=%v)", err, got == nil)
	}
	if got.Name != name || got.Version != 1 || !got.Enabled {
		t.Fatalf("unexpected row: %+v", got)
	}
	if len(got.CveIDs) != 1 || got.CveIDs[0] != "CVE-2020-1938" || len(got.Tags) != 2 {
		t.Fatalf("arrays not round-tripped: %v %v", got.CveIDs, got.Tags)
	}
	if string(got.FP) == "" || string(got.Exec) == "" {
		t.Fatal("json blobs lost")
	}
	if got.Cleanup != nil {
		t.Fatalf("cleanup should be nil, got %s", got.Cleanup)
	}

	byName, err := st.GetExpAssetByName(name)
	if err != nil || byName == nil || byName.ID != id {
		t.Fatalf("get by name: %v %+v", err, byName)
	}

	// 重名冲突
	if _, err := st.CreateExpAsset(newTestExpAsset(name)); err == nil {
		t.Fatal("duplicate name should fail")
	}

	// 更新：改描述/标签 + cleanup 落值；版本 +1
	got.Desc = "v2 描述"
	got.Tags = []string{"tomcat", "rce"}
	got.Cleanup = json.RawMessage(`{"kind":"http","method":"DELETE","url":"http://{target}:{port}/session"}`)
	if err := st.UpdateExpAsset(got, 1); err != nil {
		t.Fatalf("update: %v", err)
	}
	got2, _ := st.GetExpAsset(id)
	if got2.Version != 2 || got2.Desc != "v2 描述" || got2.Cleanup == nil || len(got2.Tags) != 2 {
		t.Fatalf("update not applied: v=%d desc=%q cleanup=%v tags=%v", got2.Version, got2.Desc, got2.Cleanup, got2.Tags)
	}

	// 乐观版本冲突：拿旧版本改必须失败
	got2.Desc = "stale write"
	if err := st.UpdateExpAsset(got2, 1); err == nil {
		t.Fatal("stale version update should fail")
	}

	// 启停：停用后 ListExpAssets(true) 不可见，版本不动
	if err := st.SetExpAssetEnabled(id, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if g, _ := st.GetExpAsset(id); g.Enabled || g.Version != 2 {
		t.Fatalf("enable flip wrong: %+v", g)
	}
	enabledOnly, err := st.ListExpAssets(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range enabledOnly {
		if e.ID == id {
			t.Fatal("disabled exp still listed with enabledOnly")
		}
	}
	_ = st.SetExpAssetEnabled(id, true)

	// 删除：Get 返回 nil
	if err := st.DeleteExpAsset(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if g, _ := st.GetExpAsset(id); g != nil {
		t.Fatal("exp still present after delete")
	}
}

// TestExpAttemptsRecordAndList 成功/失败沉淀 + 台账读取 + 级联删除。
func TestExpAttemptsRecordAndList(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	name := fmt.Sprintf("exp_att_%d", time.Now().UnixNano())
	st := d.Exps()
	id, err := st.CreateExpAsset(newTestExpAsset(name))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = st.DeleteExpAsset(id) })

	// 成功：不允许带 failure_reason
	sid, err := st.RecordExpAttempt(&ExpAttempt{
		ExpID: id, Target: "10.0.0.1:8080", Status: ExpAttemptSuccess,
		Detail: "oracle 命中", Evidence: json.RawMessage(`{"status":200,"hit":"Apache Tomcat"}`),
	})
	if err != nil {
		t.Fatalf("record success: %v", err)
	}
	if sid == 0 {
		t.Fatal("attempt id should be set")
	}

	// 失败：必须带合法 failure_reason
	_, err = st.RecordExpAttempt(&ExpAttempt{
		ExpID: id, Target: "10.0.0.2:8080", Status: ExpAttemptFailed,
		FailureReason: ExpFailOracleNotMatched, Detail: "返回 404，判定未命中",
	})
	if err != nil {
		t.Fatalf("record failed attempt: %v", err)
	}
	_, err = st.RecordExpAttempt(&ExpAttempt{
		ExpID: id, Target: "10.0.0.3:8080", Status: ExpAttemptFailed,
		FailureReason: ExpFailVersionMismatch, Detail: "实际版本 10.1 超区间",
	})
	if err != nil {
		t.Fatalf("record failed attempt 2: %v", err)
	}

	// 校验拒绝：失败缺 reason / reason 非法 / 成功带 reason / 空 target
	bad := []*ExpAttempt{
		{ExpID: id, Target: "t", Status: ExpAttemptFailed, Detail: "x"},
		{ExpID: id, Target: "t", Status: ExpAttemptFailed, FailureReason: "nope", Detail: "x"},
		{ExpID: id, Target: "t", Status: ExpAttemptSuccess, FailureReason: ExpFailOther},
		{ExpID: id, Status: ExpAttemptSuccess},
		{ExpID: id, Target: "t", Status: "weird"},
	}
	for i, b := range bad {
		if _, err := st.RecordExpAttempt(b); err == nil {
			t.Fatalf("bad attempt %d should be rejected: %+v", i, b)
		}
	}

	list, err := st.ListExpAttempts(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("want 3 attempts, got %d", len(list))
	}
	// newest first：最后一条先进列表
	if list[0].FailureReason != ExpFailVersionMismatch || list[0].Status != ExpAttemptFailed {
		t.Fatalf("order/status wrong: %+v", list[0])
	}
	if list[2].FailureReason != "" || list[2].Status != ExpAttemptSuccess {
		t.Fatalf("success row should carry no reason: %+v", list[2])
	}

	// 级联删除：EXP 删除后台账一并消失
	if err := st.DeleteExpAsset(id); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM exp_attempts WHERE exp_id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("attempts should cascade, got %d", n)
	}
}

// TestExpAssetStats 命中率 + 失败原因分布统计。
func TestExpAssetStats(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	name := fmt.Sprintf("exp_stats_%d", time.Now().UnixNano())
	st := d.Exps()
	id, err := st.CreateExpAsset(newTestExpAsset(name))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = st.DeleteExpAsset(id) })

	// 4 次尝试：1 成 3 败（oracle_not_matched ×2、timeout ×1）
	attempts := []*ExpAttempt{
		{ExpID: id, Target: "a:1", Status: ExpAttemptFailed, FailureReason: ExpFailOracleNotMatched, Detail: "d1"},
		{ExpID: id, Target: "b:2", Status: ExpAttemptFailed, FailureReason: ExpFailTimeout, Detail: "d2"},
		{ExpID: id, Target: "c:3", Status: ExpAttemptSuccess, Detail: "ok"},
		{ExpID: id, Target: "e:5", Status: ExpAttemptFailed, FailureReason: ExpFailOracleNotMatched, Detail: "d3"},
	}
	for _, a := range attempts {
		if _, err := st.RecordExpAttempt(a); err != nil {
			t.Fatalf("record %+v: %v", a, err)
		}
	}

	got, err := st.ExpAssetStatsByID(id)
	if err != nil || got == nil {
		t.Fatalf("stats by id: %v %+v", err, got)
	}
	if got.Attempts != 4 || got.Success != 1 || got.Failed != 3 {
		t.Fatalf("counts wrong: %+v", got)
	}
	if got.HitRate != 0.25 {
		t.Fatalf("hit rate = %v, want 0.25", got.HitRate)
	}
	if got.FailureDist[ExpFailOracleNotMatched] != 2 || got.FailureDist[ExpFailTimeout] != 1 {
		t.Fatalf("failure dist wrong: %v", got.FailureDist)
	}
	if got.LastAttemptAt == nil {
		t.Fatal("last attempt at should be set")
	}

	// 全量统计里包含本条
	all, err := st.ExpAssetStats()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range all {
		if s.ExpID == id {
			found = true
		}
	}
	if !found {
		t.Fatal("stats list missing the exp")
	}
}

// TestExpSchemaMigrationMatchesTypes 冒烟：schema.sql §N 的表确实存在且
// 约束生效（直接插坏 status 会被 CHECK 拒绝——repository 校验之外的兜底）。
func TestExpSchemaMigrationMatchesTypes(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	name := fmt.Sprintf("exp_schema_%d", time.Now().UnixNano())
	id, err := d.Exps().CreateExpAsset(newTestExpAsset(name))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Exps().DeleteExpAsset(id) })

	if _, err := d.Exec(`INSERT INTO exp_attempts(exp_id, target, status) VALUES ($1, 't', 'bogus')`, id); err == nil {
		t.Fatal("CHECK on status should reject bogus value")
	}
	if _, err := d.Exec(`INSERT INTO exp_attempts(exp_id, target, status) VALUES ($1, 't', 'failed')`, id); err == nil {
		t.Fatal("CHECK should reject failed attempt without failure_reason")
	}
	if _, err := d.Exec(`INSERT INTO exp_attempts(exp_id, target, status, failure_reason) VALUES ($1, 't', 'failed', 'bogus')`, id); err == nil {
		t.Fatal("CHECK should reject bogus failure_reason")
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM exp_attempts WHERE exp_id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("no attempt rows should have landed, got %d", n)
	}
}
