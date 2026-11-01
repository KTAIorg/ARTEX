package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func newVulnWorksetServer(t *testing.T) (*Server, func()) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	s := &Server{m: m}
	return s, func() { m.Close() }
}

func (s *Server) pinVulnWorkset(t *testing.T, taskID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/{id}/vuln-workset", strings.NewReader(body))
	req.SetPathValue("id", taskID)
	rec := httptest.NewRecorder()
	s.pinTaskVulnWorkset(rec, req)
	return rec
}

func (s *Server) listVulnWorkset(t *testing.T, taskID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/tasks/{id}/vuln-workset", nil)
	req.SetPathValue("id", taskID)
	rec := httptest.NewRecorder()
	s.listTaskVulnWorksets(rec, req)
	return rec
}

func TestTaskVulnWorksetPinListAndIdempotentRepin(t *testing.T) {
	s, done := newVulnWorksetServer(t)
	defer done()

	task, err := s.m.CreateTaskWithOptions("vuln workset http", "goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = s.m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	first := s.pinVulnWorkset(t, task.ID, `{"items":[
		{"vuln_asset_id":101,"snapshot":{"tier":"A","score":92}},
		{"vuln_asset_id":202,"snapshot":{"url":"https://a.example.com"}}
	]}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first pin status=%d body=%s", first.Code, first.Body.String())
	}
	var pinned struct {
		OK     bool `json:"ok"`
		Pinned int  `json:"pinned"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &pinned); err != nil {
		t.Fatal(err)
	}
	if !pinned.OK || pinned.Pinned != 2 {
		t.Fatalf("first pin response=%s, want ok=true pinned=2", first.Body.String())
	}

	// 重复 pin 幂等：101 冲突被忽略（pinned 只计新增），303 是新资产。
	second := s.pinVulnWorkset(t, task.ID, `{"items":[
		{"vuln_asset_id":101,"snapshot":{"tier":"B"}},
		{"vuln_asset_id":303,"snapshot":{}}
	]}`)
	if second.Code != http.StatusOK {
		t.Fatalf("second pin status=%d body=%s", second.Code, second.Body.String())
	}
	pinned.Pinned = -1
	if err := json.Unmarshal(second.Body.Bytes(), &pinned); err != nil {
		t.Fatal(err)
	}
	if !pinned.OK || pinned.Pinned != 1 {
		t.Fatalf("second pin response=%s, want ok=true pinned=1", second.Body.String())
	}

	list := s.listVulnWorkset(t, task.ID)
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	var payload struct {
		Items []db.TaskVulnWorkset `json:"items"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) != 3 {
		t.Fatalf("items=%d, want 3", len(payload.Items))
	}
	wantOrder := []int64{101, 202, 303}
	for i, item := range payload.Items {
		if item.VulnAssetID != wantOrder[i] {
			t.Errorf("item %d vuln_asset_id=%d, want %d (id ASC)", i, item.VulnAssetID, wantOrder[i])
		}
		if item.ID == 0 || item.TaskID == 0 || item.CreatedAt.IsZero() || len(item.Snapshot) == 0 {
			t.Errorf("item %d missing full columns: %+v", i, item)
		}
	}
	var firstSnapshot map[string]any
	if err := json.Unmarshal(payload.Items[0].Snapshot, &firstSnapshot); err != nil {
		t.Fatal(err)
	}
	if firstSnapshot["tier"] != "A" {
		t.Errorf("vuln_asset_id=101 snapshot rewritten by re-pin: %s", payload.Items[0].Snapshot)
	}
}

func TestTaskVulnWorksetRejectsInvalidRequests(t *testing.T) {
	s, done := newVulnWorksetServer(t)
	defer done()

	task, err := s.m.CreateTaskWithOptions("vuln workset validation", "goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = s.m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	over := make([]string, 0, db.MaxTaskVulnWorksetItems+1)
	over = append(over, `{"items":[`)
	for i := 0; i <= db.MaxTaskVulnWorksetItems; i++ {
		if i > 0 {
			over = append(over, `,`)
		}
		over = append(over, fmt.Sprintf(`{"vuln_asset_id":%d,"snapshot":{}}`, i+1))
	}
	over = append(over, `]}`)
	bodies := map[string]string{
		"broken json":       `{"items":[`,
		"empty items":       `{"items":[]}`,
		"items missing":     `{}`,
		"zero id":           `{"items":[{"vuln_asset_id":0,"snapshot":{}}]}`,
		"negative id":       `{"items":[{"vuln_asset_id":-5,"snapshot":{}}]}`,
		"snapshot array":    `{"items":[{"vuln_asset_id":1,"snapshot":[1,2]}]}`,
		"snapshot string":   `{"items":[{"vuln_asset_id":1,"snapshot":"x"}]}`,
		"snapshot null":     `{"items":[{"vuln_asset_id":1,"snapshot":null}]}`,
		"snapshot missing":  `{"items":[{"vuln_asset_id":1}]}`,
		"snapshot bad json": `{"items":[{"vuln_asset_id":1,"snapshot":{"a":}}]}`,
		"over 500":          strings.Join(over, ""),
	}
	for name, body := range bodies {
		if rec := s.pinVulnWorkset(t, task.ID, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	// 全部被拒后任务工作集必须保持为空。
	if rec := s.listVulnWorkset(t, task.ID); rec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
	} else if !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Errorf("rejected pins leaked rows: %s", rec.Body.String())
	}
}

func TestTaskVulnWorksetUnknownTaskReturns404(t *testing.T) {
	s, done := newVulnWorksetServer(t)
	defer done()

	const unknown = "999999999"
	if rec := s.pinVulnWorkset(t, unknown, `{"items":[{"vuln_asset_id":1,"snapshot":{}}]}`); rec.Code != http.StatusNotFound {
		t.Errorf("POST unknown task status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	if rec := s.listVulnWorkset(t, unknown); rec.Code != http.StatusNotFound {
		t.Errorf("GET unknown task status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	// 与 attachTaskAssets 同款：非数字任务 id 也走 m.Task 未命中 → 404。
	if rec := s.pinVulnWorkset(t, "not-a-number", `{"items":[{"vuln_asset_id":1,"snapshot":{}}]}`); rec.Code != http.StatusNotFound {
		t.Errorf("POST non-numeric task status=%d, want 404", rec.Code)
	}
}
