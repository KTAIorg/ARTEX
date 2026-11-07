package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestCreateTaskFromTemplateHTTPReusesRendersAndOverrides(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "artex-task-template-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for attempt := 0; attempt < 20; attempt++ {
			if err := os.RemoveAll(dataDir); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := os.RemoveAll(dataDir); err != nil {
			t.Errorf("remove manager data directory: %v", err)
		}
	})
	m, err := NewManager(dataDir, "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	template, err := m.pg.CreateTaskTemplate(db.TaskTemplateInput{
		Name:        fmt.Sprintf("CVE template %d", time.Now().UnixNano()),
		Description: "验证 {{target}} 的 {{cve_id}}；资产 {{资产}}",
		Goal:        "确认 {{cve_id}} 在 {{target}} 上的影响",
		Remark:      "目标 {{target}}",
		WorkerCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.DeleteTaskTemplate(template.ID) })

	do := func(body any) (int, map[string]any) {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	variables := func(target, cve, asset string) map[string]string {
		return map[string]string{"target": target, "cve_id": cve, "资产": asset}
	}

	code, missing := do(map[string]any{
		"template_id":        template.ID,
		"template_variables": map[string]string{"target": "https://missing.example"},
	})
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(missing["error"]), "cve_id") {
		t.Fatalf("missing variable status=%d body=%v", code, missing)
	}
	code, invalid := do(map[string]any{
		"template_id": template.ID,
		"template_variables": map[string]string{
			"target": "https://invalid.example", "cve_id": "CVE-2026-0001", "资产": "asset", "bad-name": "x",
		},
	})
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(invalid["error"]), "invalid variable name") {
		t.Fatalf("invalid variable status=%d body=%v", code, invalid)
	}

	code, first := do(map[string]any{
		"template_id":        template.ID,
		"template_variables": variables("https://one.example", "CVE-2026-0001", "one.example"),
	})
	if code != http.StatusCreated {
		t.Fatalf("first create status=%d body=%v", code, first)
	}
	firstID, _ := first["id"].(string)
	t.Cleanup(func() { _, _ = m.DeleteTask(firstID, DeleteTaskOptions{}) })
	if first["description"] != "验证 https://one.example 的 CVE-2026-0001；资产 one.example" ||
		first["goal"] != "确认 CVE-2026-0001 在 https://one.example 上的影响" ||
		first["remark"] != "目标 https://one.example" || first["worker_count"] != float64(2) {
		t.Fatalf("unexpected first task: %+v", first)
	}

	code, second := do(map[string]any{
		"description":        "顶层描述不得覆盖模板",
		"goal":               "顶层目标不得覆盖模板或嵌套 override",
		"remark":             "顶层备注不得覆盖模板或嵌套 override",
		"category_id":        123,
		"worker_count":       50,
		"template_id":        template.ID,
		"template_variables": variables("https://two.example", "CVE-2026-0002", "two.example"),
		"template_overrides": map[string]any{
			"goal": "覆盖后的目标", "remark": "", "worker_count": 0, "category_id": nil,
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("second create status=%d body=%v", code, second)
	}
	secondID, _ := second["id"].(string)
	t.Cleanup(func() { _, _ = m.DeleteTask(secondID, DeleteTaskOptions{}) })
	if second["description"] != "验证 https://two.example 的 CVE-2026-0002；资产 two.example" ||
		second["goal"] != "覆盖后的目标" || second["remark"] != "" || second["worker_count"] != float64(0) ||
		second["category_id"] != nil {
		t.Fatalf("unexpected second task: %+v", second)
	}

	stored, err := m.pg.GetTaskTemplate(template.ID)
	if err != nil || stored == nil {
		t.Fatalf("reload template: %+v, %v", stored, err)
	}
	if stored.Description != template.Description || stored.Goal != template.Goal || stored.Remark != template.Remark || stored.WorkerCount != 2 {
		t.Fatalf("task creation mutated template: %+v", stored)
	}

	code, notFound := do(map[string]any{
		"template_id":        template.ID + 1000000,
		"template_variables": map[string]string{},
	})
	if code != http.StatusNotFound {
		t.Fatalf("missing template status=%d body=%v", code, notFound)
	}
	code, withoutTemplate := do(map[string]any{
		"description": "direct", "goal": "direct", "template_variables": map[string]string{"target": "x"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("variables without template status=%d body=%v", code, withoutTemplate)
	}
	for name, body := range map[string]map[string]any{
		"description": {"goal": "direct"},
		"goal":        {"description": "direct"},
	} {
		code, response := do(body)
		if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(response["error"]), name) {
			t.Fatalf("direct create without %s status=%d body=%v", name, code, response)
		}
	}
}
