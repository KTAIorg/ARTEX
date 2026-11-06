package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestTaskCVEHTTPFiltersAndSpawnValidation(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	dataDir := t.TempDir()
	s := New(context.Background(), m, dataDir, dataDir, dataDir)
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, body any) (int, []byte) {
		t.Helper()
		var reader *bytes.Reader
		if body == nil {
			reader = bytes.NewReader(nil)
		} else {
			raw, _ := json.Marshal(body)
			reader = bytes.NewReader(raw)
		}
		req := httptest.NewRequest(method, path, reader)
		req.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		s.Handler().ServeHTTP(recorder, req)
		return recorder.Code, recorder.Body.Bytes()
	}
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{name: "missing", body: map[string]any{"description": "missing", "goal": "reject"}},
		{name: "empty", body: map[string]any{"description": "empty", "goal": "reject", "cve_ids": []string{}}},
		{name: "invalid", body: map[string]any{"description": "invalid", "goal": "reject", "cve_ids": []string{"not-a-cve"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := request(http.MethodPost, "/api/tasks", tc.body)
			if code != http.StatusBadRequest || !strings.Contains(string(body), "CVE") {
				t.Fatalf("create status=%d body=%s", code, body)
			}
		})
	}

	base := time.Now().UnixNano() % 90000000
	firstCVE := fmt.Sprintf("CVE-2026-%08d", base)
	secondCVE := fmt.Sprintf("CVE-2026-%08d", base+1)
	thirdCVE := fmt.Sprintf("CVE-2026-%08d", base+2)
	create := func(description string, cveIDs []string) (string, []string) {
		t.Helper()
		code, body := request(http.MethodPost, "/api/tasks", map[string]any{
			"description": description, "goal": "CVE HTTP test", "cve_ids": cveIDs,
		})
		if code != http.StatusCreated {
			t.Fatalf("create status=%d body=%s", code, body)
		}
		var created struct {
			ID     string   `json:"id"`
			CVEIDs []string `json:"cve_ids"`
		}
		if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
			t.Fatalf("decode created task: %s, %v", body, err)
		}
		numericID, _ := strconv.ParseInt(created.ID, 10, 64)
		t.Cleanup(func() {
			_, _ = m.pg.Exec(`DELETE FROM findings WHERE task_id=$1`, numericID)
			_, _ = m.DeleteTask(created.ID, DeleteTaskOptions{})
		})
		return created.ID, created.CVEIDs
	}
	firstID, firstDeclarations := create("first CVE task", []string{strings.ToLower(firstCVE), secondCVE, firstCVE})
	if !reflect.DeepEqual(firstDeclarations, []string{firstCVE, secondCVE}) {
		t.Fatalf("created declarations = %v", firstDeclarations)
	}
	secondID, _ := create("task without findings", []string{thirdCVE})
	for _, tc := range []struct {
		cveID  string
		taskID string
	}{{firstCVE, firstID}, {secondCVE, firstID}, {thirdCVE, secondID}} {
		code, body := request(http.MethodGet, "/api/tasks?cve_id="+url.QueryEscape(tc.cveID), nil)
		if code != http.StatusOK {
			t.Fatalf("task filter status=%d body=%s", code, body)
		}
		var list struct {
			Tasks []struct {
				ID     string   `json:"id"`
				CVEIDs []string `json:"cve_ids"`
			} `json:"tasks"`
		}
		if err := json.Unmarshal(body, &list); err != nil || len(list.Tasks) != 1 || list.Tasks[0].ID != tc.taskID {
			t.Fatalf("task CVE filter %s = %s, %v", tc.cveID, body, err)
		}
	}

	numericFirstID, _ := strconv.ParseInt(firstID, 10, 64)
	firstTask, ok := m.Task(firstID)
	if !ok {
		t.Fatal("created task missing from manager")
	}
	recorded := map[string]*db.RecordedFinding{}
	for _, cveID := range []string{firstCVE, secondCVE} {
		finding, err := m.pg.Exploration(firstTask.ExpID).RecordFinding(t.Context(), db.RecordFindingInput{
			TaskID: numericFirstID, VulnClass: "HTTP CVE test", Severity: db.SeverityHigh,
			Summary: "filtered by CVE", CVEID: cveID,
		})
		if err != nil {
			t.Fatal(err)
		}
		recorded[cveID] = finding
	}
	for cveID, expected := range recorded {
		code, body := request(http.MethodGet, "/api/findings?cve_id="+url.QueryEscape(cveID)+"&limit=20", nil)
		if code != http.StatusOK {
			t.Fatalf("finding filter status=%d body=%s", code, body)
		}
		var page struct {
			Items []struct {
				FindingID string `json:"finding_id"`
				CVEID     string `json:"cve_id"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(body, &page); err != nil || page.Total != 1 || len(page.Items) != 1 ||
			page.Items[0].FindingID != fmt.Sprint(expected.FindingID) || page.Items[0].CVEID != cveID {
			t.Fatalf("finding CVE filter %s = %s, %v", cveID, body, err)
		}
	}
	for _, path := range []string{"/api/tasks?cve_id=bad", "/api/findings?cve_id=bad&limit=20"} {
		code, body := request(http.MethodGet, path, nil)
		if code != http.StatusBadRequest || !strings.Contains(string(body), "CVE") {
			t.Fatalf("invalid filter %s: status=%d body=%s", path, code, body)
		}
	}
	spawnResult := workflowCall(t, t.Context(), s.toolSpawnTask(), map[string]any{
		"description": "spawn without CVE", "goal": "must reject", "parent_ref": firstID,
	}, true)
	if !strings.Contains(spawnResult, "CVE") {
		t.Fatalf("spawn_task error = %s", spawnResult)
	}
}
