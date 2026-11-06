package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestTaskCVEGraphOverviewAndReportFinding(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	base := time.Now().UnixNano() % 90000000
	firstCVE := fmt.Sprintf("CVE-2026-%08d", base)
	secondCVE := fmt.Sprintf("CVE-2026-%08d", base+1)
	outsideCVE := fmt.Sprintf("CVE-2026-%08d", base+2)
	task, err := d.CreateTaskWithOptions("agent CVE task", "enforce finding ownership", db.TaskCreateOptions{
		CVEIDs: []string{firstCVE, secondCVE},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID)
		_ = d.DeleteTask(task.ID)
	})
	tools := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	tools.SetTaskID(task.ID)
	overview := tools.graphOverviewData()
	taskOverview, ok := overview["task"].(map[string]any)
	if !ok || !reflect.DeepEqual(taskOverview["cve_ids"], []string{firstCVE, secondCVE}) {
		t.Fatalf("graph overview CVEs = %#v", overview["task"])
	}
	tool := tools.addFinding()
	for _, cveID := range []string{"", outsideCVE} {
		input := map[string]any{"vulnclass": "CVE test", "severity": "high", "summary": "must reject"}
		if cveID != "" {
			input["cve_id"] = cveID
		}
		raw, _ := json.Marshal(input)
		result, err := tool.Call(context.Background(), raw, nil)
		if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "CVE") {
			t.Fatalf("report_finding cve_id=%q: error=%v result=%s", cveID, err, result.Flatten())
		}
	}
	for _, cveID := range []string{firstCVE, secondCVE} {
		input := map[string]any{
			"vulnclass": "CVE test", "severity": "high", "summary": "agent finding", "evidence": "local fixture", "cve_id": cveID,
		}
		raw, _ := json.Marshal(input)
		result, err := tool.Call(context.Background(), raw, nil)
		if err != nil || result.IsError || !strings.Contains(result.Flatten(), cveID) {
			t.Fatalf("report_finding valid %s: error=%v result=%s", cveID, err, result.Flatten())
		}
	}
	items, total, err := d.ListFindingsPage(db.FindingFilter{TaskID: fmt.Sprint(task.ID)}, 1, 20)
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("agent findings = %+v total=%d err=%v", items, total, err)
	}
	seen := map[string]bool{}
	for _, finding := range items {
		seen[finding.CVEID] = true
	}
	if !seen[firstCVE] || !seen[secondCVE] {
		t.Fatalf("agent finding CVEs = %v", seen)
	}
}
