package db

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizeCVEIDs(t *testing.T) {
	ids, err := NormalizeCVEIDs([]string{" cve-2026-0001 ", "CVE-2026-0002", "CVE-2026-0001"})
	if err != nil || !reflect.DeepEqual(ids, []string{"CVE-2026-0001", "CVE-2026-0002"}) {
		t.Fatalf("normalized ids = %v, %v", ids, err)
	}
	for _, invalid := range []string{"", "CVE-26-0001", "CVE-2026-123", "GHSA-2026-0001"} {
		if _, err := NormalizeCVEID(invalid); !errors.Is(err, ErrCVEInvalid) {
			t.Fatalf("NormalizeCVEID(%q) error = %v", invalid, err)
		}
	}
	tooMany := make([]string, MaxTaskCVECount+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("CVE-2026-%04d", i+1)
	}
	if _, err := NormalizeCVEIDs(tooMany); !errors.Is(err, ErrCVEInvalid) {
		t.Fatalf("count limit error = %v", err)
	}
}

func TestTaskCVEFindingLifecycleAndLegacyCompatibility(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	base := time.Now().UnixNano() % 90000000
	firstCVE := fmt.Sprintf("CVE-2026-%08d", base)
	secondCVE := fmt.Sprintf("CVE-2026-%08d", base+1)
	outsideCVE := fmt.Sprintf("CVE-2026-%08d", base+2)
	task, err := d.CreateTaskWithOptions("CVE root", "validate both CVEs", TaskCreateOptions{
		CVEIDs: []string{strings.ToLower(firstCVE), secondCVE, firstCVE},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID)
		_ = d.DeleteTask(task.ID)
	})
	if !reflect.DeepEqual(task.CVEIDs, []string{firstCVE, secondCVE}) {
		t.Fatalf("created task CVEs = %v", task.CVEIDs)
	}
	store := d.Exploration(task.ExplorationID)
	description, goal, rootCVEs, err := store.RootContext()
	if err != nil || description != "CVE root" || goal != "validate both CVEs" || !reflect.DeepEqual(rootCVEs, []string{firstCVE, secondCVE}) {
		t.Fatalf("root context = %q %q %v, %v", description, goal, rootCVEs, err)
	}
	var originPayload []byte
	if err := d.QueryRow(`SELECT payload FROM exploration_nodes WHERE exploration_id=$1 AND state='origin'`, task.ExplorationID).Scan(&originPayload); err != nil ||
		!strings.Contains(string(originPayload), firstCVE) || !strings.Contains(string(originPayload), secondCVE) {
		t.Fatalf("root origin lost CVEs: %s, %v", originPayload, err)
	}
	record := func(cveID string) (*RecordedFinding, error) {
		return store.RecordFinding(t.Context(), RecordFindingInput{
			TaskID: task.ID, VulnClass: "CVE test", Severity: SeverityHigh,
			Summary: "CVE scoped finding", Evidence: "local fixture", Worker: "test", CVEID: cveID,
		})
	}
	if _, err := record(""); err == nil || !strings.Contains(err.Error(), "CVE") {
		t.Fatalf("missing CVE error = %v", err)
	}
	if _, err := record(outsideCVE); err == nil || !strings.Contains(err.Error(), "不属于当前任务") {
		t.Fatalf("outside CVE error = %v", err)
	}
	first, err := record(firstCVE)
	if err != nil {
		t.Fatal(err)
	}
	second, err := record(secondCVE)
	if err != nil {
		t.Fatal(err)
	}
	if first.CVEID != firstCVE || second.CVEID != secondCVE {
		t.Fatalf("recorded CVEs = %q %q", first.CVEID, second.CVEID)
	}
	if n, err := d.SetFindingReportVersionByNodeID(t.Context(), first.NodeID, "## CVE report", nil); err != nil || n != 1 {
		t.Fatalf("set report rows=%d err=%v", n, err)
	}
	stored, err := d.GetFinding(first.FindingID)
	if err != nil || stored.CVEID != firstCVE || stored.Report != "## CVE report" {
		t.Fatalf("finding report/CVE = %+v, %v", stored, err)
	}
	for _, tc := range []struct {
		cveID     string
		findingID int64
	}{{firstCVE, first.FindingID}, {secondCVE, second.FindingID}} {
		items, total, err := d.ListFindingsPage(FindingFilter{CVEID: tc.cveID}, 1, 20)
		if err != nil || total != 1 || len(items) != 1 || items[0].ID != tc.findingID || items[0].CVEID != tc.cveID {
			t.Fatalf("CVE filter %s: items=%+v total=%d err=%v", tc.cveID, items, total, err)
		}
	}

	legacy, err := d.CreateTaskWithOptions("legacy task", "legacy finding", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM findings WHERE task_id=$1`, legacy.ID)
		_ = d.DeleteTask(legacy.ID)
	})
	legacyStore := d.Exploration(legacy.ExplorationID)
	legacyFinding, err := legacyStore.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: legacy.ID, VulnClass: "legacy", Severity: SeverityLow, Summary: "legacy finding",
	})
	if err != nil || legacyFinding.CVEID != "" {
		t.Fatalf("legacy empty CVE record = %+v, %v", legacyFinding, err)
	}
	storedLegacy, err := d.GetFinding(legacyFinding.FindingID)
	if err != nil || storedLegacy.CVEID != "" {
		t.Fatalf("legacy finding changed shape: %+v, %v", storedLegacy, err)
	}
	if _, err := legacyStore.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: legacy.ID, VulnClass: "legacy", Severity: SeverityLow, Summary: "must reject", CVEID: firstCVE,
	}); err == nil || !strings.Contains(err.Error(), "存量任务未声明 CVE") {
		t.Fatalf("legacy non-empty CVE error = %v", err)
	}
}
