package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestNormalizeTaskVulnWorksetItemsRejectsBadBatches(t *testing.T) {
	over := make([]TaskVulnWorksetItem, MaxTaskVulnWorksetItems+1)
	for i := range over {
		over[i] = TaskVulnWorksetItem{VulnAssetID: int64(i + 1), Snapshot: json.RawMessage(`{}`)}
	}
	cases := []struct {
		name  string
		items []TaskVulnWorksetItem
	}{
		{"empty batch", nil},
		{"zero id", []TaskVulnWorksetItem{{VulnAssetID: 0, Snapshot: json.RawMessage(`{}`)}}},
		{"negative id", []TaskVulnWorksetItem{{VulnAssetID: -5, Snapshot: json.RawMessage(`{}`)}}},
		{"snapshot array", []TaskVulnWorksetItem{{VulnAssetID: 1, Snapshot: json.RawMessage(`[1,2]`)}}},
		{"snapshot string", []TaskVulnWorksetItem{{VulnAssetID: 1, Snapshot: json.RawMessage(`"x"`)}}},
		{"snapshot number", []TaskVulnWorksetItem{{VulnAssetID: 1, Snapshot: json.RawMessage(`42`)}}},
		{"snapshot null", []TaskVulnWorksetItem{{VulnAssetID: 1, Snapshot: json.RawMessage(`null`)}}},
		{"snapshot missing", []TaskVulnWorksetItem{{VulnAssetID: 1}}},
		{"snapshot broken json", []TaskVulnWorksetItem{{VulnAssetID: 1, Snapshot: json.RawMessage(`{"a":`)}}},
		{"over limit", over},
	}
	for _, tc := range cases {
		if _, err := normalizeTaskVulnWorksetItems(tc.items); !errors.Is(err, ErrTaskVulnWorksetInvalid) {
			t.Errorf("%s: err=%v, want ErrTaskVulnWorksetInvalid", tc.name, err)
		}
	}
}

func TestNormalizeTaskVulnWorksetItemsDedupesInBatch(t *testing.T) {
	items := []TaskVulnWorksetItem{
		{VulnAssetID: 7, Snapshot: json.RawMessage(`{"a":1}`)},
		{VulnAssetID: 8, Snapshot: json.RawMessage(`{}`)},
		{VulnAssetID: 7, Snapshot: json.RawMessage(`{"a":2}`)},
	}
	got, err := normalizeTaskVulnWorksetItems(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2 (in-batch duplicates collapse)", len(got))
	}
	if string(got[0].Snapshot) != `{"a":1}` {
		t.Fatalf("duplicate kept the later snapshot: %s", got[0].Snapshot)
	}
}

func TestPinAndListTaskVulnWorksets(t *testing.T) {
	d, assets, _ := testSetup(t)
	defer d.Close()

	task, err := d.CreateTask(fmt.Sprintf("vuln workset pin %d", time.Now().UnixNano()), "goal", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ctx := context.Background()

	batch := []TaskVulnWorksetItem{
		{VulnAssetID: 101, Snapshot: json.RawMessage(`{"tier":"A","score":92}`)},
		{VulnAssetID: 202, Snapshot: json.RawMessage(`{"url":"https://a.example.com"}`)},
	}
	if pinned, err := assets.PinTaskVulnWorksets(ctx, task.ID, batch); err != nil || pinned != 2 {
		t.Fatalf("first pin: pinned=%d err=%v, want 2/nil", pinned, err)
	}
	// 重复 pin 幂等：只计新增；已 pin 的资产保留原始快照（first write wins）。
	rebatch := []TaskVulnWorksetItem{
		{VulnAssetID: 101, Snapshot: json.RawMessage(`{"tier":"B"}`)},
		{VulnAssetID: 303, Snapshot: json.RawMessage(`{}`)},
	}
	if pinned, err := assets.PinTaskVulnWorksets(ctx, task.ID, rebatch); err != nil || pinned != 1 {
		t.Fatalf("re-pin: pinned=%d err=%v, want 1/nil", pinned, err)
	}
	got, err := assets.ListTaskVulnWorksets(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("list len=%d, want 3", len(got))
	}
	wantOrder := []int64{101, 202, 303}
	wantSnapshots := []string{`{"tier":"A","score":92}`, `{"url":"https://a.example.com"}`, `{}`}
	for i, item := range got {
		if item.VulnAssetID != wantOrder[i] {
			t.Errorf("item %d vuln_asset_id=%d, want %d (id ASC)", i, item.VulnAssetID, wantOrder[i])
		}
		if item.TaskID != task.ID || item.ID == 0 || item.CreatedAt.IsZero() {
			t.Errorf("item %d incomplete row: %+v", i, item)
		}
		var want, have map[string]any
		if err := json.Unmarshal([]byte(wantSnapshots[i]), &want); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(item.Snapshot, &have); err != nil {
			t.Fatalf("item %d snapshot not JSON: %v", i, err)
		}
		if !reflect.DeepEqual(want, have) {
			t.Errorf("item %d snapshot=%s, want %s (re-pin must not rewrite)", i, item.Snapshot, wantSnapshots[i])
		}
	}

	if _, err := assets.PinTaskVulnWorksets(ctx, 0, batch); !errors.Is(err, ErrTaskVulnWorksetInvalid) {
		t.Errorf("taskID=0: err=%v, want ErrTaskVulnWorksetInvalid", err)
	}
	if _, err := assets.ListTaskVulnWorksets(ctx, 0); !errors.Is(err, ErrTaskVulnWorksetInvalid) {
		t.Errorf("list taskID=0: err=%v, want ErrTaskVulnWorksetInvalid", err)
	}
	if _, err := assets.PinTaskVulnWorksets(ctx, 1<<40, batch); !errors.Is(err, ErrTaskVulnWorksetTaskNotFound) {
		t.Errorf("missing task: err=%v, want ErrTaskVulnWorksetTaskNotFound", err)
	}
}
