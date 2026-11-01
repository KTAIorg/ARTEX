package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 任务下发时最多随单次请求 pin 的 kt-vuln 资产条数；对齐前端批量下发的上限。
const MaxTaskVulnWorksetItems = 500

var (
	ErrTaskVulnWorksetInvalid      = errors.New("invalid task vuln workset")
	ErrTaskVulnWorksetTaskNotFound = errors.New("task not found")
)

// TaskVulnWorksetItem is one entry of a pin request: the kt-vuln asset id plus
// the snapshot taken at task dispatch time. vuln_asset_id 只在本表内做唯一键，
// 不设外键——资产事实源在 vuln.ktyun.cc，对端删除后快照仍需可回放。
type TaskVulnWorksetItem struct {
	VulnAssetID int64           `json:"vuln_asset_id"`
	Snapshot    json.RawMessage `json:"snapshot"`
}

// TaskVulnWorkset is one pinned workset row, all columns included. Snapshot is
// the verbatim JSON object captured at pin time; live facts are re-read from
// vuln.ktyun.cc, never mutated here.
type TaskVulnWorkset struct {
	ID          int64           `json:"id"`
	TaskID      int64           `json:"task_id"`
	VulnAssetID int64           `json:"vuln_asset_id"`
	Snapshot    json.RawMessage `json:"snapshot"`
	CreatedAt   time.Time       `json:"created_at"`
}

// normalizeTaskVulnWorksetItems validates a pin batch and collapses in-batch
// duplicates to the first occurrence (so one INSERT never carries the same
// conflict key twice). Empty batch, >500 items, non-positive ids and snapshots
// that are not JSON objects are all rejected with ErrTaskVulnWorksetInvalid.
func normalizeTaskVulnWorksetItems(items []TaskVulnWorksetItem) ([]TaskVulnWorksetItem, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: items is required", ErrTaskVulnWorksetInvalid)
	}
	if len(items) > MaxTaskVulnWorksetItems {
		return nil, fmt.Errorf("%w: at most %d items per request", ErrTaskVulnWorksetInvalid, MaxTaskVulnWorksetItems)
	}
	seen := make(map[int64]struct{}, len(items))
	normalized := make([]TaskVulnWorksetItem, 0, len(items))
	for index, item := range items {
		if item.VulnAssetID <= 0 {
			return nil, fmt.Errorf("%w: item %d vuln_asset_id must be a positive integer", ErrTaskVulnWorksetInvalid, index+1)
		}
		snapshot := strings.TrimSpace(string(item.Snapshot))
		// 前缀检查先把 null / 数组 / 标量挡在 400；Unmarshal 再保证 JSON 合法
		//（连库后 jsonb 解析失败会变成 500）。
		if snapshot == "" || snapshot[0] != '{' {
			return nil, fmt.Errorf("%w: item %d snapshot must be a JSON object", ErrTaskVulnWorksetInvalid, index+1)
		}
		var object map[string]any
		if err := json.Unmarshal([]byte(snapshot), &object); err != nil {
			return nil, fmt.Errorf("%w: item %d snapshot is not valid JSON: %v", ErrTaskVulnWorksetInvalid, index+1, err)
		}
		if _, ok := seen[item.VulnAssetID]; ok {
			continue
		}
		seen[item.VulnAssetID] = struct{}{}
		normalized = append(normalized, TaskVulnWorksetItem{VulnAssetID: item.VulnAssetID, Snapshot: json.RawMessage(snapshot)})
	}
	return normalized, nil
}

// PinTaskVulnWorksets snapshots kt-vuln assets onto one live task in a single
// batched statement. Already-pinned (task_id, vuln_asset_id) pairs are ignored
// (first write wins — a re-dispatch never rewrites the original snapshot), and
// the return value counts only newly inserted rows. A missing or soft-deleted
// task yields ErrTaskVulnWorksetTaskNotFound so the API can answer 404 instead
// of a silent no-op.
func (s *AssetStore) PinTaskVulnWorksets(ctx context.Context, taskID int64, items []TaskVulnWorksetItem) (int, error) {
	if taskID <= 0 {
		return 0, fmt.Errorf("%w: task id must be positive", ErrTaskVulnWorksetInvalid)
	}
	items, err := normalizeTaskVulnWorksetItems(items)
	if err != nil {
		return 0, err
	}
	values := make([]string, 0, len(items))
	args := make([]any, 0, 1+2*len(items))
	args = append(args, taskID)
	for _, item := range items {
		values = append(values, fmt.Sprintf("($%d::bigint,$%d::jsonb)", len(args)+1, len(args)+2))
		args = append(args, item.VulnAssetID, string(item.Snapshot))
	}
	query := `
INSERT INTO task_vuln_worksets(task_id, vuln_asset_id, snapshot)
SELECT task.id, v.vuln_asset_id, v.snapshot
FROM tasks task
JOIN (VALUES ` + strings.Join(values, ",") + `) AS v(vuln_asset_id, snapshot) ON true
WHERE task.id=$1 AND task.deleted_at IS NULL
ON CONFLICT (task_id, vuln_asset_id) DO NOTHING`
	exec := s.db.ExecContext
	if s.tx != nil {
		exec = s.tx.ExecContext
	}
	result, err := exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if inserted == 0 {
		// 全部冲突（返回 0 新增）与任务不存在在 RowsAffected 上不可区分，补一次
		// 存在性检查以分类错误码。
		var exists bool
		queryRow := s.db.QueryRowContext
		if s.tx != nil {
			queryRow = s.tx.QueryRowContext
		}
		if err := queryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL)`, taskID).Scan(&exists); err != nil {
			return 0, err
		}
		if !exists {
			return 0, ErrTaskVulnWorksetTaskNotFound
		}
	}
	return int(inserted), nil
}

// ListTaskVulnWorksets returns every pinned workset row of a task, all columns,
// ordered by insertion (id ASC). taskID<=0 is a caller bug, not an empty list.
func (s *AssetStore) ListTaskVulnWorksets(ctx context.Context, taskID int64) ([]TaskVulnWorkset, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("%w: task id must be positive", ErrTaskVulnWorksetInvalid)
	}
	query := s.db.QueryContext
	if s.tx != nil {
		query = s.tx.QueryContext
	}
	rows, err := query(ctx, `
SELECT id, task_id, vuln_asset_id, snapshot::text, created_at
FROM task_vuln_worksets WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskVulnWorkset{}
	for rows.Next() {
		var item TaskVulnWorkset
		var snapshot string
		if err := rows.Scan(&item.ID, &item.TaskID, &item.VulnAssetID, &snapshot, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Snapshot = json.RawMessage(snapshot)
		out = append(out, item)
	}
	return out, rows.Err()
}
