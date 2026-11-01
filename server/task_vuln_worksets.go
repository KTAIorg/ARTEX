package server

import (
	"errors"
	"net/http"

	"github.com/Autumn-27/artex/db"
)

// 500 条资产快照（含摘要/标签/评级）远超 task_assets 的 512KB，放宽到 4MiB；
// 仍由 MaxBytesReader 兜底防失控请求体。
const maxTaskVulnWorksetRequestBytes = 4 << 20

func writeTaskVulnWorksetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrTaskVulnWorksetInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, db.ErrTaskVulnWorksetTaskNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

// pinTaskVulnWorkset snapshots the submitted kt-vuln assets onto the task.
// 鉴权/归属与 attachTaskAssets 完全一致：路由先过全局 JWT，再经 m.Task 查
// 在册任务，任务不存在（含已删除/未加载）一律 404。
func (s *Server) pinTaskVulnWorkset(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskVulnWorksetRequestBytes)
	var request struct {
		Items []db.TaskVulnWorksetItem `json:"items"`
	}
	if err := decode(r, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	taskID, _ := parseTaskID(task.ID)
	pinned, err := s.m.Assets().PinTaskVulnWorksets(r.Context(), taskID, request.Items)
	if err != nil {
		writeTaskVulnWorksetError(w, err)
		return
	}
	task.Notify()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pinned": pinned})
}

func (s *Server) listTaskVulnWorksets(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	taskID, _ := parseTaskID(task.ID)
	items, err := s.m.Assets().ListTaskVulnWorksets(r.Context(), taskID)
	if err != nil {
		writeTaskVulnWorksetError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
