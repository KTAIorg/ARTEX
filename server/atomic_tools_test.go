package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/atomic"
)

// 原子操作接入层测试：atomic 注册表 → CoreTool 封包（envelope 契约在工具侧不丢）、
// tools 表 seed（system 行 + 默认绑定 worker/pentest）。

func TestAtomicToolsExposeRegistry(t *testing.T) {
	tools := (&Server{}).atomicTools()
	want := map[string]bool{"atomic_fingerprint": false, "atomic_weak_cred": false, "atomic_verify_poc": false}
	for _, tl := range tools {
		if _, ok := want[tl.Name()]; !ok {
			t.Fatalf("意外工具 %s", tl.Name())
		}
		want[tl.Name()] = true
		if tl.Description() == "" || tl.InputSchema() == nil {
			t.Fatalf("%s 缺描述或 schema", tl.Name())
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("atomicTools 缺少 %s", k)
		}
	}
}

func TestAtomicCoreToolEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "envelope-test/1")
		w.Write([]byte("<html><head><title>En</title></head></html>"))
	}))
	defer srv.Close()

	tool := atomicCoreTool(mustGet(t, "atomic_fingerprint"))
	in, _ := json.Marshal(map[string]any{"target": srv.URL})
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var out atomic.Result
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("工具结果不是合法 envelope JSON: %v", err)
	}
	if !out.OK || out.Error != "" || out.Evidence == "" {
		t.Fatalf("envelope 契约不符: %+v", out)
	}
	if !strings.Contains(out.Evidence, "envelope-test/1") {
		t.Fatalf("evidence 未带回指纹: %q", out.Evidence)
	}
}

func mustGet(t *testing.T, key string) atomic.Op {
	t.Helper()
	op, ok := atomic.Get(key)
	if !ok {
		t.Fatalf("原子操作 %s 未注册", key)
	}
	return op
}

func TestSeedAtomicTools(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)
	s.seedAtomicTools()

	for _, key := range []string{"atomic_fingerprint", "atomic_weak_cred", "atomic_verify_poc"} {
		row, err := m.PG().GetTool(key)
		if err != nil || row == nil {
			t.Fatalf("tools 表缺 %s (err=%v)", key, err)
		}
		if !row.System || row.Kind != "builtin" {
			t.Fatalf("%s 行应为 system builtin: %+v", key, row)
		}
		if !containsStr(row.Agents, "worker") || !containsStr(row.Agents, "pentest") {
			t.Fatalf("%s 默认绑定应含 worker+pentest: %v", key, row.Agents)
		}
		if !row.Enabled {
			t.Fatalf("%s 应默认启用", key)
		}
	}
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
