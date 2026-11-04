package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestLLMIdentityHTTPFlow 走真实 HTTP mux + PostgreSQL + 假 Casdoor/NewAPI，
// 验证身份凭据可配置、secret 不回显、未保存的 identity profile 也能测试/
// 拉模型，以及 relay 请求携带身份 token 与 managed 名。无本地 PG 配置时跳过。
func TestLLMIdentityHTTPFlow(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dataDir := t.TempDir()
	s := New(ctx, m, dataDir, dataDir, dataDir)
	tok, err := signJWT(s.jwtKey, "admin")
	if err != nil {
		t.Fatalf("sign admin jwt: %v", err)
	}
	h := s.Handler()

	do := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			reader = bytes.NewReader(encoded)
		}
		req := httptest.NewRequest(method, path, reader)
		req.Header.Set("Authorization", "Bearer "+tok)
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, req)
		var out map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: status=%d invalid json: %v", method, path, recorder.Code, err)
		}
		return recorder.Code, out
	}

	// 假 Casdoor：只认这一组测试凭据，返回一枚短时身份 token。
	var tokenHits int32
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "client_credentials" ||
			r.Form.Get("client_id") != "artex-test" || r.Form.Get("client_secret") != "dummy-identity-secret" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		atomic.AddInt32(&tokenHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"identity-jwt","expires_in":3600}`)
	}))
	defer tokenSrv.Close()

	// 假 NewAPI：模型列表与一次非流式 completion 都必须看到同一套身份头。
	var relayAuthFailures int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer identity-jwt" || r.Header.Get("X-Kito-Token-Name") != "artex" {
			atomic.AddInt32(&relayAuthFailures, 1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models":
			_, _ = io.WriteString(w, `{"data":[{"id":"test-model"}]}`)
		case "/v1/chat/completions":
			_, _ = io.WriteString(w, `{"id":"chat-1","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer relay.Close()

	suffix := time.Now().UnixNano()
	identityName := fmt.Sprintf("identity-http-%d", suffix)
	profileName := fmt.Sprintf("identity-profile-%d", suffix)
	code, out := do("POST", "/api/llm/identities", map[string]any{
		"name": identityName, "token_url": "https://auth.example.test/token", "client_id": "artex-test",
		"client_secret": "dummy-identity-secret", "scope": "newapi.relay", "managed_token_name": "artex",
	})
	if code != 200 {
		t.Fatalf("create identity: status=%d body=%v", code, out)
	}
	identityID := int64(out["id"].(float64))
	// API 只接受 https；测试改用假端点模拟真实 token 交换。
	if _, err := m.pg.Exec(`UPDATE llm_identities SET token_url=$1 WHERE id=$2`, tokenSrv.URL, identityID); err != nil {
		t.Fatalf("point test identity at fake Casdoor: %v", err)
	}
	defer func() {
		_, _ = m.pg.Exec(`DELETE FROM llm_profiles WHERE name=$1`, profileName)
		_, _ = m.pg.Exec(`DELETE FROM llm_identities WHERE id=$1`, identityID)
	}()

	code, out = do("GET", "/api/llm/identities", nil)
	if code != 200 {
		t.Fatalf("list identities: status=%d body=%v", code, out)
	}
	encoded, _ := json.Marshal(out)
	if strings.Contains(string(encoded), "dummy-identity-secret") || !strings.Contains(string(encoded), "…cret") {
		t.Fatalf("identity list must mask secret: %s", encoded)
	}

	// viewer 不能调用拉模型：该端点会用库存身份换 Bearer 并访问给定 base_url，
	// 非管理员调用会把短时凭据暴露给任意端点。
	viewerTok, err := signJWT(s.jwtKey, "viewer")
	if err != nil {
		t.Fatalf("sign viewer jwt: %v", err)
	}
	viewerBody, _ := json.Marshal(map[string]any{
		"provider": "openai", "base_url": relay.URL + "/v1", "auth_mode": "identity", "identity_id": identityID,
	})
	viewerReq := httptest.NewRequest(http.MethodPost, "/api/llm/models", bytes.NewReader(viewerBody))
	viewerReq.Header.Set("Authorization", "Bearer "+viewerTok)
	viewerRecorder := httptest.NewRecorder()
	h.ServeHTTP(viewerRecorder, viewerReq)
	if viewerRecorder.Code != http.StatusForbidden {
		t.Fatalf("viewer list models: status=%d want 403 body=%s", viewerRecorder.Code, viewerRecorder.Body.String())
	}

	// 故意在 identity 模式携带 key，服务端必须在写库前拒绝。
	code, out = do("POST", "/api/llm/profiles", map[string]any{
		"name": profileName + "-bad", "format": "openai", "model": "test-model", "auth_mode": "identity",
		"identity_id": identityID, "api_key": "must-not-be-stored",
	})
	if code != 400 {
		t.Fatalf("identity profile with api key: status=%d want 400 body=%v", code, out)
	}

	// 不传 profile_id：直接测试表单里尚未保存的 identity 配置。
	code, out = do("POST", "/api/llm/test", map[string]any{
		"provider": "openai", "model": "test-model", "base_url": relay.URL + "/v1",
		"auth_mode": "identity", "identity_id": identityID, "streaming": false,
	})
	if code != 200 || out["ok"] != true {
		t.Fatalf("test unsaved identity profile: status=%d body=%v", code, out)
	}
	// 显式 identity 即使误带 api_key 也不能回退成静态认证。
	code, out = do("POST", "/api/llm/models", map[string]any{
		"provider": "openai", "base_url": relay.URL + "/v1", "auth_mode": "identity",
		"identity_id": 0, "api_key": "must-not-be-used",
	})
	if code != 200 || out["ok"] != false || !strings.Contains(out["error"].(string), "KT 身份") {
		t.Fatalf("identity model-list fallback to static key: status=%d body=%v", code, out)
	}
	code, out = do("POST", "/api/llm/models", map[string]any{
		"provider": "openai", "base_url": relay.URL + "/v1", "auth_mode": "identity", "identity_id": identityID,
	})
	if code != 200 || out["ok"] != true {
		t.Fatalf("list models with unsaved identity profile: status=%d body=%v", code, out)
	}

	code, out = do("POST", "/api/llm/profiles", map[string]any{
		"name": profileName, "format": "openai", "model": "test-model", "base_url": relay.URL + "/v1",
		"auth_mode": "identity", "identity_id": identityID, "streaming": false,
	})
	if code != 200 {
		t.Fatalf("save identity profile: status=%d body=%v", code, out)
	}
	profileID := int64(out["id"].(float64))
	profile, err := m.pg.ProfileByID(profileID)
	if err != nil || profile == nil || profile.APIKey != "" || profile.AuthMode != "identity" || profile.IdentityID != identityID {
		t.Fatalf("stored identity profile=%#v err=%v", profile, err)
	}
	// 旧客户端更新时不带 auth_mode/identity_id：必须继承，不得静默切成
	// 没有 Key 的 static profile。
	code, out = do("POST", "/api/llm/profiles", map[string]any{
		"id": profileID, "name": profileName, "format": "openai", "model": "test-model", "base_url": relay.URL + "/v1",
	})
	if code != 200 {
		t.Fatalf("legacy update identity profile: status=%d body=%v", code, out)
	}
	profile, err = m.pg.ProfileByID(profileID)
	if err != nil || profile == nil || profile.AuthMode != "identity" || profile.IdentityID != identityID {
		t.Fatalf("legacy update lost identity auth: %#v err=%v", profile, err)
	}
	code, out = do("DELETE", fmt.Sprintf("/api/llm/identities/%d", identityID), nil)
	if code != 409 {
		t.Fatalf("delete referenced identity: status=%d want 409 body=%v", code, out)
	}
	if n := atomic.LoadInt32(&relayAuthFailures); n != 0 {
		t.Fatalf("relay requests missing identity auth: %d", n)
	}
	if n := atomic.LoadInt32(&tokenHits); n < 2 {
		t.Fatalf("token endpoint hits=%d want at least test + model-list exchanges", n)
	}
}
