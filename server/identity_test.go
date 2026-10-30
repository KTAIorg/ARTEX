package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// newIdentityTestServer 起一个假 KT Identity：
//   - /identity/v1/auth/introspect：Bearer 与 token 一致时按 token 查表返回
//     active/principalKind/accountId，否则 401；
//   - /identity/v1/authz/permissions：按 token 返回角色表。
func newIdentityTestServer(t *testing.T, tokens map[string]string, roles map[string][]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/v1/auth/introspect", func(w http.ResponseWriter, r *http.Request) {
		body, ok := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/identity/v1/authz/permissions", func(w http.ResponseWriter, r *http.Request) {
		rolesForToken, ok := roles[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"roles": rolesForToken})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func postExchange(s *Server, tokenJSON string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/identity/exchange", strings.NewReader(tokenJSON))
	s.identityExchange(w, req)
	return w
}

func TestIdentityExchangeRejectsInactiveToken(t *testing.T) {
	fake := newIdentityTestServer(t,
		map[string]string{"tok-inactive": `{"active":false,"principalKind":"user","accountId":"acc-1"}`},
		nil)
	t.Setenv("IDENTITY_LOGIN_URL", fake.URL)
	t.Setenv("IDENTITY_REQUIRE_ROLE", "")

	w := postExchange(&Server{jwtKey: []byte("unit-test-key")}, `{"token":"tok-inactive"}`)
	if w.Code != 401 {
		t.Fatalf("status=%d want 401; body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &payload)
	if payload.Error != "identity 令牌无效" {
		t.Fatalf("error=%q want identity 令牌无效", payload.Error)
	}
}

func TestIdentityExchangeRejectsServicePrincipal(t *testing.T) {
	fake := newIdentityTestServer(t,
		map[string]string{"tok-service": `{"active":true,"principalKind":"service","accountId":"svc-1"}`},
		nil)
	t.Setenv("IDENTITY_LOGIN_URL", fake.URL)
	t.Setenv("IDENTITY_REQUIRE_ROLE", "")

	w := postExchange(&Server{jwtKey: []byte("unit-test-key")}, `{"token":"tok-service"}`)
	if w.Code != 401 {
		t.Fatalf("status=%d want 401 (principalKind=service 不得换发用户会话); body=%s", w.Code, w.Body.String())
	}
}

func TestIdentityExchangeUnreachableUpstream(t *testing.T) {
	// 先起再关，拿到一个必然 connection refused 的地址。
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	t.Setenv("IDENTITY_LOGIN_URL", deadURL)
	t.Setenv("IDENTITY_REQUIRE_ROLE", "")

	w := postExchange(&Server{jwtKey: []byte("unit-test-key")}, `{"token":"tok-any"}`)
	if w.Code != 502 {
		t.Fatalf("status=%d want 502 (introspect 网络失败 fail-closed); body=%s", w.Code, w.Body.String())
	}
}

func TestIdentityExchangeIssuesArtexJWT(t *testing.T) {
	fake := newIdentityTestServer(t,
		map[string]string{"tok-ok": `{"active":true,"principalKind":"user","accountId":"acc-9","accountNo":"A009","displayName":"张三"}`},
		nil)
	t.Setenv("IDENTITY_LOGIN_URL", fake.URL)
	t.Setenv("IDENTITY_REQUIRE_ROLE", "")

	s := &Server{jwtKey: []byte("unit-test-key")}
	// 带首尾空白验证 trim 后再送 introspect。
	w := postExchange(s, `{"token":" tok-ok "}`)
	if w.Code != 200 {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Token   string            `json:"token"`
		Account map[string]string `json:"account"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析响应: %v; body=%s", err, w.Body.String())
	}
	if payload.Token == "" {
		t.Fatalf("未返回 token: %s", w.Body.String())
	}
	if payload.Account["id"] != "acc-9" || payload.Account["accountNo"] != "A009" || payload.Account["displayName"] != "张三" {
		t.Fatalf("account 透传错误: %v", payload.Account)
	}
	if !verifyJWT(payload.Token, s.jwtKey) {
		t.Fatalf("返回的 token 未通过 verifyJWT")
	}
	parsed, err := jwt.Parse(payload.Token, func(t *jwt.Token) (any, error) { return s.jwtKey, nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("解析返回 token: %v", err)
	}
	if claims, ok := parsed.Claims.(jwt.MapClaims); !ok || claims["sub"] != "ARTEX" {
		t.Fatalf("token subject 应为 ARTEX，得到 %v", parsed.Claims)
	}
}

func TestIdentityExchangeRoleGate(t *testing.T) {
	fake := newIdentityTestServer(t,
		map[string]string{"tok-user": `{"active":true,"principalKind":"user","accountId":"acc-u"}`, "tok-admin": `{"active":true,"principalKind":"user","accountId":"acc-a"}`},
		map[string][]string{"tok-user": {"user"}, "tok-admin": {"user", "admin"}})
	t.Setenv("IDENTITY_LOGIN_URL", fake.URL)
	t.Setenv("IDENTITY_REQUIRE_ROLE", "admin")

	s := &Server{jwtKey: []byte("unit-test-key")}

	w := postExchange(s, `{"token":"tok-user"}`)
	if w.Code != 403 {
		t.Fatalf("roles=[user] status=%d want 403; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "角色不满足") {
		t.Fatalf("错误信息应提示角色不满足: %s", w.Body.String())
	}

	w = postExchange(s, `{"token":"tok-admin"}`)
	if w.Code != 200 {
		t.Fatalf("roles=[user,admin] status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &payload)
	if !verifyJWT(payload.Token, s.jwtKey) {
		t.Fatalf("通过角色门槛后应签发有效 token: %s", w.Body.String())
	}
}

func TestIdentityProxyPassthrough(t *testing.T) {
	var gotPath, gotQuery string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		w.WriteHeader(http.StatusTeapot) // 418：非 2xx 的特殊状态码，验证透传不被吞
		_, _ = w.Write([]byte(`{"echo":true}`))
	}))
	t.Cleanup(fake.Close)
	t.Setenv("IDENTITY_LOGIN_URL", fake.URL+"/") // 末尾斜杠应被归一

	s := &Server{}
	// 走完整 Handler：验证 /identity/ 挂在顶层 mux 且不落进静态页兜底。
	req := httptest.NewRequest("GET", "/identity/v1/echo?q=1", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusTeapot {
		t.Fatalf("status=%d want 418 (上游状态码应原样透传); body=%s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != `{"echo":true}` {
		t.Fatalf("body 透传错误: %s", w.Body.String())
	}
	if gotPath != "/identity/v1/echo" || gotQuery != "q=1" {
		t.Fatalf("path/query 应原样保留: got path=%q query=%q", gotPath, gotQuery)
	}
}
