package server

import (
	"context"
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
//   - /identity/v1/authz/permissions：按 token 返回角色表；
//   - /identity/v1/authz/batch：按 token 返回 artex workspace 三个 check 的
//     allow 序列；token 不在表中时回 500，用于模拟上游故障。
func newIdentityTestServer(t *testing.T, tokens map[string]string, roles map[string][]string, allows map[string][]bool) *httptest.Server {
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
	mux.HandleFunc("/identity/v1/authz/batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Workspace string `json:"workspace"`
			Checks    []struct {
				Resource string `json:"resource"`
				Action   string `json:"action"`
			} `json:"checks"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Workspace != "artex" || len(req.Checks) != 3 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		allow, ok := allows[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		results := make([]map[string]bool, 3)
		for i := range results {
			results[i] = map[string]bool{"allow": i < len(allow) && allow[i]}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
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
		nil, nil)
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
		nil, nil)
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
		nil,
		map[string][]bool{"tok-ok": {true, false, false}})
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
		Roles   []string          `json:"roles"`
		Account map[string]string `json:"account"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析响应: %v; body=%s", err, w.Body.String())
	}
	if payload.Token == "" {
		t.Fatalf("未返回 token: %s", w.Body.String())
	}
	if len(payload.Roles) != 1 || payload.Roles[0] != "admin" {
		t.Fatalf("roles 应为 [admin]，得到 %v; body=%s", payload.Roles, w.Body.String())
	}
	if payload.Account["id"] != "acc-9" || payload.Account["accountNo"] != "A009" || payload.Account["displayName"] != "张三" {
		t.Fatalf("account 透传错误: %v", payload.Account)
	}
	if ok, roles := verifyJWT(payload.Token, s.jwtKey); !ok {
		t.Fatalf("返回的 token 未通过 verifyJWT")
	} else if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("token claims roles 应为 [admin]，得到 %v", roles)
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
		map[string][]string{"tok-user": {"user"}, "tok-admin": {"user", "admin"}},
		map[string][]bool{"tok-admin": {false, true, false}})
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
		Token string   `json:"token"`
		Roles []string `json:"roles"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &payload)
	if ok, _ := verifyJWT(payload.Token, s.jwtKey); !ok {
		t.Fatalf("通过角色门槛后应签发有效 token: %s", w.Body.String())
	}
	if len(payload.Roles) != 1 || payload.Roles[0] != "operator" {
		t.Fatalf("角色门槛通过后仍应按 batch 映射角色，want [operator] got %v; body=%s", payload.Roles, w.Body.String())
	}
}

// TestIdentityExchangeBatchRoleMapping 覆盖 authz/batch 三档按序映射与全 false 拒绝。
func TestIdentityExchangeBatchRoleMapping(t *testing.T) {
	cases := []struct {
		name     string
		allow    []bool
		wantCode int
		wantErr  string // 为空表示期望 200 并签发对应角色
		wantRole string
	}{
		{"settings admin 映射 admin", []bool{true, false, false}, 200, "", "admin"},
		{"assets write 映射 operator", []bool{false, true, false}, 200, "", "operator"},
		{"assets read 映射 viewer", []bool{false, false, true}, 200, "", "viewer"},
		{"多档命中取最高档", []bool{true, true, true}, 200, "", "admin"},
		{"write 与 read 同授取 operator", []bool{false, true, true}, 200, "", "operator"},
		{"全 false 无 ARTEX 访问权", []bool{false, false, false}, 401, "无 ARTEX 访问权限", ""},
		{"结果条数不足缺位视为 false", []bool{false}, 401, "无 ARTEX 访问权限", ""},
		{"空结果视为全 false", nil, 401, "无 ARTEX 访问权限", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newIdentityTestServer(t,
				map[string]string{"tok": `{"active":true,"principalKind":"user","accountId":"acc-m"}`},
				nil,
				map[string][]bool{"tok": tc.allow})
			t.Setenv("IDENTITY_LOGIN_URL", fake.URL)
			t.Setenv("IDENTITY_REQUIRE_ROLE", "")

			s := &Server{jwtKey: []byte("unit-test-key")}
			w := postExchange(s, `{"token":"tok"}`)
			if w.Code != tc.wantCode {
				t.Fatalf("status=%d want %d; body=%s", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantErr != "" {
				if !strings.Contains(w.Body.String(), tc.wantErr) {
					t.Fatalf("错误信息应含 %q: %s", tc.wantErr, w.Body.String())
				}
				return
			}
			var payload struct {
				Token string   `json:"token"`
				Roles []string `json:"roles"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
				t.Fatalf("解析响应: %v; body=%s", err, w.Body.String())
			}
			if len(payload.Roles) != 1 || payload.Roles[0] != tc.wantRole {
				t.Fatalf("roles want [%s] got %v; body=%s", tc.wantRole, payload.Roles, w.Body.String())
			}
			if ok, roles := verifyJWT(payload.Token, s.jwtKey); !ok || len(roles) != 1 || roles[0] != tc.wantRole {
				t.Fatalf("JWT claims roles want [%s] got %v", tc.wantRole, roles)
			}
		})
	}
}

// TestIdentityExchangeBatchUnavailableFailsClosed：introspect 通过但 authz/batch
// 5xx 时必须 fail-closed 502，绝不能回退成默认角色放行。
func TestIdentityExchangeBatchUnavailableFailsClosed(t *testing.T) {
	fake := newIdentityTestServer(t,
		map[string]string{"tok": `{"active":true,"principalKind":"user","accountId":"acc-b"}`},
		nil,
		nil) // allows 为空：batch 对任意 token 回 500
	t.Setenv("IDENTITY_LOGIN_URL", fake.URL)
	t.Setenv("IDENTITY_REQUIRE_ROLE", "")

	w := postExchange(&Server{jwtKey: []byte("unit-test-key")}, `{"token":"tok"}`)
	if w.Code != 502 {
		t.Fatalf("status=%d want 502 (batch 失败 fail-closed); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("batch 失败时不应签发 token: %s", w.Body.String())
	}
}

// TestRequireRole 覆盖角色门本身：无角色/角色不足 403，命中放行。
func TestRequireRole(t *testing.T) {
	s := &Server{}
	admin := s.requireRole("admin")
	h := admin(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })

	r := httptest.NewRequest("PUT", "/api/settings", nil)
	do := func(roles []string) int {
		w := httptest.NewRecorder()
		ctx := r.Context()
		if roles != nil {
			ctx = context.WithValue(ctx, rolesCtxKey{}, roles)
		}
		h(w, r.WithContext(ctx))
		return w.Code
	}

	if code := do(nil); code != 403 {
		t.Fatalf("无角色 want 403 got %d", code)
	}
	if code := do([]string{"viewer"}); code != 403 {
		t.Fatalf("viewer want 403 got %d", code)
	}
	if code := do([]string{"operator", "admin"}); code != 204 {
		t.Fatalf("含 admin want 204 got %d", code)
	}
}

// TestAdminRouteRejectsNonAdminJWT：走完整 Handler 链，viewer 角色的合法 JWT
// 打管理面路由应被 403 挡在 handler 之前（不需要数据库即返回）。
func TestAdminRouteRejectsNonAdminJWT(t *testing.T) {
	s := &Server{jwtKey: []byte("unit-test-key")}
	viewerJWT, err := signJWT(s.jwtKey, "viewer")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("PUT", "/api/settings", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer "+viewerJWT)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("status=%d want 403 (管理面路由拒非 admin); body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "需要管理员权限") {
		t.Fatalf("错误信息应提示需要管理员权限: %s", w.Body.String())
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
