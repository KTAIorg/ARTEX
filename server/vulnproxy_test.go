package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// vulnUpstreamCapture 记录假 kt-vuln-api 收到的请求要素，供各用例断言。
type vulnUpstreamCapture struct {
	method            string
	path              string
	query             string
	auth              string
	hasIdentityHeader bool
	hasCookie         bool
	body              string
}

// newVulnTestUpstream 起一个假 kt-vuln-api：把收到的请求要素记进 capture，
// 回固定 status/respBody。capture 为 nil 表示用例不关心上游收到什么。
func newVulnTestUpstream(t *testing.T, status int, respBody string, capture *vulnUpstreamCapture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture != nil {
			capture.method = r.Method
			capture.path = r.URL.Path
			capture.query = r.URL.RawQuery
			capture.auth = r.Header.Get("Authorization")
			capture.hasIdentityHeader = r.Header.Get("X-Identity-Token") != ""
			capture.hasCookie = len(r.Header.Values("Cookie")) > 0
			b, _ := io.ReadAll(r.Body)
			capture.body = string(b)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func callVulnProxy(s *Server, method, target, body, identityToken string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	if identityToken != "" {
		req.Header.Set("X-Identity-Token", identityToken)
	}
	s.vulnProxy(w, req)
	return w
}

// TestVulnProxyRequiresIdentityToken：缺 X-Identity-Token（含纯空白）必须 401，
// 不发起上游请求。
func TestVulnProxyRequiresIdentityToken(t *testing.T) {
	s := &Server{}
	for _, tok := range []string{"", "   "} {
		w := callVulnProxy(s, http.MethodGet, "/api/vuln/assets", "", tok)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("token=%q status=%d want 401; body=%s", tok, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "缺少 identity 令牌") {
			t.Fatalf("token=%q 错误信息应提示缺少 identity 令牌: %s", tok, w.Body.String())
		}
	}
}

// TestVulnProxyForwardsIdentityTokenAsBearer：上游 Authorization 必须等于
// X-Identity-Token 的值（Bearer 前缀），X-Identity-Token 与 cookie 不得带给上游；
// 路径改写 /api/vuln/<rest> → /api/<rest>，query 原样保留；响应状态码与 body 透传。
func TestVulnProxyForwardsIdentityTokenAsBearer(t *testing.T) {
	var cap vulnUpstreamCapture
	fake := newVulnTestUpstream(t, 200, `{"ok":true}`, &cap)
	t.Setenv("VULN_PROXY_TARGET", fake.URL+"/") // 末尾斜杠应被归一

	w := callVulnProxy(&Server{}, http.MethodGet, "/api/vuln/assets?type=web&page=2", "", "tok-user-1")
	if w.Code != 200 {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != `{"ok":true}` {
		t.Fatalf("body 透传错误: %s", w.Body.String())
	}
	if cap.auth != "Bearer tok-user-1" {
		t.Fatalf("上游 Authorization=%q want %q", cap.auth, "Bearer tok-user-1")
	}
	if cap.hasIdentityHeader {
		t.Fatalf("X-Identity-Token 不得透传给上游")
	}
	if cap.hasCookie {
		t.Fatalf("cookie 不得透传给上游")
	}
	if cap.path != "/api/assets" {
		t.Fatalf("上游 path=%q want /api/assets", cap.path)
	}
	if cap.query != "type=web&page=2" {
		t.Fatalf("上游 query=%q want type=web&page=2", cap.query)
	}
}

// TestVulnProxyCookieAndArtexJWTNotForwarded：入向携带的 cookie 与 ARTEX JWT
// （Authorization）都必须被 identity 令牌覆盖/剔除。
func TestVulnProxyCookieAndArtexJWTNotForwarded(t *testing.T) {
	var cap vulnUpstreamCapture
	fake := newVulnTestUpstream(t, 200, "{}", &cap)
	t.Setenv("VULN_PROXY_TARGET", fake.URL)

	s := &Server{jwtKey: []byte("unit-test-key")}
	artexJWT, err := signJWT(s.jwtKey, "viewer")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/vuln/assets", nil)
	req.Header.Set("X-Identity-Token", "tok-user-2")
	req.Header.Set("Authorization", "Bearer "+artexJWT) // 浏览器侧原有 ARTEX JWT
	req.Header.Add("Cookie", "sid=stale; other=1")
	s.vulnProxy(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	if cap.auth != "Bearer tok-user-2" {
		t.Fatalf("上游 Authorization=%q want Bearer tok-user-2（覆盖 ARTEX JWT）", cap.auth)
	}
	if cap.hasCookie {
		t.Fatalf("cookie 不得透传给上游")
	}
}

// TestVulnProxyPostBodyPassthrough：方法与请求体原样透传。
func TestVulnProxyPostBodyPassthrough(t *testing.T) {
	var cap vulnUpstreamCapture
	fake := newVulnTestUpstream(t, 201, `{"saved":3}`, &cap)
	t.Setenv("VULN_PROXY_TARGET", fake.URL)

	body := `{"tags":["a","b","c"]}`
	w := callVulnProxy(&Server{}, http.MethodPost, "/api/vuln/tags/bulk", body, "tok-post")
	if w.Code != 201 {
		t.Fatalf("status=%d want 201; body=%s", w.Code, w.Body.String())
	}
	if cap.method != http.MethodPost {
		t.Fatalf("上游 method=%q want POST", cap.method)
	}
	if cap.body != body {
		t.Fatalf("上游 body=%q want %q", cap.body, body)
	}
	if cap.path != "/api/tags/bulk" {
		t.Fatalf("上游 path=%q want /api/tags/bulk", cap.path)
	}
}

// TestVulnProxyUpstream401PassesThrough：上游 401 状态码与 body 原样透传。
//
// 代理不再把「任何 401」都标成 identity 过期：401 既可能是令牌失效，也可能是
// 「这个账号在目标环境没有权限」。以前统一加 X-Identity-Expired 会让前端清空
// 令牌并踢回登录页，用户永远看不到真实原因（issue #61 排障记录）。
func TestVulnProxyUpstream401PassesThrough(t *testing.T) {
	fake := newVulnTestUpstream(t, http.StatusUnauthorized, `{"error":"token expired"}`, nil)
	t.Setenv("VULN_PROXY_TARGET", fake.URL)

	w := callVulnProxy(&Server{}, http.MethodGet, "/api/vuln/assets", "", "tok-expired")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401（上游状态码原样透传）; body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Identity-Expired"); got != "" {
		t.Fatalf("X-Identity-Expired=%q want empty（401 不再自动标记为令牌过期）", got)
	}
	if strings.TrimSpace(w.Body.String()) != `{"error":"token expired"}` {
		t.Fatalf("body 透传错误: %s", w.Body.String())
	}
}

// TestVulnProxyUpstream401KeepsExplicitExpiredHeader：上游自己给了过期信号时，
// 代理必须原样透传，前端据此提示重新登录。
func TestVulnProxyUpstream401KeepsExplicitExpiredHeader(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Identity-Expired", "true")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"token expired"}`))
	}))
	t.Cleanup(fake.Close)
	t.Setenv("VULN_PROXY_TARGET", fake.URL)

	w := callVulnProxy(&Server{}, http.MethodGet, "/api/vuln/assets", "", "tok-expired")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Identity-Expired"); got != "true" {
		t.Fatalf("X-Identity-Expired=%q want true（上游显式标记必须透传）", got)
	}
}

// TestVulnProxyUpstreamUnreachable：上游不可达 → 502 fail-closed。
func TestVulnProxyUpstreamUnreachable(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	t.Setenv("VULN_PROXY_TARGET", deadURL)

	w := callVulnProxy(&Server{}, http.MethodGet, "/api/vuln/assets", "", "tok-any")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "vuln 服务不可达") {
		t.Fatalf("错误信息应提示 vuln 服务不可达: %s", w.Body.String())
	}
}

// TestVulnProxyRejectsOversizedBody：入向请求体上限 5MB，Content-Length 超限
// 直接 413。（长度未知的 chunked 入向请求会被 Go ReverseProxy 整体丢弃 body
// ——issue 16036 的既有行为——不构成绕过：浏览器 fetch JSON 必带 Content-Length。）
func TestVulnProxyRejectsOversizedBody(t *testing.T) {
	fake := newVulnTestUpstream(t, 200, "{}", nil)
	t.Setenv("VULN_PROXY_TARGET", fake.URL)

	for _, delta := range []int64{1, 4096} {
		w := callVulnProxy(&Server{}, http.MethodPost, "/api/vuln/tags/bulk", strings.Repeat("x", vulnProxyMaxBody+int(delta)), "tok-big")
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("超限 %d 字节 status=%d want 413; body=%s", delta, w.Code, w.Body.String())
		}
	}

	// 恰好 5MB 必须放行（上限是含边界值的）。
	w := callVulnProxy(&Server{}, http.MethodPost, "/api/vuln/tags/bulk", strings.Repeat("x", vulnProxyMaxBody), "tok-ok")
	if w.Code != http.StatusOK {
		t.Fatalf("恰好 5MB status=%d want 200; body=%s", w.Code, w.Body.String())
	}
}

// TestVulnProxyBehindJWTAuth：走完整 Handler 链，/api/vuln/* 必须先过 ARTEX JWT
// 鉴权——无 JWT 一律 401，带合法 JWT 才到达代理并按用户令牌透传。
func TestVulnProxyBehindJWTAuth(t *testing.T) {
	var cap vulnUpstreamCapture
	fake := newVulnTestUpstream(t, 200, `{"ok":true}`, &cap)
	t.Setenv("VULN_PROXY_TARGET", fake.URL)

	s := &Server{jwtKey: []byte("unit-test-key")}

	req := httptest.NewRequest(http.MethodGet, "/api/vuln/assets", nil)
	req.Header.Set("X-Identity-Token", "tok-user-9")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "未授权") {
		t.Fatalf("无 ARTEX JWT status=%d want 401; body=%s", w.Code, w.Body.String())
	}

	jwtTok, err := signJWT(s.jwtKey, "viewer")
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/vuln/assets", nil)
	req.Header.Set("Authorization", "Bearer "+jwtTok)
	req.Header.Set("X-Identity-Token", "tok-user-9")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("带合法 JWT status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	if cap.auth != "Bearer tok-user-9" {
		t.Fatalf("上游 Authorization=%q want Bearer tok-user-9", cap.auth)
	}
}
