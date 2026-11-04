package agent

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newTokenServer 起一个假 OAuth2 token 端点，按序返回 tokens 里的值，
// 并统计命中次数。
func newTokenServer(t *testing.T, tokens []string, hits *int32) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	var idx int
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		tok := tokens[idx]
		if idx < len(tokens)-1 {
			idx++
		}
		mu.Unlock()
		atomic.AddInt32(hits, 1)
		_, _ = io.WriteString(w, `{"access_token":"`+tok+`","expires_in":3600,"token_type":"Bearer"}`)
	}))
}

func TestIdentityTokenSourceCachesUntilExpiry(t *testing.T) {
	var hits int32
	srv := newTokenServer(t, []string{"tok-a"}, &hits)
	defer srv.Close()

	src := newIdentityTokenSource(IdentitySource{
		TokenURL: srv.URL, ClientID: "artex", ClientSecret: "s3cr3t", Scope: "newapi.relay",
	}, srv.Client())

	for range 3 {
		tok, err := src.Token()
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
		if tok != "tok-a" {
			t.Fatalf("token=%q want tok-a", tok)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("token endpoint hits=%d want 1 (cached)", n)
	}

	// 过期后重新申请。expires_in 很大也不会真等：直接把过期时间拨到过去。
	src.mu.Lock()
	src.expiresAt = time.Now().Add(-time.Second)
	src.mu.Unlock()
	tok, err := src.Token()
	if err != nil {
		t.Fatalf("Token after expiry: %v", err)
	}
	if tok != "tok-a" {
		t.Fatalf("token=%q", tok)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("token endpoint hits=%d want 2 (refreshed)", n)
	}
}

func TestIdentityTokenSourceRejectsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"bad secret"}`)
	}))
	defer srv.Close()
	src := newIdentityTokenSource(IdentitySource{TokenURL: srv.URL, ClientID: "x", ClientSecret: "y"}, srv.Client())
	if _, err := src.Token(); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("err=%v want invalid_client", err)
	}
}

func TestIdentityTokenSourceDoesNotFollowRedirect(t *testing.T) {
	var redirectedHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&redirectedHits, 1)
		_, _ = io.WriteString(w, `{"access_token":"must-not-be-issued","expires_in":3600}`)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	src := newIdentityTokenSource(IdentitySource{TokenURL: redirect.URL, ClientID: "artex", ClientSecret: "s"}, redirect.Client())
	if _, err := src.Token(); err == nil {
		t.Fatal("redirected token endpoint must fail closed")
	}
	if n := atomic.LoadInt32(&redirectedHits); n != 0 {
		t.Fatalf("redirect target hits=%d want 0 (client_secret must not be replayed)", n)
	}
}

// identityStack 按 NewProviderWithLimiter 的叠层方式组装 transport，
// 保证测试观察到的行为与生产路径一致（identity 在 quotaAware 之上）。
func identityStack(t *testing.T, ident IdentitySource) (http.Client, *httptest.Server, *int32) {
	t.Helper()
	var hits int32
	tokenSrv := newTokenServer(t, []string{"jwt-1"}, &hits)
	ident.TokenURL = tokenSrv.URL
	client, err := quotaAwareHTTPClient("", "")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	fetcher := &http.Client{Transport: client.Transport, Timeout: 20 * time.Second}
	src := newIdentityTokenSource(ident, fetcher)
	client.Transport = identityTransport{base: client.Transport, src: src, managed: ident.ManagedTokenName}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return *client, tokenSrv, &hits
}

func TestIdentityTransportInjectsHeadersAndOverridesPlaceholder(t *testing.T) {
	client, tokenSrv, hits := identityStack(t, IdentitySource{ClientID: "artex", ClientSecret: "s", ManagedTokenName: "artex"})
	defer tokenSrv.Close()

	var gotAuth, gotKey, gotManaged string
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-Api-Key")
		gotManaged = r.Header.Get("X-Kito-Token-Name")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{}")
	}))
	defer relay.Close()

	// 占位 APIKey 模拟 norma 为满足非空校验生成的认证头：必须被覆写，占位值永不出门。
	req, err := http.NewRequest(http.MethodPost, relay.URL, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer identity-mode")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if gotAuth != "Bearer jwt-1" {
		t.Fatalf("Authorization=%q want Bearer jwt-1 (placeholder must not leak)", gotAuth)
	}
	if gotKey != "jwt-1" {
		t.Fatalf("X-Api-Key=%q want jwt-1", gotKey)
	}
	if gotManaged != "artex" {
		t.Fatalf("X-Kito-Token-Name=%q want artex", gotManaged)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Fatalf("token hits=%d want 1", n)
	}
}

func TestIdentityTransportReplaysOnceOn401(t *testing.T) {
	// token 端点第一次发 jwt-old，之后发 jwt-new：模拟身份轮换后旧 token 将死。
	var hits int32
	tokenSrv := newTokenServer(t, []string{"jwt-old", "jwt-new"}, &hits)
	defer tokenSrv.Close()

	var relayBearers []string
	var bodies []string
	var calls int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		relayBearers = append(relayBearers, r.Header.Get("Authorization"))
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid token"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer relay.Close()

	client, err := quotaAwareHTTPClient("", "")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	fetcher := &http.Client{Transport: client.Transport, Timeout: 20 * time.Second}
	src := newIdentityTokenSource(IdentitySource{TokenURL: tokenSrv.URL, ClientID: "artex", ClientSecret: "s"}, fetcher)
	client.Transport = identityTransport{base: client.Transport, src: src, managed: "artex"}

	resp, err := client.Post(relay.URL, "application/json", strings.NewReader(`{"ping":1}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 after replay", resp.StatusCode)
	}
	if len(relayBearers) != 2 || relayBearers[0] != "Bearer jwt-old" || relayBearers[1] != "Bearer jwt-new" {
		t.Fatalf("bearers=%v want [jwt-old jwt-new]", relayBearers)
	}
	// 重放必须带上原始请求体（SSE/JSON 请求 body 已被第一次消费，靠 GetBody 复原）。
	if len(bodies) != 2 || bodies[0] != bodies[1] || bodies[0] != `{"ping":1}` {
		t.Fatalf("bodies=%v want identical original body on replay", bodies)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("token hits=%d want 2", n)
	}
}

func TestIdentityTransportSurfacesReal401(t *testing.T) {
	// token 未变（端点一直发同一枚）→ 401 是真的，原样上抛，绝不无限重试。
	var hits int32
	tokenSrv := newTokenServer(t, []string{"jwt-same"}, &hits)
	defer tokenSrv.Close()

	var calls int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"revoked"}`)
	}))
	defer relay.Close()

	client, err := quotaAwareHTTPClient("", "")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	fetcher := &http.Client{Transport: client.Transport, Timeout: 20 * time.Second}
	src := newIdentityTokenSource(IdentitySource{TokenURL: tokenSrv.URL, ClientID: "artex", ClientSecret: "s"}, fetcher)
	client.Transport = identityTransport{base: client.Transport, src: src, managed: "artex"}

	resp, err := client.Post(relay.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 surfaced", resp.StatusCode)
	}
	// token 未变 → 不做无意义的重放（同一枚 token 再打一次必然还是 401）。
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("relay calls=%d want 1 (no replay when token unchanged)", n)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("token hits=%d want 2 (invalidate forced one refetch)", n)
	}
}

func TestIdentityTokenSourceDoesNotExtendShortTTL(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, `{"access_token":"short-lived","expires_in":30}`)
	}))
	defer srv.Close()
	src := newIdentityTokenSource(IdentitySource{TokenURL: srv.URL, ClientID: "artex", ClientSecret: "s"}, srv.Client())
	for range 2 {
		if _, err := src.Token(); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("token hits=%d want 2; a 30s issuer TTL must not be cached for five minutes", n)
	}
}

func TestIdentityTokenExpiryUsesEarlierJWTExp(t *testing.T) {
	now := time.Now()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"exp": now.Add(10 * time.Minute).Unix()}).SignedString([]byte("test-key"))
	if err != nil {
		t.Fatalf("sign fixture: %v", err)
	}
	got := identityTokenExpiry(token, 3600, now)
	// JWT NumericDate 精度为秒，断言应对齐该协议精度。
	want := time.Unix(now.Add(10*time.Minute).Unix(), 0).Add(-identityRefreshMargin)
	if !got.Equal(want) {
		t.Fatalf("refreshAt=%v want %v (JWT exp earlier than expires_in)", got, want)
	}
	if got := identityTokenExpiry("opaque-token", 0, now); !got.Equal(now) {
		t.Fatalf("missing issuer TTL must disable caching, got %v", got)
	}
}

func TestIdentityTokenSourceInvalidateIfKeepsNewerToken(t *testing.T) {
	src := &identityTokenSource{token: "jwt-new", expiresAt: time.Now().Add(time.Hour)}
	src.InvalidateIf("jwt-old")
	tok, err := src.Token()
	if err != nil || tok != "jwt-new" {
		t.Fatalf("Token=%q err=%v; stale 401 must not invalidate a newer token", tok, err)
	}
	src.InvalidateIf("jwt-new")
	if src.token != "" {
		t.Fatalf("matching token was not invalidated")
	}
}

func TestIdentityTransportDoesNotFollowRelayRedirect(t *testing.T) {
	client, tokenSrv, _ := identityStack(t, IdentitySource{ClientID: "artex", ClientSecret: "s", ManagedTokenName: "artex"})
	defer tokenSrv.Close()

	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	resp, err := client.Post(redirect.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status=%d want 307 returned to caller", resp.StatusCode)
	}
	if n := atomic.LoadInt32(&targetHits); n != 0 {
		t.Fatalf("redirect target hits=%d want 0; bearer must not leave the configured relay", n)
	}
}

func TestConfigEqualComparesIdentityByValue(t *testing.T) {
	a := ConfigFrom("openai", "test-model", "https://ktapi.cc", "", "")
	a.Identity = &IdentitySource{TokenURL: "https://auth.test/token", ClientID: "artex", ClientSecret: "s", Scope: "newapi.relay", ManagedTokenName: "artex"}
	b := a
	b.Identity = &IdentitySource{TokenURL: "https://auth.test/token", ClientID: "artex", ClientSecret: "s", Scope: "newapi.relay", ManagedTokenName: "artex"}
	if !a.Equal(b) {
		t.Fatal("separately loaded identical identity configs must share the active provider/limiter")
	}
	b.Identity.Scope = "other"
	if a.Equal(b) {
		t.Fatal("different identity values must not compare equal")
	}
}

// 身份直连下 APIKey 为空也必须能建 provider（占位值满足 norma 非空校验）。
func TestConfigIdentityBuildsWithoutAPIKey(t *testing.T) {
	cfg := ConfigFrom("openai", "gpt-test", "https://ktapi.cc", "", "")
	cfg.Identity = &IdentitySource{
		TokenURL: "https://auth.example.test/token", ClientID: "artex", ClientSecret: "s", ManagedTokenName: "artex",
	}
	if _, err := cfg.NewProvider(); err != nil {
		t.Fatalf("NewProvider with identity and empty key: %v", err)
	}
}
