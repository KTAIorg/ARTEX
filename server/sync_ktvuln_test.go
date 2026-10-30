package server

// sync_ktvuln_test.go —— kt-vuln 数据源同步的离线测试。
// 上游 API（kt-vuln 与 kt-identity 登录）由 httptest 在本地模拟，不访问
// vuln.ktyun.cc / login.ktyun.cc，也不碰数据库。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// kvResetTokenCache 清空服务账号 token 进程内缓存（缓存跨测试存活，必须逐测试重置）。
func kvResetTokenCache(t *testing.T) {
	t.Helper()
	kvTokenCache.Lock()
	kvTokenCache.token = ""
	kvTokenCache.expiresAt = time.Time{}
	kvTokenCache.Unlock()
}

// kvIdentityLog 记录假 identity 收到的登录请求（字段值与 UA）。
type kvIdentityLog struct {
	mu     sync.Mutex
	users  []string
	passes []string
	uas    []string
}

func (l *kvIdentityLog) record(user, pass, ua string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.users = append(l.users, user)
	l.passes = append(l.passes, pass)
	l.uas = append(l.uas, ua)
	return len(l.users)
}

func (l *kvIdentityLog) snapshot() (users, passes, uas []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.users...), append([]string(nil), l.passes...), append([]string(nil), l.uas...)
}

// kvFakeIdentity 起假 kt-identity：tokenAt 按登录序号发 token，expiresAt 返回
// JSON 值（RFC3339 字符串或 nil→null）；status != 0 时返回错误体。
func kvFakeIdentity(t *testing.T, status int, tokenAt func(n int) string, expiresAt func() any) (*httptest.Server, *kvIdentityLog) {
	t.Helper()
	log := &kvIdentityLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in struct {
			LoginName string `json:"loginName"`
			Username  string `json:"username"`
			Password  string `json:"password"`
		}
		_ = json.Unmarshal(body, &in)
		n := log.record(in.LoginName, in.Password, r.Header.Get("User-Agent"))
		if in.Username != "" {
			t.Errorf("identity 收到 username 字段（契约是 loginName，线上会 400）: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"error":{"code":"invalid_credentials","message":"账号或密码错误"}}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"account": map[string]any{"name": "svc-artex"},
			"token":   tokenAt(n),
			"session": map[string]any{"expiresAt": expiresAt(), "tokenType": "Bearer"},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

// kvVulnLog 记录假 kt-vuln 收到的鉴权头与 UA。
type kvVulnLog struct {
	mu    sync.Mutex
	auths []string
	uas   []string
}

func (l *kvVulnLog) record(auth, ua string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.auths = append(l.auths, auth)
	l.uas = append(l.uas, ua)
}

func (l *kvVulnLog) snapshot() (auths, uas []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.auths...), append([]string(nil), l.uas...)
}

// kvFakeVuln 起假 kt-vuln：记录 Authorization/User-Agent，返回 stats/assets 兼容体。
func kvFakeVuln(t *testing.T) (*httptest.Server, *kvVulnLog) {
	t.Helper()
	log := &kvVulnLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r.Header.Get("Authorization"), r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte(`{"items": [], "total": 0, "assets_total": 7}`))
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

// kvSvcEnv 注入服务账号账密（成对）+ 假登录地址。
func kvSvcEnv(t *testing.T, idenURL string) {
	t.Helper()
	t.Setenv(kvEnvUser, "svc-artex")
	t.Setenv(kvEnvPass, "hunter2-pass")
	t.Setenv(kvEnvLoginURL, idenURL+"/identity/v1/auth/login")
}

// TestKVGet 覆盖 kvGet 的三种形态：正常解析、identity 网关错误体、旧版错误体。
func TestKVGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			http.Error(w, "bad auth header", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/ok":
			_, _ = w.Write([]byte(`{"assets_total": 42}`))
		case "/api/gwerr":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"not_authenticated","message":"缺少或无效的 Bearer token"}}`))
		case "/api/plainerr":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"status":"error","message":"查询失败"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	kv := kvSource{baseURL: srv.URL, token: "tok"}
	ctx := context.Background()

	var out struct {
		AssetsTotal int64 `json:"assets_total"`
	}
	if err := kvGet(ctx, kv, "/api/ok", url.Values{"x": []string{"1"}}, &out); err != nil {
		t.Fatalf("kvGet ok: %v", err)
	}
	if out.AssetsTotal != 42 {
		t.Fatalf("kvGet ok: want 42, got %d", out.AssetsTotal)
	}

	cases := []struct {
		path, wantErr string
	}{
		{"/api/gwerr", "缺少或无效的 Bearer token"},
		{"/api/plainerr", "查询失败"},
	}
	for _, c := range cases {
		err := kvGet(ctx, kv, c.path, nil, nil)
		if err == nil {
			t.Fatalf("kvGet %s: want error", c.path)
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Fatalf("kvGet %s: error %q does not contain %q", c.path, err.Error(), c.wantErr)
		}
	}

	noAuth := kvSource{baseURL: srv.URL}
	if err := kvGet(ctx, noAuth, "/api/ok", nil, nil); err == nil {
		t.Fatal("kvGet without token should fail auth check")
	}
}

// TestKVHelpers 覆盖纯映射函数：technologies、service_name、IPv6 括号、token 掩码。
func TestKVHelpers(t *testing.T) {
	comp, ver, php := "Nginx", "1.25.3", "7.4"
	it := kvAsset{Component: &comp, Version: &ver, PhpVersion: &php}
	got := kvTechnologies(it)
	if len(got) != 2 || got[0] != "Nginx/1.25.3" || got[1] != "php/7.4" {
		t.Fatalf("kvTechnologies: got %v", got)
	}
	if name := kvServiceName(it); name != "nginx" {
		t.Fatalf("kvServiceName: want nginx, got %q", name)
	}

	bare := kvAsset{Port: 8081}
	if techs := kvTechnologies(bare); len(techs) != 0 {
		t.Fatalf("kvTechnologies empty: got %v", techs)
	}
	if name := kvServiceName(bare); name != "unknown" {
		t.Fatalf("kvServiceName: want unknown, got %q", name)
	}
	phpOnly := kvAsset{PhpVersion: &php}
	if name := kvServiceName(phpOnly); name != "php" {
		t.Fatalf("kvServiceName php-only: want php, got %q", name)
	}

	if got := kvBracketIPv6("2001:db8::1"); got != "[2001:db8::1]" {
		t.Fatalf("kvBracketIPv6: got %q", got)
	}
	if got := kvBracketIPv6("1.2.3.4"); got != "1.2.3.4" {
		t.Fatalf("kvBracketIPv6 v4: got %q", got)
	}

	if got := kvTokenHint(""); got != "" {
		t.Fatalf("kvTokenHint empty: got %q", got)
	}
	if got := kvTokenHint("short"); got != "••••" {
		t.Fatalf("kvTokenHint short: got %q", got)
	}
	long := "abcdefghij0123456789"
	if got, want := kvTokenHint(long), "abcdef…6789"; got != want {
		t.Fatalf("kvTokenHint long: want %q, got %q", want, got)
	}
}

// TestKVTokenServiceAccount 服务账号模式全链路：账密登录换票 → kt-vuln 请求带
// 登录换来的 Bearer（忽略静态 token）→ 有效期内复用缓存不重复登录 → 两端 UA。
func TestKVTokenServiceAccount(t *testing.T) {
	kvResetTokenCache(t)
	iden, idenLog := kvFakeIdentity(t, 0,
		func(n int) string { return fmt.Sprintf("tok-%d", n) },
		func() any { return time.Now().Add(time.Hour).Format(time.RFC3339) },
	)
	kvSvcEnv(t, iden.URL)
	vuln, vulnLog := kvFakeVuln(t)

	kv := kvSource{baseURL: vuln.URL, token: "static-tok-ignored"}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := kvGet(ctx, kv, "/api/assets", nil, nil); err != nil {
			t.Fatalf("kvGet #%d: %v", i+1, err)
		}
	}

	users, passes, iuas := idenLog.snapshot()
	if len(users) != 1 {
		t.Fatalf("登录次数: want 1（第二次应命中缓存）, got %d", len(users))
	}
	if users[0] != "svc-artex" || passes[0] != "hunter2-pass" {
		t.Fatalf("登录账密字段: got user=%q pass=%q（契约字段是 loginName/password）", users[0], passes[0])
	}
	if iuas[0] != kvUserAgent {
		t.Fatalf("identity 请求 UA: want %q, got %q", kvUserAgent, iuas[0])
	}

	auths, vuas := vulnLog.snapshot()
	if len(auths) != 2 || auths[0] != "Bearer tok-1" || auths[1] != "Bearer tok-1" {
		t.Fatalf("kt-vuln Authorization: want 两次 Bearer tok-1, got %v", auths)
	}
	for i, ua := range vuas {
		if ua != kvUserAgent {
			t.Fatalf("kt-vuln 请求 #%d UA: want %q, got %q", i+1, kvUserAgent, ua)
		}
	}

	if mode := kv.authMode(); mode != "service_account" {
		t.Fatalf("authMode: want service_account, got %q", mode)
	}
	// 服务账号模式下无需静态 token 也算配齐。
	bare := kvSource{baseURL: vuln.URL}
	if !bare.configured() {
		t.Fatal("configured: 服务账号 env 配齐时应为 true（无静态 token）")
	}
	if mode := bare.authMode(); mode != "service_account" {
		t.Fatalf("authMode(bare): want service_account, got %q", mode)
	}
}

// TestKVTokenRefresh 临期自动刷新：过期/临期(<2min) 的 expiresAt 触发重新登录并
// 换用新 token；expiresAt 为 null 时兜底 30 分钟 TTL，不触发刷新。
func TestKVTokenRefresh(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		kvResetTokenCache(t)
		iden, _ := kvFakeIdentity(t, 0,
			func(n int) string { return fmt.Sprintf("tok-%d", n) },
			func() any { return time.Now().Add(-time.Minute).Format(time.RFC3339) },
		)
		kvSvcEnv(t, iden.URL)
		vuln, vulnLog := kvFakeVuln(t)
		kv := kvSource{baseURL: vuln.URL}
		for i := 0; i < 2; i++ {
			if err := kvGet(context.Background(), kv, "/api/assets", nil, nil); err != nil {
				t.Fatalf("kvGet #%d: %v", i+1, err)
			}
		}
		auths, _ := vulnLog.snapshot()
		if len(auths) != 2 || auths[0] != "Bearer tok-1" || auths[1] != "Bearer tok-2" {
			t.Fatalf("过期 token 应刷新: want [tok-1 tok-2], got %v", auths)
		}
	})
	t.Run("near expiry", func(t *testing.T) {
		kvResetTokenCache(t)
		iden, idenLog := kvFakeIdentity(t, 0,
			func(n int) string { return fmt.Sprintf("tok-%d", n) },
			func() any { return time.Now().Add(30 * time.Second).Format(time.RFC3339) },
		)
		kvSvcEnv(t, iden.URL)
		vuln, vulnLog := kvFakeVuln(t)
		kv := kvSource{baseURL: vuln.URL}
		for i := 0; i < 2; i++ {
			if err := kvGet(context.Background(), kv, "/api/assets", nil, nil); err != nil {
				t.Fatalf("kvGet #%d: %v", i+1, err)
			}
		}
		users, _, _ := idenLog.snapshot()
		if len(users) != 2 {
			t.Fatalf("剩余 <2min 应重新登录: want 2, got %d", len(users))
		}
		auths, _ := vulnLog.snapshot()
		if auths[1] != "Bearer tok-2" {
			t.Fatalf("临期刷新后应带新 token: got %v", auths)
		}
	})
	t.Run("null expiresAt falls back to 30m ttl", func(t *testing.T) {
		kvResetTokenCache(t)
		iden, idenLog := kvFakeIdentity(t, 0,
			func(n int) string { return fmt.Sprintf("tok-%d", n) },
			func() any { return nil }, // session.expiresAt = null
		)
		kvSvcEnv(t, iden.URL)
		vuln, _ := kvFakeVuln(t)
		kv := kvSource{baseURL: vuln.URL}
		for i := 0; i < 2; i++ {
			if err := kvGet(context.Background(), kv, "/api/assets", nil, nil); err != nil {
				t.Fatalf("kvGet #%d: %v", i+1, err)
			}
		}
		users, _, _ := idenLog.snapshot()
		if len(users) != 1 {
			t.Fatalf("兜底 30min TTL 内不应重复登录: want 1, got %d", len(users))
		}
		kvTokenCache.Lock()
		remaining := time.Until(kvTokenCache.expiresAt)
		kvTokenCache.Unlock()
		if remaining < 29*time.Minute || remaining > 31*time.Minute {
			t.Fatalf("兜底 TTL: want ~30min, got %v", remaining)
		}
	})
}

// TestKVTokenEnvIncomplete env 只配一项时回退静态 token；两者皆无则拒绝请求。
func TestKVTokenEnvIncomplete(t *testing.T) {
	kvResetTokenCache(t)
	t.Setenv(kvEnvUser, "svc-artex") // 只配用户名，密码缺失
	// 故意不配 KTVULN_LOGIN_URL：若误走登录路径会打到真实线上，测试必须证明不会。
	vuln, vulnLog := kvFakeVuln(t)

	kv := kvSource{baseURL: vuln.URL, token: "static-tok"}
	if err := kvGet(context.Background(), kv, "/api/assets", nil, nil); err != nil {
		t.Fatalf("env 不完整应回退静态 token: %v", err)
	}
	auths, _ := vulnLog.snapshot()
	if len(auths) != 1 || auths[0] != "Bearer static-tok" {
		t.Fatalf("回退静态 token: want [Bearer static-tok], got %v", auths)
	}
	if mode := kv.authMode(); mode != "env_incomplete" {
		t.Fatalf("authMode: want env_incomplete, got %q", mode)
	}
	if !kv.configured() {
		t.Fatal("configured: env 不完整 + 静态 token 应为 true")
	}

	bare := kvSource{baseURL: vuln.URL} // env 不完整且无静态 token
	if bare.configured() {
		t.Fatal("configured: env 不完整且无静态 token 应为 false")
	}
	if err := kvGet(context.Background(), bare, "/api/assets", nil, nil); err == nil {
		t.Fatal("无任何可用鉴权时 kvGet 应报错")
	}
}

// TestKVTokenLoginFailure 登录失败要带回上下文（HTTP 状态 + 服务端 message）。
func TestKVTokenLoginFailure(t *testing.T) {
	kvResetTokenCache(t)
	iden, _ := kvFakeIdentity(t, 401,
		func(n int) string { return "never" },
		func() any { return nil },
	)
	kvSvcEnv(t, iden.URL)
	vuln, _ := kvFakeVuln(t)
	kv := kvSource{baseURL: vuln.URL}
	err := kvGet(context.Background(), kv, "/api/assets", nil, nil)
	if err == nil {
		t.Fatal("登录 401 时 kvGet 应报错")
	}
	for _, want := range []string{"登录", "401", "账号或密码错误"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("错误缺少上下文 %q: %v", want, err)
		}
	}
}

// TestKVAuthMode 覆盖 auth_mode / configured 在 env×静态 token 各组合下的判定。
func TestKVAuthMode(t *testing.T) {
	cases := []struct {
		name           string
		user, pass     string
		token          string
		wantMode       string
		wantConfigured bool
	}{
		{"service account", "u", "p", "", "service_account", true},
		{"service account ignores static", "u", "p", "st", "service_account", true},
		{"env incomplete user only + static", "u", "", "st", "env_incomplete", true},
		{"env incomplete pass only", "", "p", "", "env_incomplete", false},
		{"static token", "", "", "st", "token", true},
		{"none", "", "", "", "none", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kvResetTokenCache(t)
			if c.user != "" {
				t.Setenv(kvEnvUser, c.user)
			}
			if c.pass != "" {
				t.Setenv(kvEnvPass, c.pass)
			}
			kv := kvSource{baseURL: "https://vuln.example", token: c.token}
			if got := kv.authMode(); got != c.wantMode {
				t.Fatalf("authMode: want %q, got %q", c.wantMode, got)
			}
			if got := kv.configured(); got != c.wantConfigured {
				t.Fatalf("configured: want %v, got %v", c.wantConfigured, got)
			}
		})
	}
	// token_hint 展示：service_account 不泄露凭据，其余模式掩码静态 token。
	if got := kvTokenHintFor("service_account", "abcdefghij0123456789"); got != "service-account (env)" {
		t.Fatalf("tokenHintFor service_account: got %q", got)
	}
	if got, want := kvTokenHintFor("token", "abcdefghij0123456789"), "abcdef…6789"; got != want {
		t.Fatalf("tokenHintFor token: want %q, got %q", want, got)
	}
	if got := kvTokenHintFor("none", ""); got != "" {
		t.Fatalf("tokenHintFor none: got %q", got)
	}
}
