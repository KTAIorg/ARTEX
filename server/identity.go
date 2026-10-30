package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// KT Identity（login.ktyun.cc）Telegram 扫码登录，与存量账密登录完全独立：
// 存量 /api/auth/login 等接口零改动，这里只新增"换发"——用 identity 的 opaque
// token 换 ARTEX 自己的 7 天 JWT，前端拿到后走既有登录后流程。
//
// 安全红线：identity token 绝不写日志，后端日志只打 accountId 与放行/拒绝结论。

const (
	defaultIdentityLoginURL = "https://login.ktyun.cc"
	identityMaxExchangeBody = 8 << 10 // exchange 请求体上限 8KB
	identityMaxUpstreamBody = 1 << 20 // introspect/permissions 响应读取上限
)

// identityBaseURL 解析 IDENTITY_LOGIN_URL（默认 https://login.ktyun.cc，归一末尾斜杠）。
// 每次调用时读取环境变量，代理 Director 与换发端点共用同一份归一逻辑。
func identityBaseURL() *url.URL {
	raw := strings.TrimSpace(os.Getenv("IDENTITY_LOGIN_URL"))
	if raw == "" {
		raw = defaultIdentityLoginURL
	}
	raw = strings.TrimRight(raw, "/")
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		return u
	}
	return &url.URL{Scheme: "https", Host: "login.ktyun.cc"}
}

// identityRequireRole 返回角色门槛；空串表示放行所有有效 identity 用户。
func identityRequireRole() string {
	return strings.TrimSpace(os.Getenv("IDENTITY_REQUIRE_ROLE"))
}

// identityTransport / identityReverseProxy 包级构造一次复用，避免每个请求重建连接池。
var identityTransport = &http.Transport{
	ResponseHeaderTimeout: 10 * time.Second,
	IdleConnTimeout:       60 * time.Second,
}

var identityReverseProxy = &httputil.ReverseProxy{
	// 只改写目标 scheme/host，原样保留 path 与 query：
	// 浏览器同源访问 /identity/v1/... 即等于访问 {IDENTITY_LOGIN_URL}/identity/v1/...，免 CORS。
	Director: func(req *http.Request) {
		base := identityBaseURL()
		req.URL.Scheme = base.Scheme
		req.URL.Host = base.Host
		req.Host = base.Host
	},
	Transport: identityTransport,
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[identity] 反代失败: %v", err)
		writeErr(w, http.StatusBadGateway, "identity 服务不可达")
	},
}

// GET /identity/* — 反代到 KT Identity。挂在顶层 mux（静态路由旁），不在
// requireAuth 的 /api 豁免语义内，但与静态页一样可匿名访问（登录前就要用）。
func (s *Server) identityProxy(w http.ResponseWriter, r *http.Request) {
	identityReverseProxy.ServeHTTP(w, r)
}

// identityHTTPClient 供换发端点调用 introspect / permissions，5s 超时 fail-closed。
var identityHTTPClient = &http.Client{Timeout: 5 * time.Second}

// identityIntrospection 是 introspect 响应的宽松解析：active/principalKind/accountId
// 参与校验，accountNo/displayName 可选、仅透传给前端展示。
type identityIntrospection struct {
	Active        bool   `json:"active"`
	PrincipalKind string `json:"principalKind"`
	AccountID     string `json:"accountId"`
	AccountNo     string `json:"accountNo"`
	DisplayName   string `json:"displayName"`
}

// identityGet 发起带 Bearer 的 GET 并把 JSON 响应解析进 out。返回 HTTP 状态码；
// 网络失败与响应体解析失败都以 err 返回（调用方统一按 502 fail-closed 处理）。
func identityGet(ctx context.Context, rawURL, token string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := identityHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, identityMaxUpstreamBody)).Decode(out); err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

// ARTEX 本地角色映射：一次 authz/batch 探测 artex workspace 的三个资源动作，
// 按序对应 admin/operator/viewer。与 vuln 权限（kt_vuln:* 资源）完全隔离。
var identityBatchChecks = []struct{ resource, action string }{
	{"artex:settings", "admin"},
	{"artex:assets", "write"},
	{"artex:assets", "read"},
}

// identityResolveRoles 调 POST /identity/v1/authz/batch（workspace=artex，Bearer 同
// introspect 用的 opaque token），把 identity 授权映射成 ARTEX 本地角色：
// allow[0]→admin、allow[1]→operator、allow[2]→viewer，取首个命中的档位。
// 全 false 返回空切片（调用方按无权限拒绝）；网络失败、非 2xx、响应体解析失败
// 都以 err 返回（调用方按 502 fail-closed）。结果条数不足时缺位视为 false。
func identityResolveRoles(ctx context.Context, baseURL, token string) ([]string, error) {
	checks := make([]map[string]string, 0, len(identityBatchChecks))
	for _, c := range identityBatchChecks {
		checks = append(checks, map[string]string{"resource": c.resource, "action": c.action})
	}
	payload, err := json.Marshal(map[string]any{"workspace": "artex", "checks": checks})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/identity/v1/authz/batch", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := identityHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("authz/batch status=%d", resp.StatusCode)
	}
	var out struct {
		Results []struct {
			Allow bool `json:"allow"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, identityMaxUpstreamBody)).Decode(&out); err != nil {
		return nil, err
	}
	allowed := func(i int) bool { return i < len(out.Results) && out.Results[i].Allow }
	switch {
	case allowed(0):
		return []string{"admin"}, nil
	case allowed(1):
		return []string{"operator"}, nil
	case allowed(2):
		return []string{"viewer"}, nil
	}
	return nil, nil
}

// POST /api/auth/identity/exchange — body {"token":"<identity opaque token>"}。
// 校验通过则签发 ARTEX 自己的 7 天 JWT（subject 固定 "ARTEX"，与账密登录同一把
// jwtKey），前端走既有登录后流程。
func (s *Server) identityExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "方法不允许")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, identityMaxExchangeBody+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不可读")
		return
	}
	if len(body) > identityMaxExchangeBody {
		writeErr(w, http.StatusRequestEntityTooLarge, "请求体过大")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		writeErr(w, http.StatusBadRequest, "token 不能为空")
		return
	}

	base := identityBaseURL().String()
	var intro identityIntrospection
	status, err := identityGet(r.Context(), base+"/identity/v1/auth/introspect", token, &intro)
	// 网络错误、5xx、响应体解析失败都按 identity 侧不可用处理，fail-closed。
	if err != nil || status >= 500 {
		log.Printf("[identity] exchange 拒绝: introspect 失败 (status=%d)", status)
		writeErr(w, http.StatusBadGateway, "identity 服务不可达")
		return
	}
	if status < 200 || status >= 300 || !intro.Active || intro.PrincipalKind != "user" || intro.AccountID == "" {
		log.Printf("[identity] exchange 拒绝: accountId=%q active=%v principalKind=%q", intro.AccountID, intro.Active, intro.PrincipalKind)
		writeErr(w, http.StatusUnauthorized, "identity 令牌无效")
		return
	}

	// 可选角色门槛：IDENTITY_REQUIRE_ROLE 非空时要求 permissions.roles 包含该值。
	if want := identityRequireRole(); want != "" {
		var perm struct {
			Roles []string `json:"roles"`
		}
		status, err := identityGet(r.Context(), base+"/identity/v1/authz/permissions", token, &perm)
		if err != nil || status >= 500 {
			log.Printf("[identity] exchange 拒绝: accountId=%q permissions 失败 (status=%d)", intro.AccountID, status)
			writeErr(w, http.StatusBadGateway, "identity 服务不可达")
			return
		}
		hasRole := false
		for _, role := range perm.Roles {
			if role == want {
				hasRole = true
				break
			}
		}
		if status < 200 || status >= 300 || !hasRole {
			log.Printf("[identity] exchange 拒绝: accountId=%q 缺少角色 %q", intro.AccountID, want)
			writeErr(w, http.StatusForbidden, "角色不满足")
			return
		}
	}

	// ARTEX 本地角色映射：identity artex workspace 授权 → admin/operator/viewer。
	// batch 失败（网络/非 2xx/解析失败）fail-closed 502；全 false 视为无 ARTEX 访问权。
	roles, err := identityResolveRoles(r.Context(), base, token)
	if err != nil {
		log.Printf("[identity] exchange 拒绝: accountId=%q authz/batch 失败: %v", intro.AccountID, err)
		writeErr(w, http.StatusBadGateway, "identity 服务不可达")
		return
	}
	if len(roles) == 0 {
		log.Printf("[identity] exchange 拒绝: accountId=%q 无 ARTEX 访问权限", intro.AccountID)
		writeErr(w, http.StatusUnauthorized, "无 ARTEX 访问权限")
		return
	}

	tok, err := signJWT(s.jwtKey, roles...)
	if err != nil {
		log.Printf("[identity] exchange 拒绝: accountId=%q 签发失败", intro.AccountID)
		writeErr(w, http.StatusInternalServerError, "token 生成失败")
		return
	}
	log.Printf("[identity] exchange 放行: accountId=%q roles=%v", intro.AccountID, roles)
	writeJSON(w, http.StatusOK, map[string]any{
		"token": tok,
		"roles": roles,
		"account": map[string]string{
			"id":          intro.AccountID,
			"accountNo":   intro.AccountNo,
			"displayName": intro.DisplayName,
		},
	})
}
