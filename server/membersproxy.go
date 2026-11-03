package server

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// identity 成员管理透传：前端带 X-Identity-Token 打 /api/admin/members/*，
// 转发到 {IDENTITY_LOGIN_URL}/identity/v1/authz/*（成员清单/授角色/撤角色）。
// 与 vulnproxy 同一套契约：用户的 identity opaque token 原样作为上游 Bearer，
// 权限判定全部在 identity 侧（artex workspace ADMIN 委派或全局 user:manage），
// 本服务不解析令牌、不做任何放行决策。
//
// 路由映射（POST body 原样透传，仅透传必需的 JSON 方法）：
//   GET  /api/admin/members          → GET  /identity/v1/authz/workspace/artex/members
//   POST /api/admin/members/assign   → POST /identity/v1/authz/roles/assign
//   POST /api/admin/members/revoke   → POST /identity/v1/authz/roles/revoke
//
// 安全红线（与 vulnproxy 一致）：identity token 绝不写日志。

const membersProxyMaxBody = 64 << 10 // 授权请求体很小，64KB 足够

func (s *Server) membersProxy(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.Header.Get("X-Identity-Token"))
	if token == "" {
		writeErr(w, http.StatusUnauthorized, "缺少 identity 令牌")
		return
	}
	if r.ContentLength > membersProxyMaxBody {
		writeErr(w, http.StatusRequestEntityTooLarge, "请求体过大")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, membersProxyMaxBody)

	base := identityBaseURL()
	sub, method := "", http.MethodGet
	switch strings.TrimSuffix(r.URL.Path, "/") {
	case "/api/admin/members/assign":
		sub, method = "/identity/v1/authz/roles/assign", http.MethodPost
	case "/api/admin/members/revoke":
		sub, method = "/identity/v1/authz/roles/revoke", http.MethodPost
	default:
		sub, method = "/identity/v1/authz/workspace/artex/members", http.MethodGet
	}

	var body io.Reader
	if method == http.MethodPost {
		body = r.Body
	}
	req, err := http.NewRequestWithContext(r.Context(), method, base.String()+sub, body)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "构造上游请求失败")
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	start := time.Now()
	resp, err := identityMembersHTTPClient.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "identity 不可达")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
	log.Printf("[members-proxy] %s %s -> %d (%s)", method, sub, resp.StatusCode, time.Since(start))
}

var identityMembersHTTPClient = &http.Client{Timeout: 30 * time.Second}
