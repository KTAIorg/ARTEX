package server

import (
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// kt-vuln 用户令牌透传代理：前端带 X-Identity-Token 打 /api/vuln/*，这里改写成
// {VULN_PROXY_TARGET}/api/* 并把用户的 identity opaque token 原样作为上游 Bearer
// 转发。vuln 侧是漏洞数据单一事实源：权限按用户判定、审计归因真实用户，ARTEX
// 后端不再以服务身份代替用户访问。路由挂在 /api/ 下，天然落在 requireAuth 之后
// （ARTEX JWT 有效才可能到这里），用户令牌只在前置校验非空，不在本服务解析。
//
// 安全红线：identity token 绝不写日志（与 identity.go 一致），日志只有
// path/status/耗时。

const (
	defaultVulnProxyTarget = "http://kt-vuln-api.kt-vuln.svc:8080" // 集群内直连，普通 http
	vulnProxyMaxBody       = 5 << 20                               // 入向请求体上限 5MB（tags/bulk 最大 5000 条）
)

// vulnProxyTarget 解析 VULN_PROXY_TARGET（默认集群内 kt-vuln-api，归一末尾斜杠）。
// 每次调用读环境变量，与 identityBaseURL 同一套归一逻辑。
func vulnProxyTarget() *url.URL {
	raw := strings.TrimSpace(os.Getenv("VULN_PROXY_TARGET"))
	if raw == "" {
		raw = defaultVulnProxyTarget
	}
	raw = strings.TrimRight(raw, "/")
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		return u
	}
	return &url.URL{Scheme: "http", Host: "kt-vuln-api.kt-vuln.svc:8080"}
}

// vulnProxyTransport 独立连接池：集群内直连无需 TLS 特判，响应头 30s 超时。
var vulnProxyTransport = &http.Transport{
	ResponseHeaderTimeout: 30 * time.Second,
	IdleConnTimeout:       10 * time.Minute,
}

var vulnReverseProxy = &httputil.ReverseProxy{
	// 路径改写 /api/vuln/<rest> → {target}/api/<rest>，query 原样保留。
	Director: func(req *http.Request) {
		base := vulnProxyTarget()
		req.URL.Scheme = base.Scheme
		req.URL.Host = base.Host
		req.Host = base.Host
		req.URL.Path = "/api/" + strings.TrimPrefix(req.URL.Path, "/api/vuln/")
	},
	Transport: vulnProxyTransport,
	// 上游 401 不再一律标记成「identity 过期」：
	// 401 既可能是令牌失效，也可能是「这个账号在目标环境没有权限」。前者该清令牌重登，
	// 后者清了也没用，还会把用户踢出登录页、看不到真正原因。这里只在**上游自己**
	// 明确给出过期信号时才透传该头；其余 401 原样返回，由前端展示上游错误。
	ModifyResponse: func(resp *http.Response) error {
		if resp.StatusCode == http.StatusUnauthorized && resp.Header.Get("X-Identity-Expired") == "" {
			resp.Header.Del("X-Identity-Expired")
		}
		return nil
	},
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		// 入向请求体超限（MaxBytesReader 的错误若从 RoundTrip 穿透到这里）不是
		// "上游不可达"，转成 413；其余网络级失败一律 502 fail-closed。
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			log.Printf("[vulnproxy] %s 拒绝: 请求体超限", r.URL.Path)
			writeErr(w, http.StatusRequestEntityTooLarge, "请求体过大")
			return
		}
		log.Printf("[vulnproxy] %s 反代失败: %v", r.URL.Path, err)
		writeErr(w, http.StatusBadGateway, "vuln 服务不可达")
	},
}

// vulnStatusWriter 记录实际写出的状态码，供访问日志使用。
type vulnStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *vulnStatusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *vulnStatusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// /api/vuln/* — 用户令牌透传代理。方法与请求体原样透传，上游响应（含 401/403）
// 状态码与 body 原样透传。
func (s *Server) vulnProxy(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.Header.Get("X-Identity-Token"))
	if token == "" {
		writeErr(w, http.StatusUnauthorized, "缺少 identity 令牌")
		return
	}
	// 入向请求体上限 5MB：带 Content-Length 的超限请求在这里确定性拒绝（浏览器
	// fetch JSON 必带 Content-Length）；MaxBytesReader 兜住声明长度与实际不符的
	// 病态流。长度未知的 chunked 入向请求会被 ReverseProxy 整体丢 body（Go 既有
	// 行为），不构成绕过。
	if r.ContentLength > vulnProxyMaxBody {
		writeErr(w, http.StatusRequestEntityTooLarge, "请求体过大")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, vulnProxyMaxBody)
	// 用户令牌只换头名不换值：Authorization = Bearer <identity token>，覆盖入向
	// 携带的 ARTEX JWT；X-Identity-Token 不出本服务，cookie 一律不带给上游。
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Del("X-Identity-Token")
	r.Header.Del("Cookie")

	start := time.Now()
	sw := &vulnStatusWriter{ResponseWriter: w, status: http.StatusOK}
	vulnReverseProxy.ServeHTTP(sw, r)
	log.Printf("[vulnproxy] %s %d %s", r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
}
