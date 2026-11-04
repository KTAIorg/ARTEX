package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Kito 统一 AI 钱包（kt-k8s#194）：ARTEX 后端作为用户令牌透传层访问 ktapi.cc
// （NewAPI IAM）。与 vulnproxy 同一套纪律：前端带 X-Identity-Token 打
// /api/wallet/*，ARTEX JWT 由 requireAuth 把关（普通登录用户即可，不加 admin
// 门）；用户 identity opaque token 原样作上游 Bearer。
//
// 上游契约（对齐 deepseek-harness apps/desktop/src/kito-identity.ts）：
//   - POST /api/iam/ensure           Bearer identity → data.user{id, quota, ...}，
//     并 Set-Cookie 会话；quota 单位 500000/USD。
//   - GET  /api/user/models          需 ensure 的 cookie + New-Api-User 头。
//   - GET  /ktai/wallet/deposit-address?chain=&asset=  Bearer identity。
//
// 安全红线（与 identity.go / vulnproxy.go 一致）：identity token 绝不写日志；
// 充值地址只在用户主动打开充值时才向上游取（登录不造地址），日志也不打完整地址。

const (
	defaultKtapiBase        = "https://ktapi.cc"
	kitowalletMaxUpstream   = 1 << 20 // 上游响应体读取上限 1MB
	kitowalletQuotaPerUSD   = 500_000
	kitowalletUserAgent     = "artex-kitowallet/1.0" // CF 拦默认 Go UA，必须显式带
)

// ktapiBaseURL 解析 KTAPI_BASE（默认 https://ktapi.cc，归一末尾斜杠）。
func ktapiBaseURL() *url.URL {
	raw := strings.TrimSpace(os.Getenv("KTAPI_BASE"))
	if raw == "" {
		raw = defaultKtapiBase
	}
	raw = strings.TrimRight(raw, "/")
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		return u
	}
	return &url.URL{Scheme: "https", Host: "ktapi.cc"}
}

// kitowalletTransport 独立连接池：ktapi.cc 走 CF，强制 HTTP/1.1 消灭 h2 头超时
// （同 identityTransport 的经验），响应头 30s 超时、空闲保热 10m。
var kitowalletTransport = &http.Transport{
	ResponseHeaderTimeout: 30 * time.Second,
	IdleConnTimeout:       10 * time.Minute,
	TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
}

var kitowalletHTTPClient = &http.Client{
	Timeout:   30 * time.Second,
	Transport: kitowalletTransport,
}

// kitowalletIdentityToken 取入向 X-Identity-Token（与 vulnproxy 同一头名），
// 缺失即 401，调用方直接 return。
func kitowalletIdentityToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := strings.TrimSpace(r.Header.Get("X-Identity-Token"))
	if token == "" {
		writeErr(w, http.StatusUnauthorized, "缺少 identity 令牌，请重新通过 KT Identity 登录")
		return "", false
	}
	return token, true
}

// kitowalletRequest 构造上游请求：UA 必须显式设置（CF 拦 Go 默认 UA），
// Authorization 只放 identity token，绝不携带入向 cookie。
func kitowalletRequest(ctx context.Context, method, rawURL, identityToken string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", kitowalletUserAgent)
	req.Header.Set("Authorization", "Bearer "+identityToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// kitowalletUpstreamErr 把上游非 2xx 转成可读错误：优先取 NewAPI 风格的
// message 字段，5xx/网络失败统一 502 fail-closed，4xx 原状态码透传。
func kitowalletUpstreamErr(w http.ResponseWriter, where string, status int, bodyBytes []byte, err error) {
	if err != nil {
		log.Printf("[kitowallet] %s 上游不可达: %v", where, err)
		writeErr(w, http.StatusBadGateway, "ktapi 服务不可达")
		return
	}
	var payload struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(bodyBytes, &payload)
	msg := strings.TrimSpace(payload.Message)
	if msg == "" {
		msg = fmt.Sprintf("ktapi %s 失败（%d）", where, status)
	}
	if status >= 500 {
		log.Printf("[kitowallet] %s 上游 %d", where, status)
		writeErr(w, http.StatusBadGateway, msg)
		return
	}
	writeErr(w, status, msg)
}

// kitowalletDo 执行请求并读回（上限 1MB）状态码与响应体。
func kitowalletDo(req *http.Request) (int, []byte, error) {
	resp, err := kitowalletHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, kitowalletMaxUpstream))
	return resp.StatusCode, body, err
}

// kitowalletEnsure 调 POST /api/iam/ensure，返回响应体、会话 cookie 与
// NewAPI user id（后续 /api/user/models 需要 cookie + New-Api-User 头）。
func kitowalletEnsure(ctx context.Context, identityToken string) (body []byte, cookie, userID string, status int, err error) {
	base := ktapiBaseURL().String()
	req, err := kitowalletRequest(ctx, http.MethodPost, base+"/api/iam/ensure", identityToken, strings.NewReader("{}"))
	if err != nil {
		return nil, "", "", 0, err
	}
	resp, err := kitowalletHTTPClient.Do(req)
	if err != nil {
		return nil, "", "", 0, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, kitowalletMaxUpstream))
	if err != nil {
		return body, "", "", resp.StatusCode, err
	}
	cookie = resp.Header.Get("Set-Cookie")
	var payload struct {
		Data struct {
			ID   any `json:"id"`
			User struct {
				ID any `json:"id"`
			} `json:"user"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &payload)
	id := payload.Data.ID
	if id == nil {
		id = payload.Data.User.ID
	}
	if id != nil {
		userID = fmt.Sprintf("%v", id)
	}
	return body, cookie, userID, resp.StatusCode, nil
}

// POST /api/wallet/ensure — 透传 identity token 调 ktapi /api/iam/ensure，
// 返回账号 + 余额摘要（quota/500000 折 USD，两位小数）。
// 注意：每次成功 ensure 占用一个 NewAPI 网站会话名额（上限 50），前端仅在
// 用户进入钱包页时调用一次，充值地址接口不重复 ensure。
func (s *Server) walletEnsure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "方法不允许")
		return
	}
	identityToken, ok := kitowalletIdentityToken(w, r)
	if !ok {
		return
	}
	body, _, _, status, err := kitowalletEnsure(r.Context(), identityToken)
	if err != nil || status < 200 || status >= 300 {
		kitowalletUpstreamErr(w, "ensure", status, body, err)
		return
	}
	var payload struct {
		Data struct {
			ID          int    `json:"id"`
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			Quota       *int64 `json:"quota"`
			User        struct {
				ID          int    `json:"id"`
				Username    string `json:"username"`
				DisplayName string `json:"display_name"`
				Quota       *int64 `json:"quota"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("[kitowallet] ensure 响应解析失败: %v", err)
		writeErr(w, http.StatusBadGateway, "ktapi ensure 响应格式异常")
		return
	}
	// ensure 的用户信息可能平铺在 data 或嵌在 data.user，两处都认。
	acc := struct {
		ID          int    `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Quota       *int64 `json:"quota"`
	}{payload.Data.ID, payload.Data.Username, payload.Data.DisplayName, payload.Data.Quota}
	if acc.ID == 0 && payload.Data.User.ID != 0 {
		acc = struct {
			ID          int    `json:"id"`
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			Quota       *int64 `json:"quota"`
		}{payload.Data.User.ID, payload.Data.User.Username, payload.Data.User.DisplayName, payload.Data.User.Quota}
	}
	out := map[string]any{"account": map[string]any{
		"id": acc.ID, "username": acc.Username, "displayName": acc.DisplayName,
	}}
	if acc.Quota != nil {
		out["balance"] = float64(*acc.Quota) / kitowalletQuotaPerUSD
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/wallet/models — 先 ensure 拿会话（cookie + New-Api-User），再调
// ktapi /api/user/models 返回当前用户可用模型列表，data 数组原样透传。
func (s *Server) walletModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "方法不允许")
		return
	}
	identityToken, ok := kitowalletIdentityToken(w, r)
	if !ok {
		return
	}
	_, cookie, userID, status, err := kitowalletEnsure(r.Context(), identityToken)
	if err != nil || status < 200 || status >= 300 {
		kitowalletUpstreamErr(w, "ensure", status, nil, err)
		return
	}
	if cookie == "" || userID == "" {
		log.Printf("[kitowallet] models 拒绝: ensure 未返回会话")
		writeErr(w, http.StatusBadGateway, "ktapi ensure 未返回会话")
		return
	}
	base := ktapiBaseURL().String()
	req, err := kitowalletRequest(r.Context(), http.MethodGet, base+"/api/user/models", identityToken, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "请求构造失败")
		return
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("New-Api-User", userID)
	mstatus, body, err := kitowalletDo(req)
	if err != nil || mstatus < 200 || mstatus >= 300 {
		kitowalletUpstreamErr(w, "models", mstatus, body, err)
		return
	}
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("[kitowallet] models 响应解析失败: %v", err)
		writeErr(w, http.StatusBadGateway, "ktapi models 响应格式异常")
		return
	}
	if payload.Data == nil {
		payload.Data = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": payload.Data})
}

// GET /api/wallet/deposit-address?chain=&asset= — 透传链/资产参数调 ktapi
// 充值地址接口（Bearer identity）。只在用户打开充值弹窗时调用（登录不造地址）。
// chain 只认 tron / ethereum；asset 只认 usdt / usdc。地址校验：tron 必须 T 开头，
// ethereum 必须 0x 开头且 42 位——链名对不上就不返回，避免把 TRON 地址画成
// ERC20 二维码。日志绝不打完整地址。
func (s *Server) walletDepositAddress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "方法不允许")
		return
	}
	identityToken, ok := kitowalletIdentityToken(w, r)
	if !ok {
		return
	}
	chain := strings.TrimSpace(r.URL.Query().Get("chain"))
	asset := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("asset")))
	switch {
	case chain == "tron":
		if asset == "" {
			asset = "usdt"
		}
		if asset != "usdt" {
			writeErr(w, http.StatusBadRequest, "TRC20 只支持 USDT")
			return
		}
	case chain == "ethereum":
		if asset == "" {
			asset = "usdt"
		}
		if asset != "usdt" && asset != "usdc" {
			writeErr(w, http.StatusBadRequest, "ERC20 只支持 USDT / USDC")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "chain 仅支持 tron / ethereum")
		return
	}
	base := ktapiBaseURL().String()
	target := base + "/ktai/wallet/deposit-address?chain=" + url.QueryEscape(chain) + "&asset=" + url.QueryEscape(asset)
	req, err := kitowalletRequest(r.Context(), http.MethodGet, target, identityToken, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "请求构造失败")
		return
	}
	status, body, err := kitowalletDo(req)
	if err != nil || status < 200 || status >= 300 {
		kitowalletUpstreamErr(w, "deposit-address", status, body, err)
		return
	}
	var payload struct {
		Data struct {
			Address string `json:"address"`
		} `json:"data"`
		Address string `json:"address"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("[kitowallet] deposit-address 响应解析失败: %v", err)
		writeErr(w, http.StatusBadGateway, "ktapi 充值地址响应格式异常")
		return
	}
	address := strings.TrimSpace(payload.Data.Address)
	if address == "" {
		address = strings.TrimSpace(payload.Address)
	}
	valid := (chain == "tron" && strings.HasPrefix(address, "T")) ||
		(chain == "ethereum" && len(address) == 42 && strings.HasPrefix(address, "0x"))
	if !valid {
		log.Printf("[kitowallet] deposit-address 拒绝: chain=%s 地址形态不符", chain)
		writeErr(w, http.StatusBadGateway, "充值地址与所选网络不符，请重试")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"chain": chain, "asset": asset, "address": address})
}
