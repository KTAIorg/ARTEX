package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// 资产同步（kt-vuln 数据源）。
//
// kt-vuln 是 KT 自家漏洞情报站（https://vuln.ktyun.cc），资产模型是 ip:port +
// 组件/版本 + 判定(verdict)/价值分(score)/分层(tier)。与 ScopeSentry 同步走 MCP
// 不同，它是纯 REST：kt-identity Bearer token + GET /api/assets 按 limit/offset
// 分页（limit 上限 1000），响应为 {items:[...], total}。
//
// 鉴权两级（生产走第一级）：优先服务账号——部署侧经 KTSecret → k8s Secret 注入
// KTVULN_SVC_USERNAME + KTVULN_SVC_PASSWORD（一对，只配一个算配置不完整），运行时
// 用账密调 kt-identity 登录接口（KTVULN_LOGIN_URL，默认
// https://login.ktyun.cc/identity/v1/auth/login，请求体字段是 loginName）换 Bearer，
// 进程内缓存、剩余有效期 <2 分钟自动重新登录，session.expiresAt 按 RFC3339 解析、
// 解析失败或为零值兜底 30 分钟 TTL；env 未配齐时回退 settings KV 里的静态 token
// （sync.ktvuln.token，UI 手工粘贴，会过期，仅作兜底）。登录与数据请求统一 UA
// artex-sync/1.0（CF 边缘按 UA 拦截默认 Go client）。
//
// 配置不占 mcp_servers 表（kt-vuln 不是 MCP 服务，混进去会污染 agent 的 MCP
// 工具列表和自动发现），放 settings KV：sync.ktvuln.url / .token / .enabled。
//
// 映射（kt-vuln → ARTEX 资产模型）：
//   - scheme=http/https → UpsertHTTPService（URL host 优先取第一个 hostname，
//     没有就用 IP；组件/版本/PHP 进 technologies；title 进 page_title。
//     级联生成 root_domain/subdomain/ip 资产，ip 资产由 store 内部落库，不单独计数）
//   - 无 scheme → UpsertOtherService（ip:port，组件名作 service_name）
//   - 其余 hostname → UpsertSubdomain
//   - 协同维度（score/tier(写入时按 manual_tier 合并)/biz_type/engagement_status/
//     verdict/engagement_owner/country/rating_note）写入服务资产 extra.ktvuln
//     子树（subdomain/ip 资产不带）；同步默认按业务类型聚合成公司
//     「ktvuln:<业务类型>」并落 scope（IP+非 IP hostname）

const (
	kvSettingURL     = "sync.ktvuln.url"
	kvSettingToken   = "sync.ktvuln.token"
	kvSettingEnabled = "sync.ktvuln.enabled"
	kvDefaultBaseURL = "https://vuln.ktyun.cc"
	kvPageLimit      = 1000 // kt-vuln /api/assets 的 limit 服务端上限
	kvDefaultMax     = 5000 // 单次同步入库保护上限
	kvMaxErrs        = 100  // 响应里最多带回的错误条数，其余只计数
	kvRatingNoteMax  = 500  // rating_note 落库时按字符截断的上限

	// 服务账号鉴权（部署侧 KTSecret → k8s Secret 注入，优先于静态 token）。
	kvEnvUser          = "KTVULN_SVC_USERNAME"
	kvEnvPass          = "KTVULN_SVC_PASSWORD"
	kvEnvLoginURL      = "KTVULN_LOGIN_URL"
	kvDefaultLoginURL  = "https://login.ktyun.cc/identity/v1/auth/login"
	kvUserAgent        = "artex-sync/1.0"
	kvTokenTTLFallback = 30 * time.Minute // expiresAt 缺失/无法解析时的兜底 TTL
	kvTokenRenewSkew   = 2 * time.Minute  // 剩余有效期低于该值即重新登录
)

// kvSource 是一份已解析的 kt-vuln 数据源配置。
type kvSource struct {
	baseURL string
	token   string
	enabled bool
}

// kvSvcCreds 读取服务账号环境变量（KTVULN_SVC_USERNAME/KTVULN_SVC_PASSWORD）。
func kvSvcCreds() (user, pass string) {
	return strings.TrimSpace(os.Getenv(kvEnvUser)), strings.TrimSpace(os.Getenv(kvEnvPass))
}

// kvSvcCredsSet 报告服务账号 env 是否配齐（只配一个算配置不完整，不算配齐）。
func kvSvcCredsSet() bool {
	user, pass := kvSvcCreds()
	return user != "" && pass != ""
}

// configured 报告 url + 任一鉴权路径是否配齐（能否真正发起请求）：
// 服务账号 env 配齐，或 settings KV 里有静态 token。
func (kv kvSource) configured() bool {
	return kv.baseURL != "" && (kv.token != "" || kvSvcCredsSet())
}

// authMode 报告当前生效/异常的鉴权方式（status 端点透出，供部署排障）：
//   - service_account：env 账密齐，登录换 token，忽略静态 token；
//   - env_incomplete：env 只配了一个变量（若有静态 token 仍按 token 模式工作，
//     status 端点会另附 env_warning 提示补齐）；
//   - token：静态 token（settings KV）；
//   - none：没有任何可用鉴权。
func (kv kvSource) authMode() string {
	user, pass := kvSvcCreds()
	switch {
	case user != "" && pass != "":
		return "service_account"
	case user != "" || pass != "":
		return "env_incomplete"
	case kv.token != "":
		return "token"
	default:
		return "none"
	}
}

// kvTokenCache 是服务账号模式的进程内 Bearer 缓存（互斥锁保护，
// 登录请求在锁内进行，天然避免并发刷新风暴）。
var kvTokenCache struct {
	sync.Mutex
	token     string
	expiresAt time.Time
}

// kvToken 返回当前应使用的 Bearer token：env 账密齐 → 有效期内（剩余 >2 分钟）
// 直接返回缓存 token，否则重新登录换取并更新缓存；env 未配齐 → 回退 kvSource
// 里的静态 token（可能为空串，由调用方决定是否放行请求）。
func kvToken(ctx context.Context, kv kvSource) (string, error) {
	user, pass := kvSvcCreds()
	if user == "" || pass == "" {
		return kv.token, nil
	}
	kvTokenCache.Lock()
	defer kvTokenCache.Unlock()
	if kvTokenCache.token != "" && time.Until(kvTokenCache.expiresAt) > kvTokenRenewSkew {
		return kvTokenCache.token, nil
	}
	token, expiresAt, err := kvLogin(ctx, user, pass)
	if err != nil {
		return "", fmt.Errorf("服务账号登录失败(KTVULN_SVC_USERNAME=%s): %w", user, err)
	}
	kvTokenCache.token = token
	kvTokenCache.expiresAt = expiresAt
	return token, nil
}

// kvLogin 用服务账号账密调 kt-identity 登录接口换 Bearer。
// 契约（线上实测）：POST {"loginName":..,"password":..}（字段名是 loginName，
// 不是 username），200 响应 {"token":..,"session":{"expiresAt":..,"tokenType":"Bearer"}}；
// expiresAt 按 RFC3339 字符串解析，缺失/无法解析/零值时兜底 30 分钟 TTL。
func kvLogin(ctx context.Context, user, pass string) (string, time.Time, error) {
	loginURL := strings.TrimSpace(os.Getenv(kvEnvLoginURL))
	if loginURL == "" {
		loginURL = kvDefaultLoginURL
	}
	payload, err := json.Marshal(map[string]string{"loginName": user, "password": pass})
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(payload))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", kvUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", time.Time{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
			Message string `json:"message"`
		}
		msg := resp.Status
		if json.Unmarshal(body, &e) == nil {
			if e.Error.Message != "" {
				msg = e.Error.Message
			} else if e.Message != "" {
				msg = e.Message
			}
		}
		return "", time.Time{}, fmt.Errorf("identity 登录接口 %s: HTTP %d: %s", loginURL, resp.StatusCode, msg)
	}
	var out struct {
		Token   string `json:"token"`
		Session struct {
			ExpiresAt string `json:"expiresAt"`
		} `json:"session"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("identity 登录响应解析失败: %w", err)
	}
	if out.Token == "" {
		return "", time.Time{}, fmt.Errorf("identity 登录响应缺少 token（HTTP %d）", resp.StatusCode)
	}
	expiresAt := time.Time{}
	if t := strings.TrimSpace(out.Session.ExpiresAt); t != "" {
		if parsed, err := time.Parse(time.RFC3339, t); err == nil && !parsed.IsZero() {
			expiresAt = parsed
		}
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(kvTokenTTLFallback)
	}
	return out.Token, expiresAt, nil
}

// kvLoad 从 settings KV 读取配置，url 未配置时回落到官方默认入口。
func (s *Server) kvLoad(pg *db.DB) kvSource {
	kv := kvSource{baseURL: kvDefaultBaseURL}
	if v, ok, _ := pg.GetSetting(kvSettingURL); ok {
		if t := strings.TrimRight(strings.TrimSpace(v), "/"); t != "" {
			kv.baseURL = t
		}
	}
	if v, ok, _ := pg.GetSetting(kvSettingToken); ok {
		kv.token = strings.TrimSpace(v)
	}
	kv.enabled = pg.GetBool(kvSettingEnabled, false)
	return kv
}

// kvGet 调用 kt-vuln REST API 并把 JSON 解到 out（out 为 nil 时只探活）。
// Bearer 经 kvToken 动态获取（服务账号登录换票优先，静态 token 兜底），UA 统一
// artex-sync/1.0。非 2xx 时把服务端错误 message 带回来，两种错误包体都兼容：
// {"error":{"code":..,"message":..}}（identity 网关）和 {"status":"error","message":..}。
func kvGet(ctx context.Context, kv kvSource, path string, query url.Values, out any) error {
	u := kv.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	token, err := kvToken(ctx, kv)
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("kt-vuln %s: 未配置鉴权（服务账号 env 未配齐且无静态 token）", path)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", kvUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
			Message string `json:"message"`
		}
		msg := resp.Status
		if json.Unmarshal(body, &e) == nil {
			if e.Error.Message != "" {
				msg = e.Error.Message
			} else if e.Message != "" {
				msg = e.Message
			}
		}
		return fmt.Errorf("kt-vuln %s: HTTP %d: %s", path, resp.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("kt-vuln %s 响应解析失败: %w", path, err)
	}
	return nil
}

// kvTokenHint 掩码显示 token（不回明文，与 LLM profile 的 api_key_hint 同一姿势）。
func kvTokenHint(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 12 {
		return "••••"
	}
	return token[:6] + "…" + token[len(token)-4:]
}

// kvTokenHintFor 按鉴权方式返回 token_hint 展示值（不泄露任何凭据）。
func kvTokenHintFor(mode, staticToken string) string {
	if mode == "service_account" {
		return "service-account (env)"
	}
	return kvTokenHint(staticToken)
}

// ---------- GET /api/sync/ktvuln/status ----------

func (s *Server) syncKVStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	kv := s.kvLoad(pg)
	mode := kv.authMode()
	resp := map[string]any{
		"configured":  kv.configured(),
		"enabled":     kv.enabled && kv.configured(),
		"url":         kv.baseURL,
		"auth_mode":   mode, // service_account | token | env_incomplete | none
		"token_hint":  kvTokenHintFor(mode, kv.token),
		"reachable":   false,
		"stats":       nil,
		"stats_error": "",
		"env_warning": "",
	}
	if mode == "env_incomplete" {
		warn := "服务账号环境变量只配置了一项（KTVULN_SVC_USERNAME / KTVULN_SVC_PASSWORD 需成对注入）"
		if kv.token != "" {
			warn += "，当前回退静态 token 工作"
		} else {
			warn += "，且无静态 token，数据源不可用"
		}
		resp["env_warning"] = warn
	}
	// Light reachability probe only when it can actually connect.
	if kv.configured() && kv.enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		var stats struct {
			AssetsTotal      int64 `json:"assets_total"`
			CvesTotal        int64 `json:"cves_total"`
			AssessmentsTotal int64 `json:"assessments_total"`
			FindingsTotal    int64 `json:"findings_total"`
		}
		if err := kvGet(ctx, kv, "/api/stats", nil, &stats); err != nil {
			resp["stats_error"] = err.Error()
		} else {
			resp["reachable"] = true
			resp["stats"] = stats
		}
	}
	writeJSON(w, 200, resp)
}

// ---------- POST /api/sync/ktvuln/datasource ----------
// Sets URL + token (either optional) and enables the source once usable.
// Usability follows configured(): service-account env creds alone suffice, so
// posting an empty token in that mode keeps (or turns on) the enabled state.

func (s *Server) syncKVDatasource(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var body struct {
		URL     string `json:"url"`
		Token   string `json:"token"`
		Enabled *bool  `json:"enabled"`
	}
	_ = decode(r, &body) // empty body = just re-evaluate enablement
	body.URL = strings.TrimRight(strings.TrimSpace(body.URL), "/")
	body.Token = strings.TrimSpace(body.Token)

	kv := s.kvLoad(pg)
	if body.URL != "" {
		kv.baseURL = body.URL
	}
	if body.Token != "" {
		kv.token = body.Token
	}
	// Enable once it can actually be used (same posture as the ScopeSentry row).
	kv.enabled = kv.configured()
	if body.Enabled != nil {
		kv.enabled = *body.Enabled && kv.configured()
	}

	if err := pg.SetSettingsAtomic(r.Context(), map[string]string{
		kvSettingURL:     kv.baseURL,
		kvSettingToken:   kv.token,
		kvSettingEnabled: strconv.FormatBool(kv.enabled),
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	mode := kv.authMode()
	writeJSON(w, 200, map[string]any{
		"url":        kv.baseURL,
		"enabled":    kv.enabled,
		"auth_mode":  mode,
		"token_hint": kvTokenHintFor(mode, kv.token),
	})
}

// ---------- GET /api/sync/ktvuln/assets ----------
// Browse/preview kt-vuln assets (pick targets before syncing). Filters are
// passed through to kt-vuln /api/assets; the envelope {items,total} is proxied.

func (s *Server) syncKVAssets(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	kv := s.kvLoad(pg)
	if !kv.configured() {
		writeErr(w, 502, "kt-vuln 数据源未配置鉴权（服务账号 env 或静态 Token），请先配置")
		return
	}
	limit := queryInt(r, "limit", 50)
	if limit > kvPageLimit {
		limit = kvPageLimit
	}
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if v := r.URL.Query().Get("offset"); v != "" {
		q.Set("offset", v)
	}
	for _, key := range []string{"verdict", "tier", "min_score", "component", "biz_type", "engagement", "country", "php_version", "cve", "q", "sort"} {
		if v := r.URL.Query().Get(key); v != "" {
			q.Set(key, v)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var env struct {
		Items json.RawMessage `json:"items"`
		Total int64           `json:"total"`
	}
	if err := kvGet(ctx, kv, "/api/assets", q, &env); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	if len(env.Items) == 0 {
		env.Items = json.RawMessage("[]")
	}
	writeJSON(w, 200, map[string]any{"items": env.Items, "total": env.Total})
}

// ---------- POST /api/sync/ktvuln/sync ----------

type kvSyncReq struct {
	// kt-vuln 服务端筛选（全部可选，透传 /api/assets）
	Verdict    string `json:"verdict"`    // vulnerable|executable|patched|not_applicable|unknown
	Tier       string `json:"tier"`       // A|B|C|D|E
	MinScore   int    `json:"min_score"`  // 只同步价值分 >= 该值的资产
	Component  string `json:"component"`  // tomcat/jenkins/…
	BizType    string `json:"biz_type"`   // 业务类型标签（盗U盘/VPN平台/…）
	Engagement string `json:"engagement"` // 作业状态，todo=未打过
	Country    string `json:"country"`
	CVE        string `json:"cve"` // 只同步受该 CVE 影响的资产
	Q          string `json:"q"`   // 标题/域名模糊搜索
	// 入库选项
	ImportDomains *bool `json:"import_domains"` // hostnames 落成 subdomain 资产，默认 true
	MaxAssets     int   `json:"max_assets"`     // 单次同步上限，默认 5000，上限 50000
	CreateCompany *bool `json:"create_company"` // 按业务类型聚合并建公司 scope，默认 true
}

// kvAsset 是 kt-vuln /api/assets 返回的资产行（只声明入库用到的字段）。
type kvAsset struct {
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Scheme     *string  `json:"scheme"`
	Title      *string  `json:"title"`
	Hostnames  []string `json:"hostnames"`
	PhpVersion *string  `json:"php_version"`
	Component  *string  `json:"component"`
	Version    *string  `json:"version"`
	// 协同维度（二期）：整体写入服务资产的 extra.ktvuln 子树，供 DSL 筛选与
	// 前端展示；biz_type/engagement_owner 是可空字段，nil 表示上游未标注；
	// country/manual_tier/rating_note 上游可空（null/缺失解为零值）。
	Score            int        `json:"score"`             // 价值分 0-100
	Tier             string     `json:"tier"`              // 价值分层 A-E（自动评估）
	ManualTier       string     `json:"manual_tier"`       // 人工覆核分层（可空，非空时展示优先于 tier）
	BizType          *string    `json:"biz_type"`          // 业务类型（盗U盘/VPN平台/…，可空）
	EngagementStatus string     `json:"engagement_status"` // 作业状态 todo/…
	Verdict          string     `json:"verdict"`           // 判定 vulnerable/patched/…
	EngagementOwner  *string    `json:"engagement_owner"`  // 作业负责人（可空）
	Country          string     `json:"country"`           // 归属国家两字母码（可空）
	RatingNote       string     `json:"rating_note"`       // 价值评分备注（可空，落库截断 500 字符）
	LastSeen         *time.Time `json:"last_seen"`         // 上游最近确认时间（可空，RFC3339）
}

func (s *Server) syncKVRun(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	kv := s.kvLoad(pg)
	if !kv.configured() {
		writeErr(w, 502, "kt-vuln 数据源未配置鉴权（服务账号 env 或静态 Token），请先配置")
		return
	}
	var req kvSyncReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	maxAssets := req.MaxAssets
	if maxAssets <= 0 || maxAssets > 50000 {
		maxAssets = kvDefaultMax
	}
	importDomains := true
	if req.ImportDomains != nil {
		importDomains = *req.ImportDomains
	}
	createCompany := true
	if req.CreateCompany != nil {
		createCompany = *req.CreateCompany
	}

	q := url.Values{}
	q.Set("limit", strconv.Itoa(kvPageLimit))
	q.Set("sort", "score_desc") // 达到上限截断时优先保住高价值资产
	for key, v := range map[string]string{
		"verdict": req.Verdict, "tier": req.Tier, "component": req.Component,
		"biz_type": req.BizType, "engagement": req.Engagement, "country": req.Country,
		"cve": req.CVE, "q": req.Q,
	} {
		if v != "" {
			q.Set(key, v)
		}
	}
	if req.MinScore > 0 {
		q.Set("min_score", strconv.Itoa(req.MinScore))
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	synced := map[string]int{"http_service": 0, "other_service": 0, "subdomain": 0}
	var warnings, errs []string
	errCount := 0
	addErr := func(msg string) {
		errCount++
		if len(errs) < kvMaxErrs {
			errs = append(errs, msg)
		}
	}

	fetched, truncated := 0, false
	var remoteTotal int64
	var groupItems []kvAsset // 通过 ip:port 守卫的资产，供按业务类型聚合公司
	for offset := 0; ; offset += kvPageLimit {
		if fetched >= maxAssets {
			truncated = true
			break
		}
		q.Set("offset", strconv.Itoa(offset))
		var page struct {
			Items []kvAsset `json:"items"`
			Total int64     `json:"total"`
		}
		if err := kvGet(ctx, kv, "/api/assets", q, &page); err != nil {
			addErr(fmt.Sprintf("拉取失败(offset=%d): %v", offset, err))
			break
		}
		remoteTotal = page.Total
		if len(page.Items) == 0 {
			break
		}
		for _, it := range page.Items {
			if fetched >= maxAssets {
				truncated = true
				break
			}
			fetched++
			if it.IP != "" && it.Port > 0 {
				groupItems = append(groupItems, it)
			}
			if e := kvIngest(as, it, importDomains, synced); e != "" {
				addErr(e)
			}
		}
		if truncated || int64(offset)+int64(len(page.Items)) >= remoteTotal {
			break
		}
	}
	if truncated {
		warnings = append(warnings, fmt.Sprintf("达到 %d 条上限，已截断（按价值分降序保留前 %d）", maxAssets, fetched))
	}
	if errCount > len(errs) {
		warnings = append(warnings, fmt.Sprintf("另有 %d 条错误未展示", errCount-len(errs)))
	}

	// 按业务类型聚合公司：业务类型 → 公司「ktvuln:<业务类型>」，scope 行取资产
	// IP + 全部非 IP hostname。scope 规则落库后重算归因，让已有资产也挂上公司。
	companies := []string{}
	scopeAdded := 0
	if createCompany && len(groupItems) > 0 {
		cs := s.companyStore()
		if cs == nil {
			writeErr(w, 503, "database unavailable")
			return
		}
		groups := kvGroupCompanies(groupItems)
		for name := range groups {
			companies = append(companies, name)
		}
		sort.Strings(companies)
		for _, name := range companies {
			cid, err := cs.UpsertByName(name)
			if err != nil {
				addErr("公司创建失败 " + name + ": " + err.Error())
				continue
			}
			lines := groups[name]
			for i := 0; i < len(lines); i += 200 {
				end := min(i+200, len(lines))
				added, _, _, scopeErrs := cs.AddScope(cid, lines[i:end], name)
				scopeAdded += added
				warnings = append(warnings, scopeErrs...)
			}
		}
		if len(companies) > 0 {
			if err := cs.RecomputeAttribution(); err != nil {
				addErr("公司归因重算失败: " + err.Error())
			}
		}
	}

	writeJSON(w, 200, map[string]any{
		"synced":       synced,
		"fetched":      fetched,
		"remote_total": remoteTotal,
		"truncated":    truncated,
		"warnings":     warnings,
		"errors":       errs,
		"companies":    companies,
		"scope_added":  scopeAdded,
	})
}

// kvIngest maps one kt-vuln asset to the ARTEX asset store and upserts it.
// Returns a non-empty error string on failure. synced is incremented per kind.
func kvIngest(as *db.AssetStore, it kvAsset, importDomains bool, synced map[string]int) string {
	if it.IP == "" || it.Port <= 0 {
		return "" // ip:port 是 kt-vuln 的资产主键维度，正常不会缺
	}
	now := time.Now()
	scheme := ""
	if it.Scheme != nil {
		scheme = strings.ToLower(*it.Scheme)
	}
	// URL host 首选第一个 hostname（ARTEX 以 URL 为服务资产的自然键，域名可借
	// root_domain 归因到公司）；不导入域名或没有 hostname 时用 IP。
	host := ""
	if importDomains {
		for _, h := range it.Hostnames {
			if t := strings.TrimSpace(h); t != "" && net.ParseIP(t) == nil {
				host = t
				break
			}
		}
	}
	switch scheme {
	case "http", "https":
		urlHost := host
		if urlHost == "" {
			urlHost = kvBracketIPv6(it.IP)
		}
		svcURL := scheme + "://" + urlHost
		if !((scheme == "http" && it.Port == 80) || (scheme == "https" && it.Port == 443)) {
			svcURL += ":" + strconv.Itoa(it.Port)
		}
		if _, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
			URL: svcURL, Technologies: kvTechnologies(it), PageTitle: kvStr(it.Title), IP: it.IP,
			Extra: kvExtraPatch(it, now),
		}); err != nil {
			return "http_service " + svcURL + ": " + err.Error()
		}
		synced["http_service"]++
	default:
		if _, err := as.UpsertOtherService(db.UpsertOtherServiceReq{
			IP: it.IP, Port: it.Port, ServiceName: kvServiceName(it),
			Extra: kvExtraPatch(it, now),
		}); err != nil {
			return fmt.Sprintf("other_service %s:%d: %v", it.IP, it.Port, err)
		}
		synced["other_service"]++
	}
	// 其余 hostname（以及非 HTTP 资产的全部 hostname）落成 subdomain 资产。
	for _, h := range it.Hostnames {
		h = strings.TrimSpace(h)
		if h == "" || net.ParseIP(h) != nil || strings.EqualFold(h, host) {
			continue
		}
		if _, err := as.UpsertSubdomain(db.UpsertSubdomainReq{Domain: h}); err != nil {
			return "subdomain " + h + ": " + err.Error()
		}
		synced["subdomain"]++
	}
	return ""
}

// kvExtraPatch 把协同维度字段组装成写入 assets.extra 的补丁：整体替换
// extra.ktvuln 子树（db 层顶层 || 合并，不动其他来源的 key）。空字符串/零值
// 字段省略，synced_at 记本次同步时间（RFC3339）。tier 在写入时合并展示值：
// manual_tier（人工覆核）非空优先于自动 tier，manual_tier 原样另存。
func kvExtraPatch(it kvAsset, syncedAt time.Time) map[string]any {
	sub := map[string]any{}
	if it.Score != 0 {
		sub["score"] = it.Score
	}
	tier := it.Tier
	if manual := strings.TrimSpace(it.ManualTier); manual != "" {
		tier = manual
		sub["manual_tier"] = manual
	}
	if tier != "" {
		sub["tier"] = tier
	}
	if v := strings.TrimSpace(kvStr(it.BizType)); v != "" {
		sub["biz_type"] = v
	}
	if it.EngagementStatus != "" {
		sub["engagement_status"] = it.EngagementStatus
	}
	if it.Verdict != "" {
		sub["verdict"] = it.Verdict
	}
	if v := strings.TrimSpace(kvStr(it.EngagementOwner)); v != "" {
		sub["engagement_owner"] = v
	}
	if v := strings.TrimSpace(it.Country); v != "" {
		sub["country"] = v
	}
	if v := kvTruncRunes(strings.TrimSpace(it.RatingNote), kvRatingNoteMax); v != "" {
		sub["rating_note"] = v
	}
	sub["synced_at"] = syncedAt.Format(time.RFC3339)
	return map[string]any{"ktvuln": sub}
}

// kvGroupCompanies 按业务类型把资产聚成公司 scope 行：公司名
// 「ktvuln:<业务类型>」（业务类型为空归「未分类」），每个公司的 lines 是
// 其资产 IP + 全部非 IP hostname，公司内去重并排序。输入应已过 ip:port 守卫，
// 这里再防一层（与入库口径一致）。
func kvGroupCompanies(items []kvAsset) map[string][]string {
	sets := map[string]map[string]struct{}{}
	for _, it := range items {
		if it.IP == "" || it.Port <= 0 {
			continue
		}
		display := strings.TrimSpace(kvStr(it.BizType))
		if display == "" {
			display = "未分类"
		}
		name := "ktvuln:" + display
		set, ok := sets[name]
		if !ok {
			set = map[string]struct{}{}
			sets[name] = set
		}
		set[it.IP] = struct{}{}
		for _, h := range it.Hostnames {
			if h = strings.TrimSpace(h); h != "" && net.ParseIP(h) == nil {
				set[h] = struct{}{}
			}
		}
	}
	out := make(map[string][]string, len(sets))
	for name, set := range sets {
		lines := make([]string, 0, len(set))
		for line := range set {
			lines = append(lines, line)
		}
		sort.Strings(lines)
		out[name] = lines
	}
	return out
}

// kvTechnologies 把组件/版本/PHP 拼成 technologies 列表（php 资产 component 为空）。
func kvTechnologies(it kvAsset) []string {
	var techs []string
	if c := kvStr(it.Component); c != "" {
		if v := kvStr(it.Version); v != "" {
			techs = append(techs, c+"/"+v)
		} else {
			techs = append(techs, c)
		}
	}
	if p := kvStr(it.PhpVersion); p != "" {
		techs = append(techs, "php/"+p)
	}
	return techs
}

// kvServiceName picks the other-service name: component, else php, else unknown.
func kvServiceName(it kvAsset) string {
	if c := kvStr(it.Component); c != "" {
		return strings.ToLower(c)
	}
	if kvStr(it.PhpVersion) != "" {
		return "php"
	}
	return "unknown"
}

// kvBracketIPv6 wraps a literal IPv6 address in brackets for use as a URL host.
func kvBracketIPv6(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

// kvStr dereferences a nullable string from the kt-vuln payload.
func kvStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// kvTruncRunes 按字符数截断（rating_note 备注可能含中文，避免按字节切断 UTF-8）。
func kvTruncRunes(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	return string([]rune(s)[:max])
}
