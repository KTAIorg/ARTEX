package server

// KT 漏洞情报平台（kt-vuln）只读查询工具：vuln_list_cves / vuln_search_assets /
// vuln_cve_detail。给对话 agent（auto）与任务 agent（worker）用，host 工具经
// platformTools() 注入、tools 表按 agent 绑定过滤（seed 默认绑 auto+worker）。
//
// 数据语义（与 kt-vuln handler 对齐，不要混用）：
//   - /api/cves        关注清单：约 36 条精选 CVE（curated + 有判定事实），
//                      带 assessment 暴露面统计 surface 与影响组件 affected
//   - /api/cve-catalog 全量目录：NVD 同步的 CVE 字典（28 万+ 条），仅元数据，
//                      服务端分页 page/page_size/sort/order/year/min_severity/q
//   - /api/assets      资产目录（ip:port/组件/价值分层），唯一事实源，实时查询
//
// 鉴权：只读服务账号 env（VULN_SVC_USERNAME / VULN_SVC_PASSWORD 成对），运行时
// 调 kt-identity 登录换 Bearer、进程内缓存（互斥锁内登录，避免并发刷新风暴），
// 剩余有效期 <2 分钟自动重登，API 请求 401 时废弃缓存强制重登一次再重试。
// 登录走 VULN_SVC_LOGIN_URL（默认集群内热连接代理 login-proxy，避免直连
// https://login.ktyun.cc 的 CF 冷握手 4-16s）；API 走 VULN_SVC_API_URL（默认
// 集群内 svc 直连）。所有出网请求统一 UA artex-vuln-tools/1.0（CF 边缘拦默认
// Go UA）。契约（线上实测，与 P4 退役的 sync_ktvuln.go 同源）：登录请求体字段
// 是 loginName（不是 username），200 响应 {"token":..,"session":{"expiresAt":
// RFC3339}}；expiresAt 缺失/无法解析兜底 30 分钟 TTL。
//
// env 未配齐时工具不 panic，返回可读错误提示管理员补配；kt-vuln 是唯一事实源，
// 这里只做实时查询、不落地任何数据副本（issue KTAIorg/kt-vuln #52 P4 红线）。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

const (
	envVulnUser     = "VULN_SVC_USERNAME"
	envVulnPass     = "VULN_SVC_PASSWORD"
	envVulnLoginURL = "VULN_SVC_LOGIN_URL"
	envVulnAPIURL   = "VULN_SVC_API_URL"

	vulnDefaultLoginURL = "http://login-proxy.kt-edge-proxy.svc:8080/identity/v1/auth/login"
	vulnDefaultAPIURL   = "http://kt-vuln-api.kt-vuln.svc:8080"
	vulnUserAgent       = "artex-vuln-tools/1.0"

	vulnTokenTTLFallback = 30 * time.Minute // expiresAt 缺失/无法解析时的兜底 TTL
	vulnTokenRenewSkew   = 2 * time.Minute  // 剩余有效期低于该值即重新登录

	vulnCatalogPageDef = 50  // catalog 默认每页条数（与服务端一致）
	vulnCatalogPageMax = 200 // catalog 每页上限（服务端 >200 会回落 50，这里前置钳制）
	vulnAssetLimitDef  = 50  // assets 默认条数
	vulnAssetLimitMax  = 1000
	vulnDetailAssetsN  = 20 // cve_detail 默认带回的资产条数
	vulnHostnamesMax   = 5  // 紧凑输出里 hostnames 截断上限
)

// vulnToolKeys 是 vuln 平台工具的 key 集：seed 时默认绑 auto+worker
// （对话 agent 与任务 agent 都要能查漏洞情报）。
var vulnToolKeys = map[string]bool{
	"vuln_list_cves":     true,
	"vuln_search_assets": true,
	"vuln_cve_detail":    true,
}

// vulnCreds 读取只读服务账号 env（成对才算配齐）。
func vulnCreds() (user, pass string) {
	return strings.TrimSpace(os.Getenv(envVulnUser)), strings.TrimSpace(os.Getenv(envVulnPass))
}

// vulnCredsMissing 报告 env 是否未配齐，附可读提示。
func vulnCredsMissing() bool {
	user, pass := vulnCreds()
	return user == "" || pass == ""
}

func vulnCredsError() error {
	return fmt.Errorf("管理员未配置 %s / %s（kt-vuln 只读服务账号），漏洞情报工具暂不可用；请管理员在部署环境成对注入后再试", envVulnUser, envVulnPass)
}

// vulnTokenCache 是服务账号模式的进程内 Bearer 缓存（互斥锁保护，登录在锁内
// 进行，天然避免并发刷新风暴）。
var vulnTokenCache struct {
	sync.Mutex
	token     string
	expiresAt time.Time
}

// vulnLogin 用服务账号账密调 kt-identity 登录接口换 Bearer。
func vulnLogin(ctx context.Context, user, pass string) (string, time.Time, error) {
	loginURL := strings.TrimSpace(os.Getenv(envVulnLoginURL))
	if loginURL == "" {
		loginURL = vulnDefaultLoginURL
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
	req.Header.Set("User-Agent", vulnUserAgent)
	resp, err := vulnHTTPClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", time.Time{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", time.Time{}, fmt.Errorf("identity 登录接口 HTTP %d: %s", resp.StatusCode, vulnErrMessage(body, resp.Status))
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
		expiresAt = time.Now().Add(vulnTokenTTLFallback)
	}
	return out.Token, expiresAt, nil
}

// vulnToken 返回有效期内（剩余 >2 分钟）的缓存 token，否则重新登录。
func vulnToken(ctx context.Context) (string, error) {
	if vulnCredsMissing() {
		return "", vulnCredsError()
	}
	user, pass := vulnCreds()
	vulnTokenCache.Lock()
	defer vulnTokenCache.Unlock()
	if vulnTokenCache.token != "" && time.Until(vulnTokenCache.expiresAt) > vulnTokenRenewSkew {
		return vulnTokenCache.token, nil
	}
	token, expiresAt, err := vulnLogin(ctx, user, pass)
	if err != nil {
		return "", fmt.Errorf("服务账号登录失败(%s=%s): %w", envVulnUser, user, err)
	}
	vulnTokenCache.token = token
	vulnTokenCache.expiresAt = expiresAt
	return token, nil
}

// vulnTokenReset 废弃缓存 token（API 401 时调用，强制下次重新登录）。
func vulnTokenReset() {
	vulnTokenCache.Lock()
	vulnTokenCache.token = ""
	vulnTokenCache.expiresAt = time.Time{}
	vulnTokenCache.Unlock()
}

// vulnHTTPClient 独立 client：集群内 svc 直连，连接复用。响应头超时对齐工具层
// 最大预算（150s）——/api/assets 带 engagement/cve 过滤 + sort 时 kt-vuln 侧实测
// 可跑 70s+（2026-11-02 真实 Agent 对话 E2E 发现 30s 会误杀慢查询）。
var vulnHTTPClient = &http.Client{
	Transport: &http.Transport{
		ResponseHeaderTimeout: 150 * time.Second,
		IdleConnTimeout:       10 * time.Minute,
	},
}

// vulnErrMessage 兼容两种线上错误包体取 message：
// {"error":{"code":..,"message":..}}（identity 网关）与 {"status":"error","message":..}（kt-vuln writeErr）。
func vulnErrMessage(body []byte, fallback string) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil {
		if e.Error.Message != "" {
			return e.Error.Message
		}
		if e.Message != "" {
			return e.Message
		}
	}
	return fallback
}

// vulnGet 调 kt-vuln REST API 并把 JSON 解到 out。Bearer 经 vulnToken 动态获取；
// 401（token 失效）时废弃缓存、重新登录后重试一次，仍失败则带服务端 message 返回。
func vulnGet(ctx context.Context, path string, query url.Values, out any) error {
	if vulnCredsMissing() {
		return vulnCredsError()
	}
	apiBase := strings.TrimRight(strings.TrimSpace(os.Getenv(envVulnAPIURL)), "/")
	if apiBase == "" {
		apiBase = vulnDefaultAPIURL
	}
	u := apiBase + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	for attempt := 0; ; attempt++ {
		token, err := vulnToken(ctx)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", vulnUserAgent)
		resp, err := vulnHTTPClient.Do(req)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			vulnTokenReset() // token 过期/被吊销：重登一次再试
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("kt-vuln %s: HTTP %d: %s", path, resp.StatusCode, vulnErrMessage(body, resp.Status))
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("kt-vuln %s 响应解析失败: %w", path, err)
		}
		return nil
	}
}

// ---------- 紧凑输出结构（挑对 agent 有用的字段，控制 token 占用） ----------

type vulnSurface struct {
	Vulnerable    int `json:"vulnerable"`
	Executable    int `json:"executable"`
	Patched       int `json:"patched"`
	NotApplicable int `json:"not_applicable"`
	Unknown       int `json:"unknown"`
}

// vulnFocusCve 是 /api/cves 的关注清单条目（全量透传，列表本身只有几十条）。
type vulnFocusCve struct {
	CveID    string              `json:"cve_id"`
	Title    *string             `json:"title"`
	Category *string             `json:"category"`
	Severity *float64            `json:"severity"`
	Kev      *bool               `json:"kev"`
	Affected map[string][]string `json:"affected"`
	Surface  *vulnSurface        `json:"surface"`
}

// vulnCatalogItem 是 /api/cve-catalog 条目的紧凑形态：剥掉 cvss_vector /
// cvss_version（CVSS:4.0 向量长达数百字符，对情报分诊无用且严重膨胀输出）。
type vulnCatalogItem struct {
	CveID         string   `json:"cve_id"`
	Title         string   `json:"title,omitempty"`
	Severity      *float64 `json:"severity,omitempty"`
	Published     string   `json:"published,omitempty"`
	PublishedYear *int     `json:"published_year,omitempty"`
	Kev           *bool    `json:"kev,omitempty"`
	Source        string   `json:"source,omitempty"`
}

type vulnCatalogItemRaw struct {
	CveID         string   `json:"cve_id"`
	Title         *string  `json:"title"`
	Severity      *float64 `json:"severity"`
	Published     *string  `json:"published"`
	PublishedYear *int     `json:"published_year"`
	Kev           *bool    `json:"kev"`
	Source        *string  `json:"source"`
}

// vulnAssetItem 是 /api/assets 条目的紧凑形态：保留目标定位与价值维度，
// hostnames 截前 5 个，去掉 rating_note / engagement_owner / last_seen 等长尾。
type vulnAssetItem struct {
	ID         int64    `json:"id"`
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Scheme     string   `json:"scheme,omitempty"`
	Hostnames  []string `json:"hostnames,omitempty"`
	Title      string   `json:"title,omitempty"`
	Component  string   `json:"component,omitempty"`
	Version    string   `json:"version,omitempty"`
	PhpVersion string   `json:"php_version,omitempty"`
	Verdict    string   `json:"verdict,omitempty"`
	Score      int      `json:"score,omitempty"`
	Tier       string   `json:"tier,omitempty"`
	ManualTier string   `json:"manual_tier,omitempty"`
	BizType    string   `json:"biz_type,omitempty"`
	Engagement string   `json:"engagement_status,omitempty"`
	Country    string   `json:"country,omitempty"`
}

type vulnAssetRaw struct {
	ID         int64    `json:"id"`
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Scheme     *string  `json:"scheme"`
	Hostnames  []string `json:"hostnames"`
	Title      *string  `json:"title"`
	Component  *string  `json:"component"`
	Version    *string  `json:"version"`
	PhpVersion *string  `json:"php_version"`
	Verdict    *string  `json:"verdict"`
	Score      *int     `json:"score"`
	Tier       *string  `json:"tier"`
	ManualTier *string  `json:"manual_tier"`
	BizType    *string  `json:"biz_type"`
	Engagement *string  `json:"engagement_status"`
	Country    *string  `json:"country"`
}

func vulnStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (a vulnAssetRaw) compact() vulnAssetItem {
	it := vulnAssetItem{
		ID: a.ID, IP: a.IP, Port: a.Port,
		Scheme: vulnStr(a.Scheme), Title: vulnStr(a.Title),
		Component: vulnStr(a.Component), Version: vulnStr(a.Version),
		PhpVersion: vulnStr(a.PhpVersion), Verdict: vulnStr(a.Verdict),
		Tier: vulnStr(a.Tier), ManualTier: vulnStr(a.ManualTier),
		BizType: vulnStr(a.BizType), Engagement: vulnStr(a.Engagement),
		Country: vulnStr(a.Country),
	}
	if a.Score != nil {
		it.Score = *a.Score
	}
	if n := len(a.Hostnames); n > 0 {
		if n > vulnHostnamesMax {
			it.Hostnames = append(a.Hostnames[:vulnHostnamesMax],
				fmt.Sprintf("+%d more", n-vulnHostnamesMax))
		} else {
			it.Hostnames = a.Hostnames
		}
	}
	return it
}

// vulnCveYear 从 CVE 编号解析年份（CVE-2023-46604 → 2023）。关注清单条目没有
// 独立的发布年份字段，year 过滤按编号年份做客户端过滤。
var vulnCveYearRe = regexp.MustCompile(`(?i)^CVE-(\d{4})-`)

func vulnCveYear(cveID string) int {
	m := vulnCveYearRe.FindStringSubmatch(strings.TrimSpace(cveID))
	if m == nil {
		return 0
	}
	y, _ := strconv.Atoi(m[1])
	return y
}

// focusCveMatch 报告关注清单条目是否命中关键词（编号/标题/分类/影响组件，与
// ARTEX CVE 面板的客户端过滤口径一致）。
func focusCveMatch(c vulnFocusCve, needle string) bool {
	if needle == "" {
		return true
	}
	if strings.Contains(strings.ToLower(c.CveID), needle) ||
		strings.Contains(strings.ToLower(vulnStr(c.Title)), needle) ||
		strings.Contains(strings.ToLower(vulnStr(c.Category)), needle) {
		return true
	}
	for k := range c.Affected {
		if strings.Contains(strings.ToLower(k), needle) {
			return true
		}
	}
	return false
}

// ---------- 工具实现 ----------

// toolVulnListCves vuln_list_cves：focus=关注清单（36 条精选，带暴露面统计）；
// catalog=全量目录（NVD 字典，服务端分页检索）。
func (s *Server) toolVulnListCves() actool.CoreTool {
	desc := "查询 KT 漏洞情报平台(kt-vuln, vuln.ktyun.cc)的 CVE 列表。两个 scope 语义不同、不要混用：\n" +
		"• scope=focus 关注清单：约 36 条精选 CVE（人工运营+有资产判定事实），每条带暴露面统计 surface(疑似/可确认/已修复/未知资产数)与影响组件版本 affected，回答「我们在关注哪些漏洞、各自影响面多大」用它；\n" +
		"• scope=catalog 全量目录：NVD 同步的全量 CVE 字典(28 万+条)，仅元数据(编号/标题/严重度/发布日期/KEV/来源)、无暴露面，检索任意 CVE 是否存在及基本信息用它。\n" +
		"q 关键词检索(focus 匹配编号/标题/分类/组件，catalog 匹配编号/标题)；year 发布年份；min_severity CVSS 下限(如 9.0)；page/page_size 分页(默认 1/50，上限 200；focus 为客户端分页)；sort/order 仅 catalog 有效(severity|published|cve_id，默认 severity 降序)。数据事实源在 vuln.ktyun.cc，实时查询、不落副本。"
	schema := objSchema(map[string]any{
		"scope":        map[string]any{"type": "string", "enum": []string{"focus", "catalog"}, "description": "focus=关注清单(精选+暴露面) | catalog=全量目录(NVD 字典,仅检索)"},
		"q":            strParam("关键词：focus 匹配 CVE 编号/标题/分类/影响组件；catalog 匹配 cve_id/标题(模糊)"),
		"year":         map[string]any{"type": "integer", "description": "发布年份，如 2024（focus 按编号中的年份过滤）"},
		"min_severity": map[string]any{"type": "number", "description": "CVSS 分下限 0-10，如 9.0"},
		"page":         map[string]any{"type": "integer", "description": "页码，从 1 起，默认 1"},
		"page_size":    map[string]any{"type": "integer", "description": "每页条数，默认 50、上限 200"},
		"sort":         map[string]any{"type": "string", "enum": []string{"severity", "published", "cve_id"}, "description": "仅 catalog：排序字段，默认 severity"},
		"order":        map[string]any{"type": "string", "enum": []string{"desc", "asc"}, "description": "仅 catalog：排序方向，默认 desc"},
	}, "scope")
	return roTool("vuln_list_cves", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Scope       string   `json:"scope"`
			Q           string   `json:"q"`
			Year        int      `json:"year"`
			MinSeverity *float64 `json:"min_severity"`
			Page        int      `json:"page"`
			PageSize    int      `json:"page_size"`
			Sort        string   `json:"sort"`
			Order       string   `json:"order"`
		}
		_ = json.Unmarshal(in, &a)
		a.Q = strings.TrimSpace(a.Q)
		a.Sort = strings.TrimSpace(a.Sort)
		a.Order = strings.ToLower(strings.TrimSpace(a.Order))
		if a.Page < 1 {
			a.Page = 1
		}
		if a.PageSize < 1 {
			a.PageSize = vulnCatalogPageDef
		}
		if a.PageSize > vulnCatalogPageMax {
			a.PageSize = vulnCatalogPageMax
		}

		switch a.Scope {
		case "focus":
			cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			var resp struct {
				Items []vulnFocusCve `json:"items"`
			}
			if err := vulnGet(cctx, "/api/cves", nil, &resp); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			needle := strings.ToLower(a.Q)
			filtered := make([]vulnFocusCve, 0, len(resp.Items))
			for _, c := range resp.Items {
				if !focusCveMatch(c, needle) {
					continue
				}
				if a.Year > 0 && vulnCveYear(c.CveID) != a.Year {
					continue
				}
				if a.MinSeverity != nil && (c.Severity == nil || *c.Severity < *a.MinSeverity) {
					continue
				}
				filtered = append(filtered, c)
			}
			start := (a.Page - 1) * a.PageSize
			if start > len(filtered) {
				start = len(filtered)
			}
			end := start + a.PageSize
			if end > len(filtered) {
				end = len(filtered)
			}
			return jsonResult(map[string]any{
				"scope": "focus", "total": len(filtered),
				"page": a.Page, "page_size": a.PageSize, "items": filtered[start:end],
			})
		case "catalog":
			q := url.Values{}
			q.Set("page", strconv.Itoa(a.Page))
			q.Set("page_size", strconv.Itoa(a.PageSize))
			if a.Q != "" {
				q.Set("q", a.Q)
			}
			if a.Year > 0 {
				q.Set("year", strconv.Itoa(a.Year))
			}
			if a.MinSeverity != nil {
				q.Set("min_severity", strconv.FormatFloat(*a.MinSeverity, 'f', -1, 64))
			}
			if a.Sort != "" {
				q.Set("sort", a.Sort)
			}
			if a.Order != "" {
				q.Set("order", a.Order)
			}
			cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			var resp struct {
				Items []vulnCatalogItemRaw `json:"items"`
				Total int                  `json:"total"`
				Page  int                  `json:"page"`
				Size  int                  `json:"page_size"`
			}
			if err := vulnGet(cctx, "/api/cve-catalog", q, &resp); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			items := make([]vulnCatalogItem, 0, len(resp.Items))
			for _, it := range resp.Items {
				items = append(items, vulnCatalogItem{
					CveID: it.CveID, Title: vulnStr(it.Title), Severity: it.Severity,
					Published: vulnStr(it.Published), PublishedYear: it.PublishedYear,
					Kev: it.Kev, Source: vulnStr(it.Source),
				})
			}
			return jsonResult(map[string]any{
				"scope": "catalog", "total": resp.Total,
				"page": resp.Page, "page_size": resp.Size, "items": items,
			})
		default:
			return actool.Errorf("scope 必须是 focus 或 catalog"), nil
		}
	})
}

// toolVulnSearchAssets vuln_search_assets：kt-vuln 资产目录检索（唯一事实源）。
func (s *Server) toolVulnSearchAssets() actool.CoreTool {
	desc := "检索 KT 漏洞情报平台(kt-vuln)的资产目录——全网测绘资产(ip:port/组件版本/价值分层)的唯一事实源，实时查询、不落副本。资产按 ip:port 建模，常用维度：score 价值分 0-100、tier 价值分层(S>A>B>C>D>E,exclude)、biz_type 业务类型(如 盗U盘/VPN平台)、engagement 作业状态(todo=还没打过)、verdict 漏洞判定(executable=已验证可利用 > vulnerable=疑似/版本命中 > patched=已修复)。\n" +
		"过滤参数：q(标题/域名关键词)、tier(可逗号分隔多值如 A,S)、biz_type、engagement、verdict、country(两字母码)、min_score、cve(只看受该 CVE 影响的资产，如 CVE-2023-46604，此查询较慢可能需数十秒)、sort=score_desc(价值分降序)。limit 默认 50、上限 1000，offset 翻页。返回 {total,items}。"
	schema := objSchema(map[string]any{
		"q":          strParam("标题/域名关键词，模糊匹配"),
		"tier":       map[string]any{"type": "string", "description": "价值分层 S/A/B/C/D/E/exclude，可逗号分隔多值（如 A,S）"},
		"biz_type":   strParam("业务类型标签，如 盗U盘、VPN平台"),
		"engagement": map[string]any{"type": "string", "enum": []string{"todo", "claimed", "in_progress", "done_hit", "done_miss", "blocked", "excluded"}, "description": "作业状态，todo=还没人打过"},
		"verdict":    map[string]any{"type": "string", "enum": []string{"vulnerable", "executable", "patched", "not_applicable", "unknown"}, "description": "漏洞判定；与 cve 同用时表示该 CVE 下的判定"},
		"country":    strParam("两字母国家码，如 CN、US"),
		"min_score":  map[string]any{"type": "integer", "description": "价值分下限 0-100"},
		"cve":        strParam("CVE 编号，如 CVE-2023-46604；只看受它影响的资产（较慢）"),
		"sort":       map[string]any{"type": "string", "enum": []string{"score_desc"}, "description": "排序；score_desc=价值分降序"},
		"limit":      map[string]any{"type": "integer", "description": "返回条数，默认 50、上限 1000"},
		"offset":     map[string]any{"type": "integer", "description": "翻页偏移，默认 0"},
	})
	return roTool("vuln_search_assets", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Q          string `json:"q"`
			Tier       string `json:"tier"`
			BizType    string `json:"biz_type"`
			Engagement string `json:"engagement"`
			Verdict    string `json:"verdict"`
			Country    string `json:"country"`
			MinScore   int    `json:"min_score"`
			Cve        string `json:"cve"`
			Sort       string `json:"sort"`
			Limit      int    `json:"limit"`
			Offset     int    `json:"offset"`
		}
		_ = json.Unmarshal(in, &a)
		if a.Limit < 1 {
			a.Limit = vulnAssetLimitDef
		}
		if a.Limit > vulnAssetLimitMax {
			a.Limit = vulnAssetLimitMax
		}
		if a.Offset < 0 {
			a.Offset = 0
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(a.Limit))
		q.Set("offset", strconv.Itoa(a.Offset))
		for key, v := range map[string]string{
			"q": a.Q, "tier": a.Tier, "biz_type": a.BizType, "engagement": a.Engagement,
			"verdict": a.Verdict, "country": a.Country, "cve": a.Cve, "sort": a.Sort,
		} {
			if strings.TrimSpace(v) != "" {
				q.Set(key, strings.TrimSpace(v))
			}
		}
		if a.MinScore > 0 {
			q.Set("min_score", strconv.Itoa(a.MinScore))
		}
		// cve 过滤在 kt-vuln 侧是 EXISTS 子查询扫 assessment，线上较慢，给足超时。
		cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
		var resp struct {
			Items []vulnAssetRaw `json:"items"`
			Total int64          `json:"total"`
		}
		if err := vulnGet(cctx, "/api/assets", q, &resp); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		items := make([]vulnAssetItem, 0, len(resp.Items))
		for _, it := range resp.Items {
			items = append(items, it.compact())
		}
		return jsonResult(map[string]any{
			"total": resp.Total, "limit": a.Limit, "offset": a.Offset, "items": items,
		})
	})
}

// toolVulnCveDetail vuln_cve_detail：单条 CVE 画像（focus 详情或 catalog 元数据
// 回落）+ 受影响资产。
func (s *Server) toolVulnCveDetail() actool.CoreTool {
	desc := "查单条 CVE 的完整画像：基本信息 + 暴露面统计 + 受影响资产列表。cve_id 形如 CVE-2023-46604。\n" +
		"在关注清单(约 36 条精选)内的 CVE 返回分类/影响组件版本区间 affected 与暴露面 surface(executable=已验证可利用、vulnerable=疑似、patched=已修复、unknown 各多少资产)；不在清单内的回落全量目录取基础元数据(title/severity/published/kev/source)。\n" +
		"资产列表按该 CVE 过滤(线上较慢，可能数十秒)，默认带前 20 条并附 assets_total 总数；资产行的 verdict 即该 CVE 下的判定。"
	schema := objSchema(map[string]any{
		"cve_id": strParam("CVE 编号，如 CVE-2023-46604"),
	}, "cve_id")
	return roTool("vuln_cve_detail", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			CveID string `json:"cve_id"`
		}
		_ = json.Unmarshal(in, &a)
		a.CveID = strings.ToUpper(strings.TrimSpace(a.CveID))
		if a.CveID == "" {
			return actool.Errorf("cve_id 不能为空"), nil
		}
		cctx, cancel := context.WithTimeout(ctx, 150*time.Second)
		defer cancel()

		out := map[string]any{"cve_id": a.CveID}
		var focusHit *vulnFocusCve

		var focus struct {
			Items []vulnFocusCve `json:"items"`
		}
		if err := vulnGet(cctx, "/api/cves", nil, &focus); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		for i := range focus.Items {
			if focus.Items[i].CveID == a.CveID {
				focusHit = &focus.Items[i]
				break
			}
		}
		if focusHit != nil {
			out["in_focus"] = true
			out["cve"] = focusHit
			if focusHit.Surface != nil {
				out["surface"] = focusHit.Surface
			}
		} else {
			// 回落全量字典：q 对 cve_id 做模糊匹配，客户端再精确对号。
			q := url.Values{}
			q.Set("q", a.CveID)
			q.Set("page_size", "5")
			var cat struct {
				Items []vulnCatalogItemRaw `json:"items"`
			}
			if err := vulnGet(cctx, "/api/cve-catalog", q, &cat); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var dictHit *vulnCatalogItemRaw
			for i := range cat.Items {
				if cat.Items[i].CveID == a.CveID {
					dictHit = &cat.Items[i]
					break
				}
			}
			if dictHit == nil {
				return actool.Errorf("CVE 不存在: " + a.CveID + "（关注清单与全量目录均未命中）"), nil
			}
			out["in_focus"] = false
			out["cve"] = vulnCatalogItem{
				CveID: dictHit.CveID, Title: vulnStr(dictHit.Title), Severity: dictHit.Severity,
				Published: vulnStr(dictHit.Published), PublishedYear: dictHit.PublishedYear,
				Kev: dictHit.Kev, Source: vulnStr(dictHit.Source),
			}
		}

		// 受影响资产：/api/assets?cve= 过滤（EXISTS 子查询，慢，给足预算）。
		aq := url.Values{}
		aq.Set("cve", a.CveID)
		aq.Set("limit", strconv.Itoa(vulnDetailAssetsN))
		var assets struct {
			Items []vulnAssetRaw `json:"items"`
			Total int64          `json:"total"`
		}
		if err := vulnGet(cctx, "/api/assets", aq, &assets); err != nil {
			out["assets_error"] = err.Error()
			out["assets_total"] = int64(-1)
		} else {
			items := make([]vulnAssetItem, 0, len(assets.Items))
			for _, it := range assets.Items {
				items = append(items, it.compact())
			}
			out["assets_total"] = assets.Total
			out["assets_returned"] = len(items)
			out["assets"] = items
		}
		return jsonResult(out)
	})
}
