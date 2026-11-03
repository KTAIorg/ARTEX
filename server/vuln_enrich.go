package server

// CVE 情报富化工具 vuln_enrich_cve——授权渗透测试平台的情报工具：子 agent 拿到一个
// CVE 编号、要判断「这个 CVE 值不值得打」时，一次调用聚合多源情报给出标准化画像与
// P0-P4 优先级结论。修的是成功率先验公式里的 P(指纹正确) × P(前置满足) 两项：
// affected 给指纹核对依据（组件+版本区间），preconditions 给前置满足概率依据
// （是否需认证 / 网络位置 / 用户交互）。
//
// 数据源（优先级从高到低，逐级降级，任何单源失败/超时只降级不阻塞整体）：
//   1. 本地 kt-vuln（/api/cves 关注清单 + /api/cve-catalog 全量字典，复用 vulnGet
//      服务账号通道；服务账号未配或集群不可达时跳过该源）
//   2. NVD 公开 API（cveId 精确查询，无需 key；匿名限流 5req/30s，靠缓存兜底）
//   3. GitHub Advisory（cve_id 检索，无需 key）
// EPSS 分数走 FIRST.org 公开接口尽力而为补充（取不到输出 null）。三大主源全部拿不到
// 数据时返回结构化错误并逐源列出原因，不 panic。
//
// 富化结果按 CVE 编号落 PostgreSQL cve_enrich_cache（TTL 默认 24h，env
// VULN_ENRICH_CACHE_TTL_HOURS 可调），TTL 内重复查询直接回缓存。三个外部源 URL 均可
// env 覆盖（VULN_ENRICH_NVD_URL / VULN_ENRICH_GHSA_URL / VULN_ENRICH_EPSS_URL），
// 同时是测试注入 mock 服务的挂点（不依赖真实外网）。

import (
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
	"time"

	pgdb "github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	envEnrichNVDURL   = "VULN_ENRICH_NVD_URL"
	envEnrichGHSAURL  = "VULN_ENRICH_GHSA_URL"
	envEnrichEPSSURL  = "VULN_ENRICH_EPSS_URL"
	envEnrichTTLHours = "VULN_ENRICH_CACHE_TTL_HOURS"

	enrichNVDURLDef  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	enrichGHSAURLDef = "https://api.github.com/advisories"
	enrichEPSSURLDef = "https://api.first.org/data/v1/epss"

	enrichTimeoutTotal  = 90 * time.Second // 工具层总预算（各源超时之和留有余量）
	enrichTimeoutKtVuln = 45 * time.Second
	enrichTimeoutNVD    = 20 * time.Second
	enrichTimeoutGHSA   = 10 * time.Second
	enrichTimeoutEPSS   = 5 * time.Second

	enrichTTLDef        = 24 * time.Hour // 缓存默认 TTL
	enrichDescMax       = 600            // 描述截断，控制输出 token
	enrichAffectedMax   = 10             // 影响条目上限
	enrichPocSourcesMax = 5              // PoC 链接列表上限
)

// reCVEID 校验 CVE 编号形态（CVE-2023-46604；序号 4 位起，新编号会更长）。
var reCVEID = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// enrichHTTPClient 外部公开源专用 client：整体超时兜底（每请求另有 ctx 超时），
// 不与 kt-vuln 的集群内直连 client 混用。
var enrichHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		IdleConnTimeout: 5 * time.Minute,
	},
}

// ---------- 输出契约 ----------

// cveEnrichAffected 一条影响产品/版本范围（指纹核对依据）。
type cveEnrichAffected struct {
	Source       string `json:"source"`                  // kt-vuln | nvd | github-advisory
	Product      string `json:"product"`                 // 组件（vendor:product / ecosystem:name / 人工运营组件名）
	VersionRange string `json:"version_range,omitempty"` // 如 ">= 5.0.0, < 5.18.3"
	CPE          string `json:"cpe,omitempty"`           // NVD CPE criteria（若有）
}

// cveEnrichSeverity CVSS 分数与向量。
type cveEnrichSeverity struct {
	Score  float64 `json:"score"`            // 0-10
	Vector string  `json:"vector,omitempty"` // CVSS:3.1/AV:N/...
	Level  string  `json:"level,omitempty"`  // critical|high|medium|low
	Source string  `json:"source"`           // nvd | github-advisory | kt-vuln
}

// cveEnrichPoc 公开 PoC 情报。
type cveEnrichPoc struct {
	Count   int      `json:"count"`
	Best    string   `json:"best,omitempty"` // 最可信/最可用的一条
	Sources []string `json:"sources"`        // 去重后的 PoC 链接（截前 5 条）
}

// cveEnrichPreconditions 结构化利用前置。
type cveEnrichPreconditions struct {
	Auth            string `json:"auth"`               // none | low | high | unknown
	Network         string `json:"network"`            // remote | adjacent | local | unknown
	UserInteraction string `json:"user_interaction"`   // none | required | unknown
	Evidence        string `json:"evidence,omitempty"` // 解析依据（CVSS 向量或描述关键词）
}

// cveEnrichSuggestedVerify 推荐验证原子动作草案（工具 atomic_verify_poc 的请求模板）。
type cveEnrichSuggestedVerify struct {
	Tool  string         `json:"tool"` // atomic_verify_poc
	Mode  string         `json:"mode"` // run_poc | version_check
	Draft map[string]any `json:"draft"`
}

// cveEnrichVerdict 打分结论。
type cveEnrichVerdict struct {
	Priority string `json:"priority"` // P0|P1|P2|P3|P4（P0 最优先）
	Reason   string `json:"reason"`
}

// cveEnrichSourceReport 单个数据源的取数状态（可观测：谁命中、谁降级、为什么）。
type cveEnrichSourceReport struct {
	Name   string `json:"name"`   // kt-vuln | nvd | github-advisory | epss
	Status string `json:"status"` // hit | miss | error | skipped
	Note   string `json:"note,omitempty"`
}

type cveEnrichCacheInfo struct {
	Hit       bool   `json:"hit"`
	FetchedAt string `json:"fetched_at"`
	ExpiresAt string `json:"expires_at"`
}

// cveEnrichResult 是 vuln_enrich_cve 的标准化输出，也是缓存 payload 的形态
// （落库时 Cache 为空，回给调用方前填充）。
type cveEnrichResult struct {
	CveID           string                    `json:"cve_id"`
	Title           string                    `json:"title,omitempty"`
	Summary         string                    `json:"summary,omitempty"`
	Affected        []cveEnrichAffected       `json:"affected"`
	Severity        *cveEnrichSeverity        `json:"severity"`
	Kev             any                       `json:"kev"` // true | false | "unknown"
	Epss            *float64                  `json:"epss"`
	Poc             cveEnrichPoc              `json:"poc"`
	Preconditions   *cveEnrichPreconditions   `json:"preconditions"`
	SuggestedVerify *cveEnrichSuggestedVerify `json:"suggested_verify"`
	Verdict         cveEnrichVerdict          `json:"verdict"`
	Sources         []cveEnrichSourceReport   `json:"sources"`
	Cache           *cveEnrichCacheInfo       `json:"cache,omitempty"`
}

// ---------- 数据源抓取 ----------

// enrichNVD 是 NVD CVE API 2.0 单条结果的紧凑解析形态。
type enrichNVD struct {
	Description    string
	CisaExploitAdd string // 非空 = 在 CISA KEV 清单（NVD 镜像 KEV 扩展字段）
	Score          float64
	Vector         string
	Level          string
	CPEs           []cveEnrichAffected
	Refs           []struct {
		URL        string
		ExploitTag bool // NVD 引用打了 Exploit 标签
	}
}

// enrichGHSA 是 GitHub Advisory 单条结果的紧凑解析形态。
type enrichGHSA struct {
	Summary  string
	Severity string
	Score    *float64
	Vector   string
	Refs     []string
	Vuls     []cveEnrichAffected
}

// cveEnrichGather 汇聚各源贡献，交给 buildCveEnrichResult 合并。
type cveEnrichGather struct {
	focus *vulnFocusCve       // kt-vuln 关注清单命中（含人工运营 affected/kev）
	cat   *vulnCatalogItemRaw // kt-vuln 全量字典命中
	nvd   *enrichNVD
	ghsa  *enrichGHSA
	epss  *float64
}

func enrichEnvURL(env, def string) string {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return def
}

// enrichGetJSON 抓一个外部 JSON 源：ctx 超时 + client 超时双兜底，读体限 8MB。
func enrichGetJSON(ctx context.Context, name, u string, timeout time.Duration, out any) error {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", vulnUserAgent)
	resp, err := enrichHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return errEnrichNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s HTTP %d: %s", name, resp.StatusCode, vulnErrMessage(body, resp.Status))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s 响应解析失败: %w", name, err)
	}
	return nil
}

// errEnrichNotFound 表示源明确说「没有这个 CVE」（404 / 空结果），区别于网络失败。
var errEnrichNotFound = fmt.Errorf("not found")

// enrichFetchNVD 按 cveId 精确查 NVD。返回 (nil, nil) 表示未收录。
func enrichFetchNVD(ctx context.Context, cveID string) (*enrichNVD, error) {
	u := enrichEnvURL(envEnrichNVDURL, enrichNVDURLDef) + "?cveId=" + cveID
	var resp struct {
		Vulnerabilities []struct {
			Cve struct {
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []enrichNVDMetric `json:"cvssMetricV31"`
					CvssMetricV30 []enrichNVDMetric `json:"cvssMetricV30"`
					CvssMetricV2  []enrichNVDMetric `json:"cvssMetricV2"`
				} `json:"metrics"`
				Configurations []struct {
					Nodes []struct {
						CpeMatch []enrichNVDCPE `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
				References []struct {
					URL  string   `json:"url"`
					Tags []string `json:"tags"`
				} `json:"references"`
				CisaExploitAdd string `json:"cisaExploitAdd"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := enrichGetJSON(ctx, "NVD", u, enrichTimeoutNVD, &resp); err != nil {
		if err == errEnrichNotFound {
			return nil, nil
		}
		return nil, err
	}
	if len(resp.Vulnerabilities) == 0 {
		return nil, nil
	}
	c := resp.Vulnerabilities[0].Cve
	out := &enrichNVD{CisaExploitAdd: c.CisaExploitAdd}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			out.Description = d.Value
			break
		}
	}
	// CVSS 取 V3.1 > V3.0 > V2，同版本内 Primary 优先。
	for _, group := range [][]enrichNVDMetric{c.Metrics.CvssMetricV31, c.Metrics.CvssMetricV30, c.Metrics.CvssMetricV2} {
		if len(group) == 0 {
			continue
		}
		m := group[0]
		for _, cand := range group {
			if cand.Type == "Primary" {
				m = cand
				break
			}
		}
		out.Score = m.CvssData.BaseScore
		out.Vector = m.CvssData.VectorString
		out.Level = strings.ToLower(m.CvssData.BaseSeverity)
		break
	}
	if out.Level == "" && out.Score > 0 {
		out.Level = cvssLevel(out.Score)
	}
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, cpe := range node.CpeMatch {
				if !cpe.Vulnerable {
					continue
				}
				out.CPEs = append(out.CPEs, cpe.affected())
			}
		}
	}
	for _, r := range c.References {
		ref := struct {
			URL        string
			ExploitTag bool
		}{URL: r.URL}
		for _, tag := range r.Tags {
			if tag == "Exploit" {
				ref.ExploitTag = true
				break
			}
		}
		out.Refs = append(out.Refs, ref)
	}
	return out, nil
}

type enrichNVDMetric struct {
	Type     string `json:"type"`
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

type enrichNVDCPE struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// affected 把一条 NVD CPE 命中转成 affected 条目：product 取 vendor:product
// （cpe:2.3:a:apache:activemq:* → apache:activemq），版本区间由四个边界字段拼成
// ">= x, < y" 形态。
func (c enrichNVDCPE) affected() cveEnrichAffected {
	product := ""
	if parts := strings.Split(c.Criteria, ":"); len(parts) >= 5 {
		product = parts[3] + ":" + parts[4]
	}
	var bounds []string
	if c.VersionStartIncluding != "" {
		bounds = append(bounds, ">= "+c.VersionStartIncluding)
	}
	if c.VersionStartExcluding != "" {
		bounds = append(bounds, "> "+c.VersionStartExcluding)
	}
	if c.VersionEndIncluding != "" {
		bounds = append(bounds, "<= "+c.VersionEndIncluding)
	}
	if c.VersionEndExcluding != "" {
		bounds = append(bounds, "< "+c.VersionEndExcluding)
	}
	return cveEnrichAffected{
		Source:       "nvd",
		Product:      product,
		VersionRange: strings.Join(bounds, ", "),
		CPE:          c.Criteria,
	}
}

// enrichFetchGHSA 按 cve_id 查 GitHub Advisory。返回 (nil, nil) 表示未收录。
func enrichFetchGHSA(ctx context.Context, cveID string) (*enrichGHSA, error) {
	u := enrichEnvURL(envEnrichGHSAURL, enrichGHSAURLDef) + "?cve_id=" + cveID
	var resp []struct {
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
		Cvss     struct {
			Score        *float64 `json:"score"`
			VectorString string   `json:"vector_string"`
		} `json:"cvss"`
		References      []string `json:"references"`
		Vulnerabilities []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			VulnerableVersionRange string `json:"vulnerable_version_range"`
		} `json:"vulnerabilities"`
	}
	if err := enrichGetJSON(ctx, "GitHub Advisory", u, enrichTimeoutGHSA, &resp); err != nil {
		if err == errEnrichNotFound {
			return nil, nil
		}
		return nil, err
	}
	if len(resp) == 0 {
		return nil, nil
	}
	a := resp[0]
	out := &enrichGHSA{
		Summary:  a.Summary,
		Severity: strings.ToLower(a.Severity),
		Score:    a.Cvss.Score,
		Vector:   a.Cvss.VectorString,
		Refs:     a.References,
	}
	for _, v := range a.Vulnerabilities {
		product := v.Package.Ecosystem
		if v.Package.Name != "" {
			if product != "" {
				product += "/" + v.Package.Name
			} else {
				product = v.Package.Name
			}
		}
		out.Vuls = append(out.Vuls, cveEnrichAffected{
			Source:       "github-advisory",
			Product:      product,
			VersionRange: v.VulnerableVersionRange,
		})
	}
	return out, nil
}

// enrichFetchEPSS 查 FIRST.org EPSS 分数（0-1）。取不到返回 (nil, nil)——该字段
// 本来就是尽力而为。
func enrichFetchEPSS(ctx context.Context, cveID string) (*float64, error) {
	u := enrichEnvURL(envEnrichEPSSURL, enrichEPSSURLDef) + "?cve=" + cveID
	var resp struct {
		Data []struct {
			Cve  string  `json:"cve"`
			Epss float64 `json:"epss"`
		} `json:"data"`
	}
	if err := enrichGetJSON(ctx, "EPSS", u, enrichTimeoutEPSS, &resp); err != nil {
		return nil, err
	}
	for _, d := range resp.Data {
		if strings.EqualFold(d.Cve, cveID) {
			v := d.Epss
			return &v, nil
		}
	}
	return nil, nil
}

// ---------- 解析与合并 ----------

// cvssLevel 由 CVSS 分数推导等级（NVD 口径）。
func cvssLevel(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	default:
		return "low"
	}
}

// cvssVectorPreconditions 从 CVSS 向量解析利用前置（最可靠的结构化来源）：
// AV → 网络位置，PR → 所需权限（作为「是否需认证」的近似：PR:N 无需任何凭据），
// UI → 用户交互。向量缺字段或无法解析时 ok=false，调用方回落描述关键词解析。
func cvssVectorPreconditions(vector string) (*cveEnrichPreconditions, bool) {
	if !strings.Contains(vector, "/") {
		return nil, false
	}
	pre := &cveEnrichPreconditions{Auth: "unknown", Network: "unknown", UserInteraction: "unknown"}
	seen := false
	for _, seg := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(seg, ":")
		if !ok {
			continue
		}
		switch k {
		case "AV":
			switch v {
			case "N":
				pre.Network = "remote"
			case "A":
				pre.Network = "adjacent"
			case "L", "P":
				pre.Network = "local"
			}
		case "PR":
			switch v {
			case "N":
				pre.Auth = "none"
			case "L":
				pre.Auth = "low"
			case "H":
				pre.Auth = "high"
			}
		case "UI":
			switch v {
			case "N":
				pre.UserInteraction = "none"
			case "R":
				pre.UserInteraction = "required"
			}
		default:
			continue
		}
		seen = true
	}
	if !seen {
		return nil, false
	}
	pre.Evidence = "CVSS 向量 " + vector + "（PR 近似认证要求）"
	return pre, true
}

// 描述关键词解析（无 CVSS 向量时的回落）。中英文常见表述，宁缺毋滥：命不中就 unknown。
var (
	reAuthNoneDesc = regexp.MustCompile(`(?i)unauthenticated|without authentication|pre-?auth|no authentication|无需认证|未授权|匿名`)
	reAuthHighDesc = regexp.MustCompile(`(?i)administrator|admin privileges|root privileges|管理员权限`)
	reAuthLowDesc  = regexp.MustCompile(`(?i)authenticated|requires authentication|valid user|logged[- ]?in|登录后|认证后|经过认证`)
	reNetRemote    = regexp.MustCompile(`(?i)\bremote(?:ly)?\b|over the (?:internet|network)|远程`)
	reNetLocal     = regexp.MustCompile(`(?i)\blocal(?:ly)?\b|requires local|本地`)
)

func descriptionPreconditions(desc string) *cveEnrichPreconditions {
	pre := &cveEnrichPreconditions{Auth: "unknown", Network: "unknown", UserInteraction: "unknown"}
	l := strings.ToLower(desc)
	var ev []string
	if reAuthNoneDesc.MatchString(l) {
		pre.Auth = "none"
		ev = append(ev, "描述: 无需认证")
	} else if reAuthHighDesc.MatchString(l) {
		pre.Auth = "high"
		ev = append(ev, "描述: 需管理员权限")
	} else if reAuthLowDesc.MatchString(l) {
		pre.Auth = "low"
		ev = append(ev, "描述: 需认证/登录")
	}
	if reNetLocal.MatchString(l) {
		pre.Network = "local"
		ev = append(ev, "描述: 本地利用")
	} else if reNetRemote.MatchString(l) {
		pre.Network = "remote"
		ev = append(ev, "描述: 可远程利用")
	}
	pre.Evidence = strings.Join(ev, "; ")
	return pre
}

// PoC 链接启发式评分：>0 视为公开 PoC。NVD 的 Exploit 标签是权威信号直接封顶；
// 其余按 URL 特征打分（exploit-db > github PoC 仓库 > gist/raw > 泛 poc 关键词）。
var (
	rePocRepoSignal = regexp.MustCompile(`(?i)poc|exploit|cve-\d{4}`)
	rePocDescSignal = regexp.MustCompile(`(?i)poc|proof[-_ ]?of[-_ ]?concept|exploit`)
)

func enrichPocScore(u string, exploitTagged bool) int {
	score := 0
	if exploitTagged {
		score += 100
	}
	lu := strings.ToLower(u)
	switch {
	case strings.Contains(lu, "exploit-db.com"):
		score += 90
	case strings.Contains(lu, "packetstormsecurity.com"), strings.Contains(lu, "metasploit"):
		score += 80
	case strings.Contains(lu, "raw.githubusercontent.com"), strings.Contains(lu, "gist.github.com"):
		score += 50
	case strings.Contains(lu, "github.com/"):
		if strings.Contains(lu, "github.com/advisories/") {
			break // 公告页不是 PoC 仓库
		}
		score += 40
		if rePocRepoSignal.MatchString(u) {
			score += 30
		}
	case rePocDescSignal.MatchString(lu):
		score += 30
	}
	return score
}

// collectPoc 从 NVD 引用与 GHSA 引用里筛 PoC 链接（去重、按可信度选 best）。
func collectPoc(nvd *enrichNVD, ghsa *enrichGHSA) cveEnrichPoc {
	type cand struct {
		url   string
		score int
	}
	var list []cand
	seen := map[string]bool{}
	add := func(u string, score int) {
		if score <= 0 || u == "" || seen[u] {
			return
		}
		seen[u] = true
		list = append(list, cand{u, score})
	}
	if nvd != nil {
		for _, r := range nvd.Refs {
			add(r.URL, enrichPocScore(r.URL, r.ExploitTag))
		}
	}
	if ghsa != nil {
		for _, u := range ghsa.Refs {
			add(u, enrichPocScore(u, false))
		}
	}
	out := cveEnrichPoc{Sources: []string{}}
	// best 取分数最高（并列取先出现，遍历顺序固定：NVD 引用在前，保持确定性）。
	bestIdx := -1
	for i, c := range list {
		if bestIdx < 0 || c.score > list[bestIdx].score {
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		out.Best = list[bestIdx].url
	}
	out.Count = len(list)
	for _, c := range list {
		if len(out.Sources) >= enrichPocSourcesMax {
			break
		}
		out.Sources = append(out.Sources, c.url)
	}
	return out
}

// buildCveEnrichVerdict 按固定规则打 P0-P4（口径见 docs/CVE富化工具.md，测试锁定）：
//
//	P0  在 CISA KEV 在野利用清单
//	P1  CVSS≥9，或 CVSS≥7 且有公开 PoC
//	P2  CVSS≥7，或有公开 PoC，或 EPSS≥0.5
//	P3  CVSS≥4
//	P4  其余（低危或数据不足）
func buildCveEnrichVerdict(kev bool, sev *cveEnrichSeverity, pocCount int, epss *float64) cveEnrichVerdict {
	score := 0.0
	if sev != nil {
		score = sev.Score
	}
	epssV := 0.0
	if epss != nil {
		epssV = *epss
	}
	var facts []string
	if kev {
		facts = append(facts, "在 CISA KEV 在野利用清单")
	}
	if sev != nil {
		facts = append(facts, fmt.Sprintf("CVSS %.1f(%s)", score, sev.Level))
	}
	if pocCount > 0 {
		facts = append(facts, fmt.Sprintf("公开 PoC %d 条", pocCount))
	}
	if epssV >= 0.5 {
		facts = append(facts, fmt.Sprintf("EPSS %.2f", epssV))
	}
	priority := "P4"
	switch {
	case kev:
		priority = "P0"
	case score >= 9 || (score >= 7 && pocCount > 0):
		priority = "P1"
	case score >= 7 || pocCount > 0 || epssV >= 0.5:
		priority = "P2"
	case score >= 4:
		priority = "P3"
	}
	reason := strings.Join(facts, "；")
	if reason == "" {
		reason = "无 CVSS/KEV/PoC 数据，情报不足以升优先级，按默认低优先处理"
	}
	return cveEnrichVerdict{Priority: priority, Reason: reason}
}

// buildSuggestedVerify 推验证动作草案：有可信 PoC 且非纯本地利用 → run_poc 模板；
// 否则有影响区间 → version_check（指纹版本核对）；都推不出返回 nil。
func buildSuggestedVerify(poc cveEnrichPoc, pre *cveEnrichPreconditions, affected []cveEnrichAffected) *cveEnrichSuggestedVerify {
	network := "unknown"
	if pre != nil {
		network = pre.Network
	}
	if poc.Best != "" && network != "local" {
		auth := "unknown"
		if pre != nil {
			auth = pre.Auth
		}
		return &cveEnrichSuggestedVerify{
			Tool: "atomic_verify_poc",
			Mode: "run_poc",
			Draft: map[string]any{
				"poc_url": poc.Best,
				"target":  "<待填:目标资产地址>",
				"auth":    auth,
				"expect":  "<待填:PoC 成功特征(版本回显/回连/敏感数据回显)>",
			},
		}
	}
	if len(affected) > 0 && affected[0].Product != "" {
		return &cveEnrichSuggestedVerify{
			Tool: "atomic_verify_poc",
			Mode: "version_check",
			Draft: map[string]any{
				"component":                affected[0].Product,
				"vulnerable_version_range": affected[0].VersionRange,
				"expect":                   "目标资产指纹版本落在受影响区间",
			},
		}
	}
	return nil
}

// buildCveEnrichResult 合并各源贡献成标准化输出。字段优先级口径：
//   - title/summary: kt-vuln > NVD > GHSA
//   - severity: 有向量的优先（NVD > GHSA），kt-vuln 仅分数兜底
//   - kev: 任一源判 true 即 true；NVD/kt-vuln 任一可达即视为可判定（false 有效），
//     只有 KEV 能力源全挂才 unknown
//   - affected: kt-vuln 人工运营 > NVD CPE > GHSA 生态区间（截前 10 条）
func buildCveEnrichResult(cveID string, g *cveEnrichGather) *cveEnrichResult {
	res := &cveEnrichResult{
		CveID:    cveID,
		Affected: []cveEnrichAffected{},
		Poc:      cveEnrichPoc{Sources: []string{}},
	}

	// title / summary
	title := ""
	if g.focus != nil {
		title = vulnStr(g.focus.Title)
	}
	if title == "" && g.cat != nil {
		title = vulnStr(g.cat.Title)
	}
	desc := ""
	if g.nvd != nil {
		desc = g.nvd.Description
	}
	if desc == "" && g.ghsa != nil {
		desc = g.ghsa.Summary
	}
	if title == "" && g.ghsa != nil {
		title = g.ghsa.Summary
	}
	res.Title = title
	if len(desc) > enrichDescMax {
		desc = desc[:enrichDescMax] + "…"
	}
	res.Summary = desc

	// severity：有向量优先（可推前置），再比源优先级。
	switch {
	case g.nvd != nil && g.nvd.Vector != "":
		res.Severity = &cveEnrichSeverity{Score: g.nvd.Score, Vector: g.nvd.Vector, Level: g.nvd.Level, Source: "nvd"}
	case g.ghsa != nil && g.ghsa.Vector != "" && g.ghsa.Score != nil:
		res.Severity = &cveEnrichSeverity{Score: *g.ghsa.Score, Vector: g.ghsa.Vector, Level: g.ghsa.Severity, Source: "github-advisory"}
	case g.nvd != nil && g.nvd.Score > 0:
		res.Severity = &cveEnrichSeverity{Score: g.nvd.Score, Level: g.nvd.Level, Source: "nvd"}
	case g.ghsa != nil && g.ghsa.Score != nil:
		res.Severity = &cveEnrichSeverity{Score: *g.ghsa.Score, Level: g.ghsa.Severity, Source: "github-advisory"}
	default:
		var fs *float64
		if g.focus != nil {
			fs = g.focus.Severity
		}
		if fs == nil && g.cat != nil {
			fs = g.cat.Severity
		}
		if fs != nil {
			res.Severity = &cveEnrichSeverity{Score: *fs, Level: cvssLevel(*fs), Source: "kt-vuln"}
		}
	}

	// kev 三态：kt-vuln / NVD 都给不出判定才算 unknown。
	var kev *bool
	if g.focus != nil {
		kev = g.focus.Kev
	}
	if kev == nil && g.cat != nil {
		kev = g.cat.Kev
	}
	if g.nvd != nil {
		if g.nvd.CisaExploitAdd != "" {
			t := true
			kev = &t
		} else if kev == nil {
			f := false
			kev = &f
		}
	}
	if kev != nil {
		res.Kev = *kev
	} else {
		res.Kev = "unknown"
	}

	res.Epss = g.epss

	// affected：kt-vuln 人工运营在前。
	if g.focus != nil {
		for product, ranges := range g.focus.Affected {
			res.Affected = append(res.Affected, cveEnrichAffected{
				Source:       "kt-vuln",
				Product:      product,
				VersionRange: strings.Join(ranges, ", "),
			})
		}
	}
	if g.nvd != nil {
		res.Affected = append(res.Affected, g.nvd.CPEs...)
	}
	if g.ghsa != nil {
		res.Affected = append(res.Affected, g.ghsa.Vuls...)
	}
	if len(res.Affected) > enrichAffectedMax {
		res.Affected = res.Affected[:enrichAffectedMax]
	}

	res.Poc = collectPoc(g.nvd, g.ghsa)

	// preconditions：CVSS 向量优先，回落描述关键词。
	if res.Severity != nil && res.Severity.Vector != "" {
		if pre, ok := cvssVectorPreconditions(res.Severity.Vector); ok {
			res.Preconditions = pre
		}
	}
	if res.Preconditions == nil && res.Summary != "" {
		res.Preconditions = descriptionPreconditions(res.Summary)
	}

	// verdict + suggested_verify
	kevBool := false
	if b, ok := res.Kev.(bool); ok {
		kevBool = b
	}
	res.Verdict = buildCveEnrichVerdict(kevBool, res.Severity, res.Poc.Count, res.Epss)
	res.SuggestedVerify = buildSuggestedVerify(res.Poc, res.Preconditions, res.Affected)
	return res
}

// ---------- 工具实现 ----------

// toolVulnEnrichCve vuln_enrich_cve：单 CVE 多源情报富化 + P0-P4 打分。
func (s *Server) toolVulnEnrichCve() actool.CoreTool {
	desc := "CVE 情报富化（授权渗透平台）：输入一个 CVE 编号，一次调用聚合 kt-vuln/NVD/GitHub Advisory/EPSS 多源情报，" +
		"输出标准化画像与优先级结论，回答「这个 CVE 值不值得打」。判定打某目标资产上的 CVE 之前先调它拿依据，再用 vuln_search_assets 的 cve 参数找受影响资产。\n" +
		"输出字段：affected 影响组件与版本区间(指纹核对依据)、severity CVSS 分数与向量、kev 是否在 CISA KEV 在野利用清单(true/false/unknown)、" +
		"epss 利用概率分(0-1,取不到为 null)、poc 公开 PoC 数量/链接/最可用一条、preconditions 利用前置(auth 是否需认证/network 网络位置/user_interaction 用户交互，" +
		"CVSS 向量优先，推不出为 unknown)、suggested_verify 推荐验证动作草案(run_poc/version_check，推不出为 null)、verdict 优先级 P0(最优先)~P4 与一句话理由。\n" +
		"结果缓存 24 小时(PostgreSQL cve_enrich_cache)，重复查询直接回缓存；refresh=true 跳过缓存强制重新富化。"
	schema := objSchema(map[string]any{
		"cve_id":  strParam("CVE 编号，如 CVE-2023-46604（大小写不敏感）"),
		"refresh": map[string]any{"type": "boolean", "description": "跳过缓存强制重新富化，默认 false"},
	}, "cve_id")
	return roTool("vuln_enrich_cve", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			CveID   string `json:"cve_id"`
			Refresh bool   `json:"refresh"`
		}
		_ = json.Unmarshal(in, &a)
		cveID := strings.ToUpper(strings.TrimSpace(a.CveID))
		if !reCVEID.MatchString(cveID) {
			return actool.Errorf("cve_id 格式不合法（期望形如 CVE-2023-46604）: " + strings.TrimSpace(a.CveID)), nil
		}

		pg := s.enrichPG()
		ttl := enrichTTL()

		// 缓存命中直接回（读失败不阻塞富化）。
		if pg != nil && !a.Refresh {
			if row, err := pg.GetCVEEnrichCache(cveID); err == nil && row != nil {
				var cached cveEnrichResult
				if json.Unmarshal(row.Payload, &cached) == nil && cached.CveID == cveID {
					cached.Cache = &cveEnrichCacheInfo{
						Hit:       true,
						FetchedAt: row.FetchedAt.Format(time.RFC3339),
						ExpiresAt: row.ExpiresAt.Format(time.RFC3339),
					}
					return jsonResult(cached)
				}
			}
		}

		cctx, cancel := context.WithTimeout(ctx, enrichTimeoutTotal)
		defer cancel()
		res, srcs := s.fetchCveEnrichment(cctx, cveID)
		if res == nil {
			var parts []string
			for _, src := range srcs {
				p := src.Name + "=" + src.Status
				if src.Note != "" {
					p += "(" + src.Note + ")"
				}
				parts = append(parts, p)
			}
			return actool.Errorf("CVE 富化失败: " + cveID + "，所有数据源均未取得数据[" + strings.Join(parts, "; ") + "]；若各源均为 miss 可能是编号不存在，若为 error 请稍后重试或检查出网"), nil
		}

		if pg != nil {
			payload, err := json.Marshal(res) // Cache 字段此刻为空，落库不含缓存元信息
			if err == nil {
				if err := pg.SaveCVEEnrichCache(cveID, payload, ttl); err != nil {
					res.Sources = append(res.Sources, cveEnrichSourceReport{
						Name: "cache", Status: "error", Note: "缓存写入失败: " + err.Error(),
					})
				}
			}
			now := time.Now()
			res.Cache = &cveEnrichCacheInfo{
				Hit:       false,
				FetchedAt: now.Format(time.RFC3339),
				ExpiresAt: now.Add(ttl).Format(time.RFC3339),
			}
		}
		return jsonResult(res)
	})
}

// enrichPG 取富化缓存用的 PG 句柄；Server 未接 Manager（测试空壳）时返回 nil，
// 富化照常工作、只是不缓存。
func (s *Server) enrichPG() *pgdb.DB {
	if s == nil || s.m == nil {
		return nil
	}
	return s.m.pg
}

// enrichTTL 读缓存 TTL（env VULN_ENRICH_CACHE_TTL_HOURS，默认 24h；非法值回落默认）。
func enrichTTL() time.Duration {
	if v := strings.TrimSpace(os.Getenv(envEnrichTTLHours)); v != "" {
		if hours, err := strconv.Atoi(v); err == nil && hours > 0 && hours <= 24*30 {
			return time.Duration(hours) * time.Hour
		}
	}
	return enrichTTLDef
}

// fetchCveEnrichment 按优先级逐源抓取并合并。返回标准化结果与逐源状态；三大主源
// 全空时结果为 nil（状态照常返回，供错误信息逐源说明）。
func (s *Server) fetchCveEnrichment(ctx context.Context, cveID string) (*cveEnrichResult, []cveEnrichSourceReport) {
	g := &cveEnrichGather{}
	var sources []cveEnrichSourceReport

	// 1. 本地 kt-vuln（优先：关注清单带人工运营的 affected/kev，全量字典兜底存在性）。
	if vulnCredsMissing() {
		sources = append(sources, cveEnrichSourceReport{Name: "kt-vuln", Status: "skipped", Note: "服务账号 env 未配置"})
	} else {
		g.focus, g.cat = s.enrichFromKtVuln(ctx, cveID)
		if g.focus != nil || g.cat != nil {
			note := "全量字典"
			if g.focus != nil {
				note = "关注清单+全量字典"
			}
			sources = append(sources, cveEnrichSourceReport{Name: "kt-vuln", Status: "hit", Note: note})
		} else {
			sources = append(sources, cveEnrichSourceReport{Name: "kt-vuln", Status: "miss", Note: "关注清单与全量字典均未命中"})
		}
	}

	// 2. NVD。
	nvd, err := enrichFetchNVD(ctx, cveID)
	if err != nil {
		sources = append(sources, cveEnrichSourceReport{Name: "nvd", Status: "error", Note: err.Error()})
	} else if nvd != nil {
		g.nvd = nvd
		sources = append(sources, cveEnrichSourceReport{Name: "nvd", Status: "hit"})
	} else {
		sources = append(sources, cveEnrichSourceReport{Name: "nvd", Status: "miss", Note: "NVD 未收录"})
	}

	// 3. GitHub Advisory。
	ghsa, err := enrichFetchGHSA(ctx, cveID)
	if err != nil {
		sources = append(sources, cveEnrichSourceReport{Name: "github-advisory", Status: "error", Note: err.Error()})
	} else if ghsa != nil {
		g.ghsa = ghsa
		sources = append(sources, cveEnrichSourceReport{Name: "github-advisory", Status: "hit"})
	} else {
		sources = append(sources, cveEnrichSourceReport{Name: "github-advisory", Status: "miss", Note: "无对应 advisory"})
	}

	// 三大主源全空 → 结构化失败（含 EPSS 也不算数，EPSS 只是补充分）。
	if g.focus == nil && g.cat == nil && g.nvd == nil && g.ghsa == nil {
		return nil, sources
	}

	// 4. EPSS 尽力而为（失败不记 error，只在 note 里说明取不到）。
	epss, err := enrichFetchEPSS(ctx, cveID)
	if err == nil && epss != nil {
		g.epss = epss
		sources = append(sources, cveEnrichSourceReport{Name: "epss", Status: "hit"})
	} else {
		note := "无 EPSS 数据"
		if err != nil {
			note = "EPSS 获取失败: " + err.Error()
		}
		sources = append(sources, cveEnrichSourceReport{Name: "epss", Status: "miss", Note: note})
	}

	res := buildCveEnrichResult(cveID, g)
	res.Sources = sources
	return res, sources
}

// enrichFromKtVuln 查 kt-vuln 关注清单 + 全量字典，返回各自命中（可为 nil，nil）。
// 两个端点都失败时返回 (nil, nil)，失败细节由调用方按 miss 记录——关注清单只有
// 36 条、字典 28 万+，未命中与不可达对富化结果等价：该源无贡献。
func (s *Server) enrichFromKtVuln(ctx context.Context, cveID string) (*vulnFocusCve, *vulnCatalogItemRaw) {
	kctx, cancel := context.WithTimeout(ctx, enrichTimeoutKtVuln)
	defer cancel()

	var focusHit *vulnFocusCve
	var focus struct {
		Items []vulnFocusCve `json:"items"`
	}
	if err := vulnGet(kctx, "/api/cves", nil, &focus); err == nil {
		for i := range focus.Items {
			if focus.Items[i].CveID == cveID {
				focusHit = &focus.Items[i]
				break
			}
		}
	}

	var catHit *vulnCatalogItemRaw
	q := url.Values{}
	q.Set("q", cveID)
	q.Set("page_size", "5")
	var cat struct {
		Items []vulnCatalogItemRaw `json:"items"`
	}
	if err := vulnGet(kctx, "/api/cve-catalog", q, &cat); err == nil {
		for i := range cat.Items {
			if cat.Items[i].CveID == cveID {
				catHit = &cat.Items[i]
				break
			}
		}
	}
	return focusHit, catHit
}
