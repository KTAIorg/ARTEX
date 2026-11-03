package server

// vuln_enrich_cve 工具测试：全部走 httptest mock（不依赖真实外网）。外部源 URL
// 经 env（VULN_ENRICH_NVD_URL / VULN_ENRICH_GHSA_URL / VULN_ENRICH_EPSS_URL）注入，
// kt-vuln 侧复用 newVulnFakeAuth。缓存路径分两层测：无 PG（&Server{}，不缓存不
// panic）与有 PG（NewManager，命中/refresh/过期重取，无库自动 skip）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReCVEID(t *testing.T) {
	for in, ok := range map[string]bool{
		"CVE-2023-46604":  true,
		"CVE-1999-0001":   true,
		"CVE-2025-123456": true, // 新编号更长
		"cve-2023-46604":  false,
		"CVE-23-46604":    false,
		"CVE-2023-466":    false,
		"GHSA-xxxx":       false,
		"":                false,
	} {
		if got := reCVEID.MatchString(in); got != ok {
			t.Errorf("reCVEID(%q)=%v want %v", in, got, ok)
		}
	}
}

func TestCvssVectorPreconditions(t *testing.T) {
	pre, ok := cvssVectorPreconditions("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if !ok {
		t.Fatal("合法向量应解析成功")
	}
	if pre.Network != "remote" || pre.Auth != "none" || pre.UserInteraction != "none" {
		t.Errorf("AV:N/PR:N/UI:N 解析错误: %+v", pre)
	}

	pre, ok = cvssVectorPreconditions("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H")
	if !ok {
		t.Fatal("合法向量应解析成功")
	}
	if pre.Network != "local" || pre.Auth != "high" || pre.UserInteraction != "required" {
		t.Errorf("AV:L/PR:H/UI:R 解析错误: %+v", pre)
	}

	pre, ok = cvssVectorPreconditions("CVSS:3.1/AV:A/AC:L/PR:L/UI:N")
	if !ok || pre.Network != "adjacent" || pre.Auth != "low" {
		t.Errorf("AV:A/PR:L 解析错误: %+v ok=%v", pre, ok)
	}

	if _, ok := cvssVectorPreconditions("not-a-vector"); ok {
		t.Error("非法向量应解析失败")
	}
	if _, ok := cvssVectorPreconditions(""); ok {
		t.Error("空向量应解析失败")
	}
}

func TestDescriptionPreconditions(t *testing.T) {
	pre := descriptionPreconditions("The application allows unauthenticated remote attackers to execute arbitrary code.")
	if pre.Auth != "none" || pre.Network != "remote" {
		t.Errorf("无需认证+远程 解析错误: %+v", pre)
	}

	pre = descriptionPreconditions("Requires an authenticated user with administrator privileges.")
	if pre.Auth != "high" {
		t.Errorf("需管理员 解析错误: %+v", pre)
	}
	if pre.Network != "unknown" {
		t.Errorf("无网络线索应为 unknown: %+v", pre)
	}

	pre = descriptionPreconditions("An unspecified local issue.")
	if pre.Network != "local" || pre.Auth != "unknown" {
		t.Errorf("本地+认证不明 解析错误: %+v", pre)
	}

	pre = descriptionPreconditions("Something happened.")
	if pre.Auth != "unknown" || pre.Network != "unknown" || pre.UserInteraction != "unknown" {
		t.Errorf("无线索应全 unknown: %+v", pre)
	}
}

func TestEnrichPocScore(t *testing.T) {
	cases := map[string]int{
		"https://exploit-db.com/exploits/50768":           90,
		"https://github.com/user/CVE-2021-44228-poc":      70,
		"https://github.com/user/repo":                    40,
		"https://github.com/advisories/GHSA-7hhh-8g9g":    0,
		"https://nvd.nist.gov/vuln/detail/CVE-2021-44228": 0,
		"https://www.apache.org/security/log4j2.html":     0,
		"https://gist.github.com/user/abc123":             50,
	}
	for u, want := range cases {
		if got := enrichPocScore(u, false); got != want {
			t.Errorf("enrichPocScore(%q)=%d want %d", u, got, want)
		}
	}
	if got := enrichPocScore("https://nvd.nist.gov/vuln/detail/CVE-1", true); got < 100 {
		t.Errorf("Exploit 标签应封顶: %d", got)
	}
}

func TestCollectPoc(t *testing.T) {
	nvd := &enrichNVD{Refs: []struct {
		URL        string
		ExploitTag bool
	}{
		{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228", false},
		{"https://github.com/user/log4shell-exploit", true},
	}}
	ghsa := &enrichGHSA{Refs: []string{
		"https://github.com/advisories/GHSA-7hhh",
		"https://github.com/user/log4shell-exploit", // 与 NVD 重复，应去重
		"https://example.com/advisory",
	}}
	poc := collectPoc(nvd, ghsa)
	if poc.Count != 1 {
		t.Errorf("去重后应只有 1 条 PoC: %+v", poc)
	}
	if poc.Best != "https://github.com/user/log4shell-exploit" {
		t.Errorf("best 应是 Exploit 标签链接: %s", poc.Best)
	}
	if poc := collectPoc(nil, nil); poc.Count != 0 || poc.Best != "" || poc.Sources == nil {
		t.Errorf("空输入应返回零值: %+v", poc)
	}
}

func TestBuildCveEnrichVerdict(t *testing.T) {
	ten, epssHigh := 10.0, 0.6
	cases := []struct {
		name string
		kev  bool
		sev  *cveEnrichSeverity
		poc  int
		epss *float64
		want string
	}{
		{"kev 一票封顶", true, &cveEnrichSeverity{Score: 3.1, Level: "low"}, 0, nil, "P0"},
		{"cvss>=9", false, &cveEnrichSeverity{Score: ten, Level: "critical"}, 0, nil, "P1"},
		{"cvss>=7 且有 poc", false, &cveEnrichSeverity{Score: 7.5, Level: "high"}, 2, nil, "P1"},
		{"cvss>=7 无 poc", false, &cveEnrichSeverity{Score: 7.5, Level: "high"}, 0, nil, "P2"},
		{"仅 poc", false, nil, 1, nil, "P2"},
		{"仅 epss", false, nil, 0, &epssHigh, "P2"},
		{"cvss>=4", false, &cveEnrichSeverity{Score: 4.3, Level: "medium"}, 0, nil, "P3"},
		{"低危", false, &cveEnrichSeverity{Score: 3.1, Level: "low"}, 0, nil, "P4"},
		{"全无数据", false, nil, 0, nil, "P4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildCveEnrichVerdict(c.kev, c.sev, c.poc, c.epss).Priority; got != c.want {
				t.Errorf("priority=%s want %s", got, c.want)
			}
		})
	}
	kevReason := buildCveEnrichVerdict(true, &cveEnrichSeverity{Score: ten, Level: "critical"}, 1, nil)
	if !strings.Contains(kevReason.Reason, "KEV") || !strings.Contains(kevReason.Reason, "PoC") {
		t.Errorf("理由应包含关键事实: %s", kevReason.Reason)
	}
	if r := buildCveEnrichVerdict(false, nil, 0, nil).Reason; !strings.Contains(r, "情报不足") {
		t.Errorf("无数据理由应说明情报不足: %s", r)
	}
}

func TestEnrichNVDCPEAffected(t *testing.T) {
	c := enrichNVDCPE{
		Vulnerable:            true,
		Criteria:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
		VersionStartIncluding: "2.0-beta9",
		VersionEndExcluding:   "2.15.0",
	}
	a := c.affected()
	if a.Product != "apache:log4j" || a.VersionRange != ">= 2.0-beta9, < 2.15.0" || a.Source != "nvd" {
		t.Errorf("CPE 转换错误: %+v", a)
	}
}

// ---------- 工具级 E2E（mock 数据源） ----------

// newEnrichExternal 起三个外部源 mock（NVD/GHSA/EPSS），env 指到各自 URL，返回
// 各自的请求计数（供缓存命中断言）。handler 为 nil 表示该源不可达（关死的端口）。
func newEnrichExternal(t *testing.T, nvd, ghsa, epss http.HandlerFunc) (n, g, e *int32) {
	t.Helper()
	up := func(h http.HandlerFunc) (*httptest.Server, *int32) {
		var count int32
		if h == nil {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			srv.Close() // 立刻关闭 → 连接拒绝
			return srv, &count
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&count, 1)
			h(w, r)
		}))
		t.Cleanup(srv.Close)
		return srv, &count
	}
	nvdSrv, nvdCount := up(nvd)
	ghsaSrv, ghsaCount := up(ghsa)
	epssSrv, epssCount := up(epss)
	t.Setenv(envEnrichNVDURL, nvdSrv.URL)
	t.Setenv(envEnrichGHSAURL, ghsaSrv.URL)
	t.Setenv(envEnrichEPSSURL, epssSrv.URL)
	return nvdCount, ghsaCount, epssCount
}

// nvdPayload 是 CVE-2021-44228 风格的 NVD 响应（KEV 扩展字段 + 主 CVSS + CPE 区间
// + Exploit 标签引用）。
const nvdPayload = `{
"vulnerabilities":[{"cve":{
  "id":"CVE-2021-44228",
  "descriptions":[{"lang":"en","value":"Apache Log4j2 up to 2.14.1 JNDI features allow remote attackers to execute arbitrary code when log messages look up unauthenticated user-controlled data."}],
  "metrics":{"cvssMetricV31":[
    {"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","baseScore":10.0,"baseSeverity":"CRITICAL"}},
    {"source":"134.1.2.3","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":8.1,"baseSeverity":"HIGH"}}
  ]},
  "configurations":[{"nodes":[{"operator":"OR","cpeMatch":[
    {"vulnerable":true,"criteria":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0-beta9","versionEndExcluding":"2.15.0"},
    {"vulnerable":false,"criteria":"cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*"}
  ]}]}],
  "references":[
    {"url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228","tags":["Broken Link"]},
    {"url":"https://github.com/kozbin/log4shell-PoC","tags":["Exploit","Third Party Advisory"]}
  ],
  "cisaExploitAdd":"2021-12-10",
  "published":"2021-12-10T00:00:00.000"
}}],"resultsPerPage":1,"startIndex":0,"totalResults":1}`

const ghsaPayload = `[{
  "ghsa_id":"GHSA-jfh8-c2jp-5v3q",
  "cve_id":"CVE-2021-44228",
  "summary":"Remote code injection in Log4j",
  "severity":"critical",
  "cvss":{"score":10.0,"vector_string":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
  "references":["https://github.com/advisories/GHSA-jfh8-c2jp-5v3q","https://github.com/kozbin/log4shell-PoC"],
  "vulnerabilities":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"vulnerable_version_range":"= 2.0","first_patched_version":{"identifier":"2.15.0"}}]
}]`

const epssPayload = `{"data":[{"cve":"CVE-2021-44228","epss":0.97702,"percentile":0.99987}]}`

// enrichCall 调工具并把 JSON 输出解回结果结构。
func enrichCall(t *testing.T, s *Server, input map[string]any) (cveEnrichResult, string) {
	t.Helper()
	out := vulnToolCall(t, s.toolVulnEnrichCve(), input)
	var res cveEnrichResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("输出不是合法 JSON: %v\n%s", err, out)
	}
	return res, out
}

func TestToolVulnEnrichCveFullPipeline(t *testing.T) {
	vulnTokenReset()
	newVulnFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/cves":
			_, _ = w.Write([]byte(`{"items":[{"cve_id":"CVE-2021-44228","title":"Log4Shell JNDI RCE",
				"severity":10,"kev":true,"affected":{"log4j-core":["2.0-beta9 - 2.14.1"]}}]}`))
		case "/api/cve-catalog":
			_, _ = w.Write([]byte(`{"items":[{"cve_id":"CVE-2021-44228","title":"Log4Shell JNDI RCE",
				"severity":10,"kev":true,"source":"nvd"}],"total":1}`))
		default:
			t.Errorf("意外路径: %s", r.URL.Path)
		}
	})
	newEnrichExternal(t,
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("cveId") != "CVE-2021-44228" {
				t.Errorf("cveId 参数异常: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(nvdPayload))
		},
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("cve_id") != "CVE-2021-44228" {
				t.Errorf("cve_id 参数异常: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(ghsaPayload))
		},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(epssPayload))
		},
	)

	// 无 Manager（无缓存路径），小写输入验证归一化。
	res, _ := enrichCall(t, &Server{}, map[string]any{"cve_id": "cve-2021-44228"})
	if res.CveID != "CVE-2021-44228" {
		t.Errorf("cve_id 未归一化为大写: %s", res.CveID)
	}

	// 逐字段断言
	if res.Severity == nil || res.Severity.Score != 10.0 || res.Severity.Source != "nvd" ||
		!strings.HasPrefix(res.Severity.Vector, "CVSS:3.1/AV:N") || res.Severity.Level != "critical" {
		t.Errorf("severity 应取 NVD Primary(10.0, 向量, critical): %+v", res.Severity)
	}
	if res.Kev != true {
		t.Errorf("kev 应为 true: %v", res.Kev)
	}
	if res.Epss == nil || *res.Epss < 0.97 || *res.Epss > 0.98 {
		t.Errorf("epss 应为 0.977: %v", res.Epss)
	}
	if res.Poc.Count != 1 || res.Poc.Best != "https://github.com/kozbin/log4shell-PoC" {
		t.Errorf("poc 应去重后 1 条且 best 是 Exploit 标签仓库: %+v", res.Poc)
	}
	if res.Preconditions == nil || res.Preconditions.Auth != "none" ||
		res.Preconditions.Network != "remote" || res.Preconditions.UserInteraction != "none" {
		t.Errorf("preconditions 应从 CVSS 向量解析 AV:N/PR:N/UI:N: %+v", res.Preconditions)
	}
	// affected: kt-vuln 人工运营在前 + NVD CPE + GHSA 生态区间。
	if len(res.Affected) != 3 {
		t.Fatalf("affected 应有 3 条(kt-vuln/nvd/ghsa): %+v", res.Affected)
	}
	if res.Affected[0].Source != "kt-vuln" || res.Affected[0].Product != "log4j-core" ||
		res.Affected[0].VersionRange != "2.0-beta9 - 2.14.1" {
		t.Errorf("kt-vuln affected 应排最前: %+v", res.Affected[0])
	}
	if res.Affected[1].Source != "nvd" || res.Affected[1].Product != "apache:log4j" ||
		res.Affected[1].VersionRange != ">= 2.0-beta9, < 2.15.0" || res.Affected[1].CPE == "" {
		t.Errorf("nvd CPE affected 解析错误: %+v", res.Affected[1])
	}
	if res.Affected[2].Source != "github-advisory" || res.Affected[2].Product != "Maven/org.apache.logging.log4j:log4j-core" {
		t.Errorf("ghsa affected 解析错误: %+v", res.Affected[2])
	}
	if res.Verdict.Priority != "P0" || !strings.Contains(res.Verdict.Reason, "KEV") {
		t.Errorf("KEV 应判 P0: %+v", res.Verdict)
	}
	if res.SuggestedVerify == nil || res.SuggestedVerify.Mode != "run_poc" ||
		res.SuggestedVerify.Draft["poc_url"] != "https://github.com/kozbin/log4shell-PoC" {
		t.Errorf("suggested_verify 应是 run_poc 草案: %+v", res.SuggestedVerify)
	}
	if res.Cache != nil {
		t.Errorf("无 PG 不应有缓存元信息: %+v", res.Cache)
	}
	// 4 源全 hit
	for _, src := range res.Sources {
		if src.Status != "hit" {
			t.Errorf("源 %s 状态应 hit: %+v", src.Name, src)
		}
	}
}

func TestToolVulnEnrichCveDegrade(t *testing.T) {
	vulnTokenReset()
	// kt-vuln 服务账号未配 → skipped 降级；NVD 500 → error 降级；GHSA 独撑；
	// EPSS 不可达 → miss 降级（epss=null）。
	t.Setenv(envVulnUser, "")
	t.Setenv(envVulnPass, "")
	newEnrichExternal(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message":"rate limited"}`))
		},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`[{
				"ghsa_id":"GHSA-xxxx","cve_id":"CVE-2020-1382",
				"summary":"Authentication bypass requires an authenticated administrator session to execute arbitrary commands.",
				"severity":"high",
				"cvss":{"score":8.8,"vector_string":"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"},
				"references":["https://www.exploit-db.com/exploits/48170"],
				"vulnerabilities":[{"package":{"ecosystem":"PIP","name":"product-x"},"vulnerable_version_range":"< 1.2.3"}]}]`))
		},
		nil, // EPSS 源关闭 → 连接拒绝
	)

	res, raw := enrichCall(t, &Server{}, map[string]any{"cve_id": "CVE-2020-1382"})
	if res.Severity == nil || res.Severity.Source != "github-advisory" || res.Severity.Score != 8.8 {
		t.Errorf("NVD 挂掉后 severity 应回落 GHSA: %+v", res.Severity)
	}
	if res.Kev != "unknown" {
		t.Errorf("KEV 能力源全不可达应为 unknown: %v", res.Kev)
	}
	if res.Epss != nil {
		t.Errorf("EPSS 不可达应为 null: %v", res.Epss)
	}
	if res.Preconditions == nil || res.Preconditions.Auth != "high" || res.Preconditions.Network != "remote" {
		t.Errorf("前置应从 GHSA 向量解析 PR:H/AV:N: %+v", res.Preconditions)
	}
	if res.Poc.Count != 1 || res.Poc.Best != "https://www.exploit-db.com/exploits/48170" {
		t.Errorf("exploit-db 引用应计为 PoC: %+v", res.Poc)
	}
	// 8.8 < 9 但「CVSS≥7 且有公开 PoC」→ P1
	if res.Verdict.Priority != "P1" {
		t.Errorf("8.8+PoC 应判 P1: %+v", res.Verdict)
	}
	// 源状态：kt-vuln=skipped, nvd=error, github-advisory=hit, epss≠hit
	status := map[string]string{}
	for _, s := range res.Sources {
		status[s.Name] = s.Status
	}
	if status["kt-vuln"] != "skipped" || status["nvd"] != "error" || status["github-advisory"] != "hit" {
		t.Errorf("逐源状态异常: %v (raw=%s)", status, raw)
	}
	if status["epss"] == "hit" {
		t.Errorf("epss 不应 hit: %v", status)
	}
	// NVD 挂掉时 summary 回落 GHSA summary。
	if !strings.Contains(res.Summary, "administrator") {
		t.Errorf("summary 应回落 GHSA summary: %q", res.Summary)
	}
}

func TestToolVulnEnrichCveAllDown(t *testing.T) {
	vulnTokenReset()
	t.Setenv(envVulnUser, "")
	t.Setenv(envVulnPass, "")
	newEnrichExternal(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) },
		nil,
	)
	out := vulnToolCall(t, (&Server{}).toolVulnEnrichCve(), map[string]any{"cve_id": "CVE-2030-0001"})
	for _, want := range []string{"CVE 富化失败", "nvd=error", "github-advisory=miss", "kt-vuln=skipped"} {
		if !strings.Contains(out, want) {
			t.Errorf("结构化错误缺少 %s: %s", want, out)
		}
	}
}

func TestToolVulnEnrichCveBadInput(t *testing.T) {
	out := vulnToolCall(t, (&Server{}).toolVulnEnrichCve(), map[string]any{"cve_id": "log4shell"})
	if !strings.Contains(out, "格式不合法") {
		t.Errorf("非法编号应报格式错误: %s", out)
	}
	out = vulnToolCall(t, (&Server{}).toolVulnEnrichCve(), map[string]any{"cve_id": ""})
	if !strings.Contains(out, "格式不合法") {
		t.Errorf("空编号应报格式错误: %s", out)
	}
}

func TestEnrichTTL(t *testing.T) {
	if got := enrichTTL(); got != enrichTTLDef {
		t.Errorf("默认 TTL 应为 %v: %v", enrichTTLDef, got)
	}
	t.Setenv(envEnrichTTLHours, "6")
	if got := enrichTTL(); got != 6*time.Hour {
		t.Errorf("env TTL 应为 6h: %v", got)
	}
	t.Setenv(envEnrichTTLHours, "-3")
	if got := enrichTTL(); got != enrichTTLDef {
		t.Errorf("非法 TTL 应回落默认: %v", got)
	}
}

// TestToolVulnEnrichCveCache 缓存三态：命中秒回（外部源零请求）、refresh 强制重取、
// 过期后重取。需要真实 PostgreSQL，无库自动 skip。
func TestToolVulnEnrichCveCache(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() }) // t.Cleanup LIFO：后注册的删缓存动作先于关库执行
	vulnTokenReset()
	t.Setenv(envVulnUser, "")
	t.Setenv(envVulnPass, "")

	const cveID = "CVE-2098-76543" // 测试专用编号，避免污染真实情报缓存
	t.Cleanup(func() { _ = m.pg.DeleteCVEEnrichCache(cveID) })

	nvdCount, ghsaCount, _ := newEnrichExternal(t,
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{
				"descriptions":[{"lang":"en","value":"Test CVE for cache."}],
				"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
				"references":[{"url":"https://github.com/user/x-poc","tags":["Exploit"]}]}}],"totalResults":1}`))
		},
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) },
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"data":[]}`)) },
	)
	s := &Server{m: m}

	// 1) 首次：miss → 富化 + 落缓存
	res, _ := enrichCall(t, s, map[string]any{"cve_id": cveID})
	if res.Cache == nil || res.Cache.Hit {
		t.Fatalf("首次查询应 cache.hit=false: %+v", res.Cache)
	}
	if atomic.LoadInt32(nvdCount) != 1 {
		t.Fatalf("首次应打一次 NVD: %d", *nvdCount)
	}

	// 2) 二次：命中缓存，外部源零请求（计数与首次持平）
	res, _ = enrichCall(t, s, map[string]any{"cve_id": cveID})
	if res.Cache == nil || !res.Cache.Hit {
		t.Fatalf("二次查询应命中缓存: %+v", res.Cache)
	}
	if res.Verdict.Priority != "P1" {
		t.Errorf("缓存回放应保留 verdict: %+v", res.Verdict)
	}
	if n, g := atomic.LoadInt32(nvdCount), atomic.LoadInt32(ghsaCount); n != 1 || g != 1 {
		t.Errorf("缓存命中后外部源计数不应增长: nvd=%d ghsa=%d", n, g)
	}

	// 3) refresh=true：跳过缓存强制重取
	res, _ = enrichCall(t, s, map[string]any{"cve_id": cveID, "refresh": true})
	if res.Cache == nil || res.Cache.Hit {
		t.Errorf("refresh 应重新富化: %+v", res.Cache)
	}
	if atomic.LoadInt32(nvdCount) != 2 {
		t.Errorf("refresh 后 NVD 应打到 2 次: %d", *nvdCount)
	}

	// 4) 过期：把 expires_at 拨到过去，重取
	if _, err := m.pg.Exec(`UPDATE cve_enrich_cache SET expires_at = now() - interval '1 hour' WHERE cve_id=$1`, cveID); err != nil {
		t.Fatalf("拨过期失败: %v", err)
	}
	res, _ = enrichCall(t, s, map[string]any{"cve_id": cveID})
	if res.Cache == nil || res.Cache.Hit {
		t.Errorf("过期后应重新富化: %+v", res.Cache)
	}
	if atomic.LoadInt32(nvdCount) != 3 {
		t.Errorf("过期后 NVD 应打到 3 次: %d", *nvdCount)
	}
}
