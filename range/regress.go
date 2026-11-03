package vrange

// 回归执行器：对每个 (EXP × 靶标) 组合，起靶标 → 指纹匹配 → 渲染并执行
// EXP 的 exec_template → 双 oracle 比对（EXP 自称的成功判据 + 靶标侧
// ground truth）→ Pass/Fail + 耗时。
//
// 为什么直接执行 HTTP 模板而不是包一层 atomic.Execute("atomic_verify_poc")：
// 闸门需要拿原始响应（状态码 + 响应体全文）分别喂给两个 oracle 求值，
// 而 atomic_verify_poc 只回命中片段；把 oracle 塞进 match_re 还会在
// 多状态码 / 关键字 AND 语义上有损。占位符渲染语义（{name} 从 params
// 取值、未取值原样保留）与 atomic 的 vpRender 保持一致。
//
// 全程纯 Go：httptest 起靶标（仅回环地址）、标准库发请求，无 docker、无外网。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	// rgTimeoutDef / rgTimeoutMax 单次执行模板请求的超时（与 atomic_verify_poc 对齐）。
	rgTimeoutDef  = 10000 * time.Millisecond
	rgTimeoutMax  = 60000 * time.Millisecond
	rgBodyLimit   = 1 << 20 // 判定最多读 1MB 响应体
	rgEvidenceMax = 400     // evidence 截断（rune 计，进报告/审计日志）
	rgMaxRedirect = 5       // PoC 语义跟随重定向
)

// rgPlaceholder 与 atomic 的占位符语法一致：{name}，name 为字母/数字/下划线。
var rgPlaceholder = regexp.MustCompile(`\{[A-Za-z0-9_]+\}`)

// httpExecTemplate 是 exec_template（kind=http）的结构化形态：与
// db.ExpAsset 既有约定（method/url/headers/body + {name} 占位符）对齐，
// 额外支持 auth_user/auth_pass（Basic 认证类 EXP 需要，语义同 atomic_verify_poc）。
type httpExecTemplate struct {
	Kind      string            `json:"kind"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	AuthUser  string            `json:"auth_user"`
	AuthPass  string            `json:"auth_pass"`
	TimeoutMS int               `json:"timeout_ms"`
}

// executeHTTPTemplate 渲染并执行一次 EXP 执行模板，返回原始响应（状态码 + 全文）。
// params 目前只注入 {"target": 靶标 BaseURL}——靶场语境下 EXP 模板约定写
// `{target}/path`（target 是完整基地址）。渲染后仍残留占位符 = 模板要了
// 靶场给不出的参数，直接判执行失败（留痕可见，便于发现参数缺口）。
func executeHTTPTemplate(ctx context.Context, raw json.RawMessage, params map[string]string) (status int, body string, err error) {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return 0, "", fmt.Errorf("exec_template 为空")
	}
	var t httpExecTemplate
	if err := json.Unmarshal(raw, &t); err != nil {
		return 0, "", fmt.Errorf("exec_template 不是合法 JSON: %w", err)
	}
	if t.Kind != "http" {
		// 靶场闸门当前只能验证 http 类 EXP；command/script 需要 docker 级靶标（遗留项）。
		return 0, "", fmt.Errorf("靶场执行器只支持 kind=http 的 exec_template，收到 %q", t.Kind)
	}
	url := strings.TrimSpace(renderTemplate(t.URL, params))
	if url == "" {
		return 0, "", fmt.Errorf("exec_template.url 为空")
	}
	if m := rgPlaceholder.FindString(url); m != "" {
		return 0, "", fmt.Errorf("exec_template.url 占位符 %s 未取值（靶场只注入 {target}）", m)
	}
	if !strings.Contains(url, "://") {
		url = "http://" + url // 渲染后拿到裸 host:port/path 时补 scheme
	}
	method := strings.ToUpper(strings.TrimSpace(t.Method))
	if method == "" {
		method = http.MethodGet
	}
	timeout := clampDuration(time.Duration(t.TimeoutMS)*time.Millisecond, rgTimeoutDef, rgTimeoutMax)

	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var bodyReader io.Reader
	if t.Body != "" {
		rendered := renderTemplate(t.Body, params)
		if m := rgPlaceholder.FindString(rendered); m != "" {
			return 0, "", fmt.Errorf("exec_template.body 占位符 %s 未取值（靶场只注入 {target}）", m)
		}
		bodyReader = strings.NewReader(rendered)
	}
	req, err := http.NewRequestWithContext(tctx, method, url, bodyReader)
	if err != nil {
		return 0, "", fmt.Errorf("构造请求失败: %w", err)
	}
	for k, v := range t.Headers {
		req.Header.Set(k, renderTemplate(v, params))
	}
	if t.AuthUser != "" || t.AuthPass != "" {
		req.SetBasicAuth(t.AuthUser, t.AuthPass)
	}
	req.Header.Set("User-Agent", "ARTEX-Range/1.0 (authorized-pentest)")

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= rgMaxRedirect {
				return fmt.Errorf("停止：已跟随 %d 次重定向", rgMaxRedirect)
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, rgBodyLimit))
	return resp.StatusCode, string(b), nil
}

// renderTemplate 把 {name} 替换成 params[name]，未命中原样保留（语义同
// atomic.vpRender；但 executeHTTPTemplate 会把渲染后残留的占位符升级为
// 显式错误——靶场不给含糊执行留口子）。
func renderTemplate(tmpl string, params map[string]string) string {
	if tmpl == "" || len(params) == 0 {
		return tmpl
	}
	return rgPlaceholder.ReplaceAllStringFunc(tmpl, func(s string) string {
		if v, ok := params[strings.Trim(s, "{}")]; ok {
			return v
		}
		return s
	})
}

// =====================================================================
// 回归报告
// =====================================================================

// CaseResult 是一个 (EXP × 靶标) 组合的判定结果。Pass 的充要条件：
// 指纹命中 ∧ 模板执行无错 ∧ EXP 判据命中 ∧ 靶标判据命中。
type CaseResult struct {
	ExpID   int64  `json:"exp_id"`
	ExpName string `json:"exp_name"`
	Target  string `json:"target"`

	// Applicable 指纹是否命中（EXP 声明适用于该靶标）。
	Applicable bool `json:"applicable"`
	// FPReason 指纹未命中原因（fingerprint_mismatch / version_mismatch /
	// 条件非法说明；命中为空）。指纹不命中不计 EXP 的罪状——EXP 本来就
	// 只服务特定指纹面，闸门只要求「至少一个靶标 Pass」。
	FPReason string `json:"fp_reason,omitempty"`

	Executed   bool   `json:"executed"`
	ExecError  string `json:"exec_error,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`

	// 双 oracle：EXP 自称的成功判据 + 靶标侧 ground truth，两者都要命中。
	// ExpOracleOK=false 而 TargetOracleOK=true → EXP 判据写错了（漏报真命中）；
	// 反之 → EXP 判据过松（打到任意页面就自称成功，误报假命中）。两种漂移
	// 都会让 EXP 库的命中率统计失真，闸门都要拦。
	ExpOracleOK      bool   `json:"exp_oracle_ok"`
	ExpOracleFail    string `json:"exp_oracle_fail,omitempty"`
	TargetOracleOK   bool   `json:"target_oracle_ok"`
	TargetOracleFail string `json:"target_oracle_fail,omitempty"`

	Pass       bool   `json:"pass"`
	DurationMS int64  `json:"duration_ms"`
	Evidence   string `json:"evidence"`
}

// ExpSummary 是一条 EXP 在整个靶标矩阵上的战绩（闸门决策的直接输入）。
type ExpSummary struct {
	ExpName string `json:"exp_name"`
	// Passed 通过的靶标（至少一个才放行入库）。
	Passed []string `json:"passed,omitempty"`
	// FailedApplicable 指纹命中但没打下来的靶标（EXP 的真失败）。
	FailedApplicable []string `json:"failed_applicable,omitempty"`
	// Mismatched 指纹不命中的靶标（不计罪状，仅留痕）。
	Mismatched []string `json:"mismatched,omitempty"`
}

// Report 是一次回归的全量结果（结构化，可直出 JSON 供看板/审计）。
type Report struct {
	StartedAt   time.Time `json:"started_at"`
	DurationMS  int64     `json:"duration_ms"`
	TotalExp    int       `json:"total_exp"`
	TotalTarget int       `json:"total_target"`

	Total            int `json:"total"`             // 组合总数
	Passed           int `json:"passed"`            // Pass 组合数
	FailedApplicable int `json:"failed_applicable"` // 指纹命中但失败的组合数
	FailedMismatch   int `json:"failed_mismatch"`   // 指纹不命中的组合数

	PerExp []*ExpSummary `json:"per_exp"`
	Cases  []CaseResult  `json:"cases"`
}

// RunRegression 对每个 (EXP × 靶标) 组合执行回归，产出全量报告。
// 纯 Go、仅回环流量；单组合失败不中断矩阵（闸门要看全貌再决策）。
func RunRegression(ctx context.Context, exps []*db.ExpAsset, targets []*VulnTarget) *Report {
	rep := &Report{
		StartedAt:   time.Now(),
		TotalExp:    len(exps),
		TotalTarget: len(targets),
		Total:       len(exps) * len(targets),
		PerExp:      []*ExpSummary{},
		Cases:       []CaseResult{},
	}
	defer func() { rep.DurationMS = time.Since(rep.StartedAt).Milliseconds() }()
	for _, e := range exps {
		sum := &ExpSummary{ExpName: e.Name}
		for _, t := range targets {
			c := runCase(ctx, e, t)
			rep.Cases = append(rep.Cases, *c)
			switch {
			case c.Pass:
				rep.Passed++
				sum.Passed = append(sum.Passed, c.Target)
			case c.Applicable:
				rep.FailedApplicable++
				sum.FailedApplicable = append(sum.FailedApplicable, c.Target)
			default:
				rep.FailedMismatch++
				sum.Mismatched = append(sum.Mismatched, c.Target)
			}
		}
		rep.PerExp = append(rep.PerExp, sum)
	}
	return rep
}

// runCase 跑一个组合：起靶标 → 指纹匹配 → 执行模板 → 双 oracle。
// 执行失败（error 语义）与「判定未命中」（未通过语义）分开记——报告里
// 都算 Fail，但原因可区分，对齐 atomic 的三态契约。
func runCase(ctx context.Context, e *db.ExpAsset, t *VulnTarget) *CaseResult {
	start := time.Now()
	c := &CaseResult{ExpID: e.ID, ExpName: e.Name, Target: t.Name}
	defer func() { c.DurationMS = time.Since(start).Milliseconds() }()

	inst, err := t.Start()
	if err != nil {
		c.ExecError = "靶标启动失败: " + err.Error()
		c.Evidence = c.ExecError
		return c
	}
	defer inst.Stop()

	// ① 指纹匹配：EXP 的 fingerprint_match 必须命中靶标资产指纹。
	fp, err := db.ParseExpFingerprint(e.FP)
	if err != nil {
		c.FPReason = "指纹条件非法: " + err.Error()
		c.Evidence = c.FPReason
		return c
	}
	asset := runtimeAssetFingerprint(t, inst.BaseURL)
	if ok, reason := db.MatchExpFingerprint(fp, asset); !ok {
		c.FPReason = reason
		c.Evidence = "指纹未命中 " + t.Component + " " + t.Version + "：" + reason
		return c
	}
	c.Applicable = true

	// ② 执行 EXP 模板（{target} = 靶标基地址）。
	status, body, err := executeHTTPTemplate(ctx, e.Exec, map[string]string{"target": inst.BaseURL})
	if err != nil {
		c.ExecError = err.Error()
		c.Evidence = "执行失败：" + c.ExecError
		return c
	}
	c.Executed = true
	c.HTTPStatus = status

	// ③ EXP 自称的成功判据。
	if spec, perr := parseOracle(e.Oracle); perr != nil {
		c.ExpOracleFail = perr.Error()
	} else if ok, why := spec.evaluate(status, body); !ok {
		c.ExpOracleFail = why
	} else {
		c.ExpOracleOK = true
	}
	// ④ 靶标侧 ground truth 判据（内置靶标定义保证合法；防御性记录失败）。
	if spec, perr := parseOracle(t.SuccessOracle); perr != nil {
		c.TargetOracleFail = perr.Error()
	} else if ok, why := spec.evaluate(status, body); !ok {
		c.TargetOracleFail = why
	} else {
		c.TargetOracleOK = true
	}

	c.Pass = c.Applicable && c.Executed && c.ExpOracleOK && c.TargetOracleOK
	c.Evidence = truncateRunes(c.buildEvidence(), rgEvidenceMax)
	return c
}

// buildEvidence 拼一句能进审计日志的判定依据。
func (c *CaseResult) buildEvidence() string {
	var b strings.Builder
	b.WriteString(c.Target)
	if c.Executed {
		b.WriteString(" ← HTTP ")
		b.WriteString(strconv.Itoa(c.HTTPStatus))
	}
	if c.ExecError != "" {
		b.WriteString(" 执行失败：")
		b.WriteString(c.ExecError)
		return b.String()
	}
	if c.FPReason != "" {
		b.WriteString(" 指纹未命中：")
		b.WriteString(c.FPReason)
		return b.String()
	}
	if !c.ExpOracleOK {
		b.WriteString(" EXP 判据未命中（")
		b.WriteString(c.ExpOracleFail)
		b.WriteString("）")
	}
	if !c.TargetOracleOK {
		b.WriteString(" 靶标判据未命中（")
		b.WriteString(c.TargetOracleFail)
		b.WriteString("）")
	}
	if c.Pass {
		b.WriteString(" 双判据命中，Pass")
	}
	return b.String()
}

// runtimeAssetFingerprint 把靶标静态指纹合并运行实例 URL，得到匹配用的
// 资产指纹（EXP 的 paths 维度条件因此可用；静态指纹坏掉时退化为只有 URL
// 的稀疏指纹——匹配自然不命中，不会 panic）。
func runtimeAssetFingerprint(t *VulnTarget, baseURL string) *db.AssetFingerprint {
	af, err := db.ParseAssetFingerprint(t.Fingerprint)
	if err != nil || af == nil {
		af = &db.AssetFingerprint{}
	}
	af.URL = baseURL
	return af
}

// ---------- 小工具（包内自持，避免依赖 atomic 的未导出助手） ----------

func clampDuration(v, def, max time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
