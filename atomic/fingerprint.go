// atomic_fingerprint：HTTP 指纹探测（示范原子操作 #1）。
//
// 给定 host:port（或完整 URL），用纯标准库探测 HTTP 指纹：根路径状态码、Server /
// X-Powered-By 响应头、<title>、以及一组常见路径（/robots.txt、/login、/admin）的
// 探测回包。修的是 P(指纹正确) 的数据采集环节——采集是确定性的，指纹归纳交给上层。
package atomic

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
)

func init() {
	desc := "HTTP 指纹探测（授权渗透测试范围内的确定性动作）：给定 host:port 或完整 URL，" +
		"探测根路径状态码、Server/X-Powered-By 头、页面标题，并探测常见路径(/robots.txt、/login、/admin)的回包。" +
		"纯标准库实现、不跟随重定向(记录 Location)。输出统一契约 {ok, evidence, error, data}，" +
		"data 含 status/server/title 与逐路径探测结果 paths[]。"
	err := Register(Op{
		Key:         "atomic_fingerprint",
		Description: desc,
		InputSchema: objSchema(map[string]any{
			"target":     strParam("目标 host:port（如 1.2.3.4:8080）或完整 URL（http(s)://...）；只有 host:port 时按端口猜 scheme"),
			"scheme":     map[string]any{"type": "string", "enum": []string{"auto", "http", "https"}, "description": "auto=智能猜测(443 端口先 https，其余先 http，失败换向重试一次)", "default": "auto"},
			"paths":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "附加探测路径(以 / 开头)，默认内置 /robots.txt /login /admin，最多 8 条"},
			"timeout_ms": map[string]any{"type": "integer", "description": "单请求超时毫秒，默认 5000，上限 30000", "default": 5000},
		}, "target"),
		OutputSchema: OutputSchema(map[string]any{
			"scheme":       map[string]any{"type": "string"},
			"host":         map[string]any{"type": "string"},
			"port":         map[string]any{"type": "integer"},
			"status":       map[string]any{"type": "integer"},
			"server":       map[string]any{"type": "string"},
			"x_powered_by": map[string]any{"type": "string"},
			"title":        map[string]any{"type": "string"},
			"paths":        map[string]any{"type": "array", "description": "逐路径探测结果 [{path,status,location,title,server}]"},
		}),
		Run: runFingerprint,
	})
	if err != nil {
		panic(err)
	}
}

const (
	fpUserAgent   = "ARTEX-Atomic/1.0 (authorized-pentest)"
	fpBodyLimit   = 64 << 10 // 标题提取只读前 64KB
	fpEvidenceMax = 400      // evidence 截断长度（rune 计）
	fpTitleMax    = 120
	fpMaxPaths    = 9 // 根路径 + 最多 8 条附加路径
)

var (
	fpTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	fpTagRe   = regexp.MustCompile(`(?s)<[^>]+>`)
)

// fpDefaultPaths：默认附加探测路径（常见指纹位）。
var fpDefaultPaths = []string{"/robots.txt", "/login", "/admin"}

// fpProbeResult 是单条路径的探测回包摘要（根路径也用它，path="/"）。
type fpProbeResult struct {
	Path       string `json:"path"`
	Status     int    `json:"status"`
	Location   string `json:"location,omitempty"`
	Title      string `json:"title,omitempty"`
	Server     string `json:"server,omitempty"`
	XPoweredBy string `json:"x_powered_by,omitempty"`
	Note       string `json:"note,omitempty"` // 请求失败原因（连接拒绝/超时等）
}

// fpProbe 是一次确定性 GET：不跟随重定向、限量读体、提取指纹要素。
func fpProbe(ctx context.Context, client *http.Client, rawURL, path string) fpProbeResult {
	res := fpProbeResult{Path: path}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		res.Note = "无效 URL: " + err.Error()
		return res
	}
	req.Header.Set("User-Agent", fpUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		res.Note = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, fpBodyLimit))
	res.Status = resp.StatusCode
	res.Location = resp.Header.Get("Location")
	res.Server = resp.Header.Get("Server")
	res.XPoweredBy = resp.Header.Get("X-Powered-By")
	res.Title = extractTitle(string(body))
	return res
}

// extractTitle 抽 <title> 文本：去标签、压空白、截断。
func extractTitle(body string) string {
	m := fpTitleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(fpTagRe.ReplaceAllString(m[1], "")), " ")
	return truncateRunes(t, fpTitleMax)
}

func runFingerprint(ctx context.Context, in json.RawMessage) Result {
	var a struct {
		Target    string   `json:"target"`
		Scheme    string   `json:"scheme"`
		Paths     []string `json:"paths"`
		TimeoutMS int      `json:"timeout_ms"`
	}
	if err := decodeIn(in, &a); err != nil {
		return Fail(err)
	}
	a.Target = strings.TrimSpace(a.Target)
	if a.Target == "" {
		return Failf("target 不能为空")
	}
	if a.TimeoutMS <= 0 {
		a.TimeoutMS = 5000
	}
	if a.TimeoutMS > 30000 {
		a.TimeoutMS = 30000
	}

	hostport, scheme, pathBase, err := fpNormalize(a.Target, a.Scheme)
	if err != nil {
		return Fail(err)
	}

	// 探测路径 = 根 + 默认三条 + 调用方补充，合并去重、限量。
	paths := append([]string{"/"}, fpDefaultPaths...)
	seen := map[string]bool{"/": true}
	for _, p := range a.Paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	if len(paths) > fpMaxPaths {
		paths = paths[:fpMaxPaths]
	}

	client := &http.Client{
		Timeout: time.Duration(a.TimeoutMS) * time.Millisecond,
		// 指纹探测不跟随重定向：3xx 本身就是指纹要素（记录 Location）。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// 根路径探测（auto 时按端口猜顺序，失败换向重试一次）。
	candidates := []string{scheme}
	if scheme == "auto" {
		if strings.HasSuffix(hostport, ":443") {
			candidates = []string{"https", "http"}
		} else {
			candidates = []string{"http", "https"}
		}
	}
	var root fpProbeResult
	var usedScheme, lastNote string
	for _, sc := range candidates {
		r := fpProbe(ctx, client, fmt.Sprintf("%s://%s%s", sc, hostport, pathBase), "/")
		if r.Status > 0 {
			root, usedScheme = r, sc
			break
		}
		lastNote = r.Note
	}
	if usedScheme == "" {
		return Failf("目标 %s 不可达（%s）", hostport, lastNote)
	}

	results := []fpProbeResult{root}
	for _, p := range paths[1:] { // 其余路径用已确认的 scheme
		results = append(results, fpProbe(ctx, client, fmt.Sprintf("%s://%s%s", usedScheme, hostport, p), p))
	}

	h, p := splitHostPort(hostport)
	data := map[string]any{
		"scheme": usedScheme, "host": h, "port": p,
		"status": root.Status, "server": root.Server, "x_powered_by": root.XPoweredBy,
		"title": root.Title, "paths": results,
	}

	var ev strings.Builder
	fmt.Fprintf(&ev, "%s://%s → HTTP %d", usedScheme, hostport, root.Status)
	if root.Server != "" {
		fmt.Fprintf(&ev, " | Server: %s", root.Server)
	}
	if root.XPoweredBy != "" {
		fmt.Fprintf(&ev, " | X-Powered-By: %s", root.XPoweredBy)
	}
	if root.Title != "" {
		fmt.Fprintf(&ev, " | title: %q", root.Title)
	}
	for _, r := range results[1:] {
		if r.Status > 0 {
			fmt.Fprintf(&ev, " | %s → %d", r.Path, r.Status)
		}
	}
	return OK(truncateRunes(ev.String(), fpEvidenceMax), data)
}

// fpNormalize 归一 target：返回 host:port、scheme（可能是 auto）、URL 路径前缀。
func fpNormalize(target, scheme string) (hostport, sc, pathBase string, err error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		scheme = "auto"
	}
	if scheme != "auto" && scheme != "http" && scheme != "https" {
		return "", "", "", fmt.Errorf("scheme 需为 auto/http/https")
	}
	if i := strings.Index(target, "://"); i >= 0 {
		us, rest := target[:i], target[i+3:]
		if us != "http" && us != "https" {
			return "", "", "", fmt.Errorf("仅支持 http/https 目标，收到 %q", us)
		}
		if scheme == "auto" {
			scheme = us
		}
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return rest[:slash], scheme, rest[slash:], nil
		}
		return rest, scheme, "/", nil
	}
	if strings.Contains(target, "/") {
		return "", "", "", fmt.Errorf("target 带 path 却没有 scheme，请给完整 URL")
	}
	return target, scheme, "/", nil
}

// splitHostPort 容错拆 host:port（无端口时默认 80）。
func splitHostPort(hostport string) (string, int) {
	h, p := hostport, 80
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		if v, err := strconv.Atoi(hostport[i+1:]); err == nil {
			h, p = hostport[:i], v
		}
	}
	return h, p
}

// truncateRunes 按 rune 截断（中文安全），超长补省略号。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
