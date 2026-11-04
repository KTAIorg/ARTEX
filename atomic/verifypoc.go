// atomic_verify_poc：PoC 验证执行器（示范原子操作 #3，EXP 执行器的雏形）。
//
// 给定一个 HTTP 请求模板（方法/路径/头/体）+ 成功判定正则，确定性执行一次并返回
// 是否命中。武器（payload/正则）由 LLM 或人编写，执行与判定在这一层——同样的请求
// 模板 + 同样的判定式，重复执行结论一致，这就是 P(执行无误) 的落点。
package atomic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func init() {
	desc := "PoC 验证执行器（授权渗透测试范围内的确定性动作，EXP 执行器雏形）：给定 HTTP 请求模板" +
		"(method/url/headers/body，支持 {name} 占位符从 params 取值)与成功判定正则 match_re(匹配响应体)，" +
		"执行一次并返回是否命中；可选 expect_status 精确校验状态码、auth_user/auth_pass 自动附带 Basic 认证。" +
		"输出统一契约 {ok, evidence, error, data}：ok=true 表示判定命中(evidence 带命中片段)；" +
		"ok=false 且 error 为空表示判定未命中；error 非空表示请求/参数层失败。"
	err := Register(Op{
		Key:         "atomic_verify_poc",
		Description: desc,
		InputSchema: objSchema(map[string]any{
			"method":        map[string]any{"type": "string", "description": "HTTP 方法，默认 GET", "default": "GET"},
			"url":           strParam("目标完整 URL（必填，支持 {name} 占位符）"),
			"headers":       map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "附加请求头（值支持 {name} 占位符）"},
			"body":          map[string]any{"type": "string", "description": "请求体（支持 {name} 占位符）"},
			"params":        map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "占位符取值表：url/headers/body 中的 {name} 会被替换"},
			"match_re":      strParam("成功判定正则（Go regexp 语法，匹配响应体；必填）"),
			"expect_status": map[string]any{"type": "integer", "description": "精确期望状态码（可选）；不填则只看正则命中"},
			"auth_user":     strParam("可选：Basic 认证用户名（与 auth_pass 成对出现时自动附 Authorization 头）"),
			"auth_pass":     strParam("可选：Basic 认证口令"),
			"timeout_ms":    map[string]any{"type": "integer", "description": "请求超时毫秒，默认 10000、上限 60000", "default": 10000},
		}, "url", "match_re"),
		OutputSchema: OutputSchema(map[string]any{
			"status":  map[string]any{"type": "integer"},
			"matched": map[string]any{"type": "string", "description": "正则命中的文本片段（截断）"},
			"reason":  map[string]any{"type": "string", "description": "判定说明（为什么命中/未命中）"},
		}),
		Run: runVerifyPoC,
	})
	if err != nil {
		panic(err)
	}
}

const (
	vpBodyLimit   = 1 << 20 // 响应体最多读 1MB 做判定
	vpMatchMax    = 200     // 命中片段截断（rune 计）
	vpTimeoutDef  = 10000 * time.Millisecond
	vpTimeoutMax  = 60000 * time.Millisecond
	vpMaxRedirect = 5 // PoC 语义跟随重定向（与指纹探测相反：这里要的是最终回包）
)

func runVerifyPoC(ctx context.Context, in json.RawMessage) Result {
	var a struct {
		Method       string            `json:"method"`
		URL          string            `json:"url"`
		Headers      map[string]string `json:"headers"`
		Body         string            `json:"body"`
		Params       map[string]string `json:"params"`
		MatchRe      string            `json:"match_re"`
		ExpectStatus int               `json:"expect_status"`
		AuthUser     string            `json:"auth_user"`
		AuthPass     string            `json:"auth_pass"`
		TimeoutMS    int               `json:"timeout_ms"`
	}
	if err := decodeIn(in, &a); err != nil {
		return Fail(err)
	}
	a.URL = strings.TrimSpace(vpRender(a.URL, a.Params))
	if a.URL == "" {
		return Failf("url 不能为空")
	}
	a.MatchRe = strings.TrimSpace(a.MatchRe)
	if a.MatchRe == "" {
		return Failf("match_re 不能为空")
	}
	re, err := regexp.Compile(a.MatchRe)
	if err != nil {
		return Failf("match_re 不是合法正则：%v", err)
	}
	method := strings.ToUpper(strings.TrimSpace(a.Method))
	if method == "" {
		method = http.MethodGet
	}
	timeout := clampDur(time.Duration(a.TimeoutMS)*time.Millisecond, vpTimeoutDef, 0, vpTimeoutMax)

	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var bodyReader io.Reader
	if a.Body != "" {
		bodyReader = strings.NewReader(vpRender(a.Body, a.Params))
	}
	req, err := http.NewRequestWithContext(tctx, method, a.URL, bodyReader)
	if err != nil {
		return Failf("构造请求失败：%v", err)
	}
	for k, v := range a.Headers {
		req.Header.Set(k, vpRender(v, a.Params))
	}
	if a.AuthUser != "" || a.AuthPass != "" {
		req.SetBasicAuth(a.AuthUser, a.AuthPass)
	}
	req.Header.Set("User-Agent", fpUserAgent)

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= vpMaxRedirect {
				return fmt.Errorf("停止：已跟随 %d 次重定向", vpMaxRedirect)
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return Failf("请求失败：%v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, vpBodyLimit))

	// 判定（确定性）：状态码（如指定）AND 正则命中响应体。
	if a.ExpectStatus != 0 && resp.StatusCode != a.ExpectStatus {
		return notHit(resp.StatusCode, fmt.Sprintf("状态码 %d ≠ 期望 %d", resp.StatusCode, a.ExpectStatus))
	}
	m := re.Find(body)
	if m == nil {
		return notHit(resp.StatusCode, fmt.Sprintf("正则 %q 未命中响应体（%d 字节）", a.MatchRe, len(body)))
	}
	snippet := truncateRunes(string(m), vpMatchMax)
	ev := fmt.Sprintf("HTTP %d，正则命中：%s", resp.StatusCode, snippet)
	return OK(ev, map[string]any{
		"status": resp.StatusCode, "matched": snippet,
		"reason": fmt.Sprintf("状态码 %d 且正则 %q 命中", resp.StatusCode, a.MatchRe),
	})
}

// notHit 构造「执行成功、判定未命中」的 Result（ok=false、error 空——三态契约）。
func notHit(status int, reason string) Result {
	ev := fmt.Sprintf("HTTP %d，判定未命中：%s", status, reason)
	return Result{OK: false, Evidence: ev, Data: map[string]any{
		"status": status, "matched": "", "reason": reason,
	}}
}

// vpRender 把模板里的 {name} 替换成 params[name]；未命中的占位符原样保留
// （留痕可见，便于发现漏传参数）。占位符名只匹配字母/数字/下划线。
var vpPlaceholder = regexp.MustCompile(`\{[A-Za-z0-9_]+\}`)

func vpRender(tmpl string, params map[string]string) string {
	if tmpl == "" || len(params) == 0 {
		return tmpl
	}
	return vpPlaceholder.ReplaceAllStringFunc(tmpl, func(s string) string {
		if v, ok := params[strings.Trim(s, "{}")]; ok {
			return v
		}
		return s
	})
}
