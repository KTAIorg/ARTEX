// atomic_weak_cred：弱口令尝试（示范原子操作 #2）。
//
// 给定 service 类型 + 地址，用内置小字典（用户名 6 条 × 口令 12 条，均 <20）对授权
// 范围内的目标做弱口令尝试。支持 http_basic（标准库）与 ssh（golang.org/x/crypto/ssh，
// 仓库既有直接依赖，无新增）。Telnet 等明文协议刻意不做：现代目标占比低且实现易误判。
//
// 内置约束：单次尝试超时（默认 5s）、尝试间隔限速（默认 200ms）、尝试总数上限
// （默认 24、硬上限 64）——对目标友好是授权测试的义务，字典与上限都故意压小：
// 这一层修的是 P(执行无误)（确定性、可留痕地完成「试弱口令」这个动作），不是爆破。
package atomic

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func init() {
	desc := "弱口令尝试（授权渗透测试范围内的确定性动作）：用内置小字典(用户名 6×口令 12)对目标做" +
		"弱口令核验，支持 http_basic(HTTP Basic 认证)与 ssh。内置单次超时、尝试间隔限速与总次数上限(默认 24)。" +
		"输出统一契约 {ok, evidence, error, data}：ok=true 表示命中有效弱凭据(data 带 username/password)；" +
		"ok=false 且 error 为空表示字典试尽未命中；error 非空表示执行失败(不可达/参数非法)。"
	err := Register(Op{
		Key:         "atomic_weak_cred",
		Description: desc,
		InputSchema: objSchema(map[string]any{
			"service":      map[string]any{"type": "string", "enum": []string{"http_basic", "ssh"}, "description": "服务类型：http_basic(HTTP Basic) 或 ssh"},
			"target":       strParam("目标：http_basic 传完整 URL(如 http://1.2.3.4/admin/)或 host:port；ssh 传 host:port(缺端口默认 22)"),
			"usernames":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "覆盖默认用户名字典(≤8 条)"},
			"passwords":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "覆盖默认口令字典(≤16 条)"},
			"max_attempts": map[string]any{"type": "integer", "description": "尝试总数上限，默认 24、硬上限 64", "default": 24},
			"delay_ms":     map[string]any{"type": "integer", "description": "尝试间隔毫秒(限速)，默认 200、上限 2000，测试可传 0", "default": 200},
			"timeout_ms":   map[string]any{"type": "integer", "description": "单次尝试超时毫秒，默认 5000、上限 30000", "default": 5000},
		}, "service", "target"),
		OutputSchema: OutputSchema(map[string]any{
			"service": map[string]any{"type": "string"}, "target": map[string]any{"type": "string"},
			"found":    map[string]any{"type": "boolean"},
			"username": map[string]any{"type": "string", "description": "命中用户名(未命中为空)"},
			"password": map[string]any{"type": "string", "description": "命中口令(未命中为空)"},
			"attempts": map[string]any{"type": "integer", "description": "实际尝试次数"},
		}),
		Run: runWeakCred,
	})
	if err != nil {
		panic(err)
	}
}

// wcDefaults：内置小字典。仅用于授权渗透测试平台的目标核验；条目刻意压少（<20）。
var (
	wcUsernames = []string{"admin", "root", "test", "guest", "user", "system"}
	wcPasswords = []string{"admin", "admin123", "123456", "password", "root", "toor",
		"12345678", "admin@123", "P@ssw0rd", "88888888", "admin888", "666666"}
)

const (
	wcAttemptsDef = 24
	wcAttemptsMax = 64
	wcDelayDef    = 200 * time.Millisecond
	wcDelayMax    = 2000 * time.Millisecond
	wcTimeoutDef  = 5000 * time.Millisecond
	wcTimeoutMax  = 30000 * time.Millisecond
)

// wcCreds 是一次弱口令核验的输入汇总（归一后）。
type wcCreds struct {
	Service   string
	Target    string
	Usernames []string
	Passwords []string
	MaxTries  int
	Delay     time.Duration
	Timeout   time.Duration
}

// tryCred 对单个 (user, pass) 执行一次协议判定：返回是否为有效凭据。
type tryCred func(ctx context.Context, user, pass string) (bool, error)

func runWeakCred(ctx context.Context, in json.RawMessage) Result {
	var a struct {
		Service     string   `json:"service"`
		Target      string   `json:"target"`
		Usernames   []string `json:"usernames"`
		Passwords   []string `json:"passwords"`
		MaxAttempts int      `json:"max_attempts"`
		DelayMS     int      `json:"delay_ms"`
		TimeoutMS   int      `json:"timeout_ms"`
	}
	if err := decodeIn(in, &a); err != nil {
		return Fail(err)
	}
	a.Target = strings.TrimSpace(a.Target)
	if a.Target == "" {
		return Failf("target 不能为空")
	}

	var try tryCred
	switch a.Service {
	case "http_basic":
		u, err := wcNormalizeHTTP(a.Target)
		if err != nil {
			return Fail(err)
		}
		try = wcTryHTTPBasic(u)
	case "ssh":
		addr, err := wcNormalizeSSH(a.Target)
		if err != nil {
			return Fail(err)
		}
		try = wcTrySSH(addr)
	default:
		return Failf("service 需为 http_basic 或 ssh，收到 %q", a.Service)
	}

	// 字典：默认内置，调用方可覆盖（同样限量，防把原子操作当爆破机用）。
	users, passes := wcUsernames, wcPasswords
	if n := len(a.Usernames); n > 0 {
		if n > 8 {
			return Failf("usernames 最多 8 条，收到 %d", n)
		}
		users = a.Usernames
	}
	if n := len(a.Passwords); n > 0 {
		if n > 16 {
			return Failf("passwords 最多 16 条，收到 %d", n)
		}
		passes = a.Passwords
	}
	maxTries := clampInt(a.MaxAttempts, wcAttemptsDef, 0, wcAttemptsMax)
	delay := clampDur(time.Duration(a.DelayMS)*time.Millisecond, wcDelayDef, 0, wcDelayMax)
	timeout := clampDur(time.Duration(a.TimeoutMS)*time.Millisecond, wcTimeoutDef, 0, wcTimeoutMax)

	attempts := 0
	for _, u := range users {
		for _, p := range passes {
			if attempts >= maxTries {
				break
			}
			if attempts > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return Failf("已取消（尝试 %d 次）", attempts)
				}
			}
			if err := ctx.Err(); err != nil {
				return Failf("已取消（尝试 %d 次）", attempts)
			}
			attempts++
			ok, err := tryWithTimeout(ctx, timeout, try, u, p)
			if err != nil {
				// 连续网络失败：换下一个组合意义不大，直接判执行失败（区别于「未命中」）。
				return Failf("第 %d 次尝试(%s/%s)执行失败：%v", attempts, u, redact(p), err)
			}
			if ok {
				ev := fmt.Sprintf("%s %s 弱口令命中：%s/%s（第 %d 次尝试）", a.Service, a.Target, u, p, attempts)
				return OK(ev, map[string]any{
					"service": a.Service, "target": a.Target, "found": true,
					"username": u, "password": p, "attempts": attempts,
				})
			}
		}
		if attempts >= maxTries {
			break
		}
	}
	ev := fmt.Sprintf("%s %s 内置字典试尽（%d 次）未命中弱口令", a.Service, a.Target, attempts)
	return Result{OK: false, Evidence: ev, Data: map[string]any{
		"service": a.Service, "target": a.Target, "found": false,
		"username": "", "password": "", "attempts": attempts,
	}}
}

// tryWithTimeout 给单次尝试套独立超时（不占用外层 ctx 预算语义）。
func tryWithTimeout(ctx context.Context, timeout time.Duration, try tryCred, user, pass string) (bool, error) {
	if timeout <= 0 {
		return try(ctx, user, pass)
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return try(tctx, user, pass)
}

// ---------- http_basic ----------

// wcNormalizeHTTP：接受完整 URL 或 host:port（补 http:// 与 /）。
func wcNormalizeHTTP(target string) (string, error) {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", fmt.Errorf("无效 URL: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", fmt.Errorf("仅支持 http/https，收到 %q", u.Scheme)
		}
		return target, nil
	}
	return "http://" + target + "/", nil
}

// wcTryHTTPBasic：GET 目标 + Basic 凭据；判定 = 非 401/403（凭据被接受）。
// 注意语义边界：永远回 200 的开放端点会「命中任何凭据」，调用方应先 fingerprint
// 确认目标确有 Basic 质询（401）再对本操作下结论。
func wcTryHTTPBasic(rawURL string) tryCred {
	client := &http.Client{
		Timeout:       wcTimeoutDef,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return func(ctx context.Context, user, pass string) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return false, err
		}
		req.SetBasicAuth(user, pass)
		req.Header.Set("User-Agent", fpUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		return resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden, nil
	}
}

// ---------- ssh ----------

// wcNormalizeSSH：接受 host 或 host:port（缺省补 :22）。
func wcNormalizeSSH(target string) (string, error) {
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target, nil
	}
	if strings.Contains(target, ":") {
		return "", fmt.Errorf("无效的 host:port：%q", target)
	}
	return target + ":22", nil
}

// wcTrySSH：每次尝试新建连接做密码认证（目标侧的 MaxAuthTries 不会累积误伤）。
// 主机密钥不做校验：弱口令核验关心的是凭据，不是 MITM（授权测试语境下的既定取舍）。
func wcTrySSH(addr string) tryCred {
	return func(ctx context.Context, user, pass string) (bool, error) {
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return false, err
		}
		defer conn.Close()
		cfg := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.Password(pass)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         0, // 超时由 ctx 控制（tryWithTimeout 已包）
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
		if err != nil {
			// 认证失败在 ssh 协议里就是错误返回；只有「认证被拒」才视为「未命中」，
			// 其它错误（握手失败/网络断开）向上抛。
			if strings.Contains(err.Error(), "unable to authenticate") {
				return false, nil
			}
			return false, err
		}
		// 认证通过即命中：不需要开 session，立刻收尾。
		client := ssh.NewClient(c, chans, reqs)
		_ = client.Close()
		return true, nil
	}
}

// ---------- helpers ----------

// redact 把口令打成首字符 + ***（evidence 全文留痕，但 error 诊断信息适度脱敏）。
func redact(s string) string {
	if s == "" {
		return "***"
	}
	return s[:1] + "***"
}

func clampInt(v, def, min, max int) int {
	if v <= 0 {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func clampDur(v, def, min, max time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
