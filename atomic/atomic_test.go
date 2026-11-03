package atomic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// 本文件自测原子操作层。重点是用例 TestVerticalSliceNoLLM：在完全无 LLM 的前提下，
// 「指纹 → 弱口令 → PoC 验证」三步经注册表 Execute 串起来能跑通——这正是原子操作层
// 的存在意义（确定性动作不进 LLM 循环）。

// startMockTarget 起一个本地 mock 靶场（模拟授权测试范围内的目标）：
//   - /          200 管理台首页（Server 头 + title）
//   - /robots.txt 200
//   - /login     200
//   - /admin/    Basic 认证 admin/admin123 → 200 带旗标；否则 401
func startMockTarget(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "artex-mock/1.0")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><head><title>ARTEX 靶场管理台</title></head><body>index</body></html>")
		case "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin/\n")
		case "/login":
			fmt.Fprint(w, "<html><head><title>登录 - 靶场</title></head></html>")
		case "/echo":
			b, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "echo:%s", b)
		case "/admin":
			user, pass, ok := r.BasicAuth()
			if ok && user == "admin" && pass == "admin123" {
				fmt.Fprint(w, "admin console: flag{atomic-ok}")
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="admin"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "401 unauthorized")
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "404")
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func mustExec(t *testing.T, key string, in any) Result {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	res := Execute(context.Background(), key, b)
	if res.Evidence == "" {
		t.Fatalf("%s 返回空 evidence，违反输出契约", key)
	}
	return res
}

// asInt 兼容 int / int64 / float64 的数字断言（直接调用与 JSON 往返两种路径）。
func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return -1
}

func TestRegistry(t *testing.T) {
	// 三个示范操作在 init() 里注册完成。
	keys := []string{}
	for _, op := range List() {
		keys = append(keys, op.Key)
	}
	for _, want := range []string{"atomic_fingerprint", "atomic_verify_poc", "atomic_weak_cred"} {
		found := false
		for _, k := range keys {
			if k == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("List() 缺少 %s，现有 %v", want, keys)
		}
	}
	// List 按 key 排序。
	for i := 1; i < len(keys); i++ {
		if keys[i-1] >= keys[i] {
			t.Fatalf("List() 未按 key 排序: %v", keys)
		}
	}
	// 重复注册 / 非法 key / 缺 Run 都要拒绝。
	if err := Register(Op{Key: "atomic_fingerprint", Run: func(context.Context, json.RawMessage) Result { return Result{} }}); err == nil {
		t.Fatal("重复注册未报错")
	}
	if err := Register(Op{Key: "Bad-Key", Run: func(context.Context, json.RawMessage) Result { return Result{} }}); err == nil {
		t.Fatal("非法 key 未报错")
	}
	if err := Register(Op{Key: "zz_no_run", InputSchema: objSchema(nil)}); err == nil {
		t.Fatal("缺 Run 未报错")
	}
	// 未注册 key 的 Execute：返回错误 Result 而不是 panic。
	res := Execute(context.Background(), "no_such_op", nil)
	if res.OK || res.Error == "" {
		t.Fatalf("未注册操作应返回失败 Result，got %+v", res)
	}
}

func TestFingerprint(t *testing.T) {
	srv := startMockTarget(t)
	hostport := strings.TrimPrefix(srv.URL, "http://")

	res := mustExec(t, "atomic_fingerprint", map[string]any{"target": hostport})
	if !res.OK || res.Error != "" {
		t.Fatalf("指纹探测失败: %+v", res)
	}
	if res.Data["title"] != "ARTEX 靶场管理台" {
		t.Fatalf("title 指纹不符: %v", res.Data["title"])
	}
	if res.Data["server"] != "artex-mock/1.0" {
		t.Fatalf("server 指纹不符: %v", res.Data["server"])
	}
	paths, ok := res.Data["paths"].([]fpProbeResult)
	if !ok {
		t.Fatalf("paths 类型不符: %T", res.Data["paths"])
	}
	byPath := map[string]fpProbeResult{}
	for _, p := range paths {
		byPath[p.Path] = p
	}
	if byPath["/robots.txt"].Status != 200 || byPath["/login"].Status != 200 {
		t.Fatalf("常见路径探测不符: %+v", byPath)
	}
	if byPath["/admin"].Status != 401 {
		t.Fatalf("/admin 应为 401 质询: %+v", byPath["/admin"])
	}
	if !strings.Contains(res.Evidence, "artex-mock/1.0") {
		t.Fatalf("evidence 未包含 Server 指纹: %q", res.Evidence)
	}
}

// TestVerticalSliceNoLLM 是本任务的核心验收：指纹 → 弱口令 → PoC 验证 三步串联，
// 全程只经 atomic.Execute（无 LLM、无 DB、无外部网络），每步的输出喂给下一步。
func TestVerticalSliceNoLLM(t *testing.T) {
	srv := startMockTarget(t)

	// 第 1 步：指纹。确认这是活着的 HTTP 管理台，并从结果里取 host/port（下一步用）。
	fp := mustExec(t, "atomic_fingerprint", map[string]any{"target": srv.URL})
	if !fp.OK || fp.Error != "" {
		t.Fatalf("步骤1 指纹失败: %+v", fp)
	}
	host, _ := fp.Data["host"].(string)
	port := asInt(fp.Data["port"])
	if host == "" || port <= 0 {
		t.Fatalf("步骤1 未取到 host/port: %+v", fp.Data)
	}
	if asInt(fp.Data["status"]) != 200 {
		t.Fatalf("步骤1 根路径状态不符: %+v", fp.Data)
	}

	// 第 2 步：弱口令。指纹显示 /admin 有 Basic 质询 → 对它试内置小字典。
	adminURL := fmt.Sprintf("http://%s:%d/admin", host, port)
	wc := mustExec(t, "atomic_weak_cred", map[string]any{
		"service": "http_basic", "target": adminURL, "delay_ms": 0,
	})
	if !wc.OK || wc.Error != "" {
		t.Fatalf("步骤2 弱口令未命中: %+v", wc)
	}
	if wc.Data["username"] != "admin" || wc.Data["password"] != "admin123" {
		t.Fatalf("步骤2 命中凭据不符: %+v", wc.Data)
	}

	// 第 3 步：PoC 验证。用拿到的凭据访问受限页，正则判定旗标存在（EXP 执行器雏形）。
	vp := mustExec(t, "atomic_verify_poc", map[string]any{
		"url":       adminURL,
		"auth_user": wc.Data["username"], "auth_pass": wc.Data["password"],
		"match_re": `flag\{[^}]+\}`,
	})
	if !vp.OK || vp.Error != "" {
		t.Fatalf("步骤3 PoC 验证未命中: %+v", vp)
	}
	if !strings.Contains(vp.Data["matched"].(string), "flag{atomic-ok}") {
		t.Fatalf("步骤3 命中片段不符: %+v", vp.Data)
	}

	// 反向核对：错误凭据下同样的 PoC 应「未命中」（ok=false 且 error 为空——三态契约）。
	bad := mustExec(t, "atomic_verify_poc", map[string]any{
		"url": adminURL, "auth_user": "admin", "auth_pass": "wrong-pass",
		"match_re": `flag\{[^}]+\}`, "expect_status": 200,
	})
	if bad.OK || bad.Error != "" {
		t.Fatalf("错误凭据不应命中: %+v", bad)
	}
}

func TestWeakCredSSH(t *testing.T) {
	addr := startTestSSHServer(t)
	res := mustExec(t, "atomic_weak_cred", map[string]any{
		"service": "ssh", "target": addr, "delay_ms": 0,
	})
	if !res.OK || res.Error != "" {
		t.Fatalf("ssh 弱口令未命中: %+v", res)
	}
	if res.Data["username"] != "admin" || res.Data["password"] != "admin123" {
		t.Fatalf("ssh 命中凭据不符: %+v", res.Data)
	}
}

// startTestSSHServer 用 x/crypto/ssh 起一个最小 SSH 服务端（只做密码认证判定，
// 不接受任何 channel），密码只认 admin/admin123。
func startTestSSHServer(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if meta.User() == "admin" && string(pass) == "admin123" {
				return nil, nil
			}
			return nil, fmt.Errorf("凭据无效")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for range chans {
					// 弱口令核验只做认证，不开 channel。
				}
				sconn.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestVerifyPoCJudgments(t *testing.T) {
	srv := startMockTarget(t)
	// 非法正则 → 执行层失败（error 非空）。
	res := mustExec(t, "atomic_verify_poc", map[string]any{
		"url": srv.URL + "/", "match_re": "[invalid",
	})
	if res.OK || res.Error == "" {
		t.Fatalf("非法正则应报错: %+v", res)
	}

	// 状态码不符 → 未命中（ok=false、error 空）。
	res = mustExec(t, "atomic_verify_poc", map[string]any{
		"url": srv.URL + "/nope", "match_re": "404", "expect_status": 200,
	})
	if res.OK || res.Error != "" {
		t.Fatalf("状态码不符应为「未命中」而非失败: %+v", res)
	}

	// 占位符渲染：body 里的 {u} 从 params 取值，/echo 回显后正则判定。
	res = mustExec(t, "atomic_verify_poc", map[string]any{
		"method": "POST", "url": srv.URL + "/echo",
		"body": "user={u}", "params": map[string]string{"u": "probe"},
		"match_re": `echo:user=probe`,
	})
	if !res.OK {
		t.Fatalf("占位符渲染后应命中: %+v", res)
	}
	// 未提供取值的占位符原样保留（可从回显看到漏传）。
	res = mustExec(t, "atomic_verify_poc", map[string]any{
		"method": "POST", "url": srv.URL + "/echo",
		"body":     "user={missing}",
		"match_re": `echo:user=\{missing\}`,
	})
	if !res.OK {
		t.Fatalf("未命中占位符应原样保留: %+v", res)
	}
}

func TestWeakCredGuardrails(t *testing.T) {
	srv := startMockTarget(t)
	// 未知 service → 参数错误。
	if res := mustExec(t, "atomic_weak_cred", map[string]any{"service": "telnet", "target": srv.URL}); res.Error == "" {
		t.Fatalf("未知 service 应报错: %+v", res)
	}
	// 覆盖字典超限 → 拒绝（防把原子操作当爆破机）。
	if res := mustExec(t, "atomic_weak_cred", map[string]any{
		"service": "http_basic", "target": srv.URL + "/admin",
		"passwords": []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17"},
	}); res.Error == "" {
		t.Fatalf("口令字典超限应报错: %+v", res)
	}
	// 目标不可达 → 执行失败（error 非空），不是「未命中」。
	if res := mustExec(t, "atomic_weak_cred", map[string]any{
		"service": "http_basic", "target": "http://127.0.0.1:1/admin", "timeout_ms": 1000,
	}); res.OK || res.Error == "" {
		t.Fatalf("不可达目标应为执行失败: %+v", res)
	}
}

func TestFingerprintUnreachable(t *testing.T) {
	res := mustExec(t, "atomic_fingerprint", map[string]any{"target": "127.0.0.1:1", "timeout_ms": 1000})
	if res.OK || res.Error == "" {
		t.Fatalf("不可达目标应为执行失败: %+v", res)
	}
}
