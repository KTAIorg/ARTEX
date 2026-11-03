package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestVulnCveYear(t *testing.T) {
	for in, want := range map[string]int{
		"CVE-2023-46604": 2023,
		"cve-2017-5638":  2017,
		"GHSA-xxxx":      0,
		"":               0,
	} {
		if got := vulnCveYear(in); got != want {
			t.Errorf("vulnCveYear(%q)=%d want %d", in, got, want)
		}
	}
}

func TestFocusCveMatch(t *testing.T) {
	title := "Struts2 S2-045 RCE"
	c := vulnFocusCve{CveID: "CVE-2017-5638", Title: &title, Category: nil,
		Affected: map[string][]string{"struts2": {"2.3.5-2.3.31"}}}
	for needle, want := range map[string]bool{
		"":        true,
		"5638":    true,
		"struts":  true, // affected 组件命中
		"wordpress": false,
	} {
		if got := focusCveMatch(c, strings.ToLower(needle)); got != want {
			t.Errorf("focusCveMatch(%q)=%v want %v", needle, got, want)
		}
	}
}

func TestVulnAssetCompact(t *testing.T) {
	scheme, comp := "https", "activemq"
	score := 65
	hostnames := []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com"}
	raw := vulnAssetRaw{ID: 7, IP: "1.2.3.4", Port: 8161, Scheme: &scheme,
		Hostnames: hostnames, Component: &comp, Version: nil, Score: &score}
	got := raw.compact()
	if got.Scheme != "https" || got.Component != "activemq" || got.Score != 65 {
		t.Errorf("compact 基本字段丢失: %+v", got)
	}
	if len(got.Hostnames) != vulnHostnamesMax+1 || got.Hostnames[vulnHostnamesMax] != "+2 more" {
		t.Errorf("hostnames 截断错误: %v", got.Hostnames)
	}
}

func TestVulnErrMessage(t *testing.T) {
	if m := vulnErrMessage([]byte(`{"error":{"code":401,"message":"token expired"}}`), "fb"); m != "token expired" {
		t.Errorf("identity 形态解析失败: %s", m)
	}
	if m := vulnErrMessage([]byte(`{"status":"error","message":"查询失败"}`), "fb"); m != "查询失败" {
		t.Errorf("writeErr 形态解析失败: %s", m)
	}
	if m := vulnErrMessage([]byte(`not json`), "fb"); m != "fb" {
		t.Errorf("兜底文案失败: %s", m)
	}
}

// newVulnFakeAuth 起一对假 identity 登录端点 + 假 kt-vuln API，并注入工具用的
// env。返回 api 服务器与已登录次数计数（供 401 重登断言）。
func newVulnFakeAuth(t *testing.T, apiHandler http.HandlerFunc) (*httptest.Server, *int32) {
	t.Helper()
	var logins int32
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&logins, 1)
		if r.Header.Get("User-Agent") != vulnUserAgent {
			t.Errorf("登录请求缺少自定义 UA: %q", r.Header.Get("User-Agent"))
		}
		var in struct{ LoginName, Password string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.LoginName != "svc-user" || in.Password != "svc-pass" || in.LoginName == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"bad creds"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "tok-" + string(rune('0'+atomic.LoadInt32(&logins))),
			"session": map[string]any{"expiresAt": "2000-01-01T00:00:00Z"}, // 零值 → 每次都重登
		})
	}))
	api := httptest.NewServer(apiHandler)
	t.Setenv(envVulnUser, "svc-user")
	t.Setenv(envVulnPass, "svc-pass")
	t.Setenv(envVulnLoginURL, login.URL)
	t.Setenv(envVulnAPIURL, api.URL)
	t.Cleanup(func() { login.Close(); api.Close(); vulnTokenReset() })
	return api, &logins
}

func TestVulnGetReloginOn401(t *testing.T) {
	vulnTokenReset()
	var calls int32
	api, logins := newVulnFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"status":"error","message":"unauthorized"}`))
			return
		}
		if r.Header.Get("User-Agent") != vulnUserAgent {
			t.Errorf("API 请求缺少自定义 UA: %q", r.Header.Get("User-Agent"))
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-") {
			t.Errorf("Bearer 头异常: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"items":[],"total":0}`))
	})
	_ = api
	var out struct {
		Total int `json:"total"`
	}
	if err := vulnGet(context.Background(), "/api/assets", nil, &out); err != nil {
		t.Fatalf("vulnGet 401 重试失败: %v", err)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Errorf("期望 401 后重试一次, 实际请求 %d 次", calls)
	}
	if atomic.LoadInt32(logins) < 2 {
		t.Errorf("期望强制重登, 实际登录 %d 次", *logins)
	}
}

func vulnToolCall(t *testing.T, tool actool.CoreTool, input any) string {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	r, err := tool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("%s: %v", tool.Name(), err)
	}
	return r.Flatten()
}

func TestVulnToolsCredsMissing(t *testing.T) {
	vulnTokenReset()
	t.Setenv(envVulnUser, "")
	t.Setenv(envVulnPass, "")
	s := &Server{}
	for _, tool := range []actool.CoreTool{s.toolVulnListCves(), s.toolVulnSearchAssets(), s.toolVulnCveDetail()} {
		out := vulnToolCall(t, tool, map[string]any{"scope": "focus", "cve_id": "CVE-2023-46604"})
		if !strings.Contains(out, "管理员未配置") || !strings.Contains(out, envVulnUser) {
			t.Errorf("%s 缺配置时的错误提示不清晰: %s", tool.Name(), out)
		}
	}
}

func TestToolVulnListCvesCatalog(t *testing.T) {
	vulnTokenReset()
	newVulnFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cve-catalog" {
			t.Errorf("路径异常: %s", r.URL.Path)
		}
		q := r.URL.Query()
		for k, want := range map[string]string{
			"page": "2", "page_size": "50", "sort": "published", "order": "asc",
			"year": "2023", "min_severity": "9", "q": "activemq",
		} {
			if q.Get(k) != want {
				t.Errorf("query %s=%q want %q", k, q.Get(k), want)
			}
		}
		_, _ = w.Write([]byte(`{"items":[{"cve_id":"CVE-2023-46604","title":"ActiveMQ RCE",
			"severity":10,"published":"2023-10-27","published_year":2023,"kev":true,"source":"curated",
			"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cvss_version":"3.1"}],
			"total":1,"page":2,"page_size":50}`))
	})
	out := vulnToolCall(t, (&Server{}).toolVulnListCves(), map[string]any{
		"scope": "catalog", "q": "activemq", "year": 2023, "min_severity": 9,
		"page": 2, "sort": "published", "order": "asc",
	})
	if strings.Contains(out, "cvss_vector") {
		t.Errorf("catalog 紧凑输出不应包含 cvss_vector: %s", out)
	}
	for _, want := range []string{`"cve_id":"CVE-2023-46604"`, `"total":1`, `"kev":true`} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺少 %s: %s", want, out)
		}
	}
}

func TestToolVulnCveDetail(t *testing.T) {
	vulnTokenReset()
	newVulnFakeAuth(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/cves":
			_, _ = w.Write([]byte(`{"items":[{"cve_id":"CVE-2023-46604","title":"ActiveMQ RCE",
				"severity":10,"kev":true,"affected":{"activemq":["5.x"]},
				"surface":{"vulnerable":550,"executable":0,"patched":0,"unknown":2472}}]}`))
		case "/api/cve-catalog":
			// 回落检索：q 对 cve_id 模糊匹配，按请求的 q 如实返回（未命中给空集）。
			switch r.URL.Query().Get("q") {
			case "CVE-2017-5638":
				_, _ = w.Write([]byte(`{"items":[{"cve_id":"CVE-2017-5638","title":"Struts2 S2-045",
					"severity":10,"published":"2017-03-06","kev":true,"source":"nvd"}],"total":1}`))
			default:
				_, _ = w.Write([]byte(`{"items":[],"total":0}`))
			}
		case "/api/assets":
			if r.URL.Query().Get("cve") == "" {
				t.Errorf("资产查询缺 cve 参数: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"items":[{"id":1749159,"ip":"1.12.237.229","port":35000,
				"scheme":"http","component":"activemq","version":"5.19.6","score":65,"tier":"B",
				"verdict":"vulnerable"}],"total":3022}`))
		default:
			t.Errorf("意外路径: %s", r.URL.Path)
		}
	})
	s := &Server{}

	out := vulnToolCall(t, s.toolVulnCveDetail(), map[string]any{"cve_id": "cve-2023-46604"})
	for _, want := range []string{`"in_focus":true`, `"vulnerable":550`, `"assets_total":3022`, `"cve_id":"CVE-2023-46604"`} {
		if !strings.Contains(out, want) {
			t.Errorf("focus 命中输出缺少 %s: %s", want, out)
		}
	}

	out = vulnToolCall(t, s.toolVulnCveDetail(), map[string]any{"cve_id": "CVE-2017-5638"})
	for _, want := range []string{`"in_focus":false`, `"source":"nvd"`, `"assets_total":3022`} {
		if !strings.Contains(out, want) {
			t.Errorf("catalog 回落输出缺少 %s: %s", want, out)
		}
	}

	out = vulnToolCall(t, s.toolVulnCveDetail(), map[string]any{"cve_id": "CVE-9999-0001"})
	if !strings.Contains(out, "CVE 不存在") {
		t.Errorf("未命中应报不存在: %s", out)
	}
}
