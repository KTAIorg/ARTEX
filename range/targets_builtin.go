package vrange

// 内置靶标集：三个纯 Go（httptest）靶标，覆盖 atomic 三操作各自的验证路径。
//
// 靶标与原子操作的对应关系（atomic/ 包的三个示范操作）：
//   - weakcred-basic-auth   → atomic_weak_cred 的验证路径：弱口令类漏洞，
//     EXP 以「带凭据的 HTTP 模板」表达「弱口令可用」——凭据正确则拿到
//     受保护内容（FLAG），凭据错误则 401 质询。
//   - cve-known-path-echo   → atomic_verify_poc 的验证路径：已知漏洞路径
//     回显类（模拟 CVE 命中），只有到达 /vuln/echo 才触发带 CVE 编号的
//     水印回显，EXP 的判据必须能捕获它。
//   - version-banner-gate   → atomic_fingerprint 的验证路径：版本指纹区间
//     类，根路径横幅携带组件版本，EXP 的 fingerprint_match 声明版本区间，
//     区间覆盖靶标版本才命中、执行后横幅可验证。
//
// 全部无状态、无副作用、进程内自起；FLAG/水印是受控环境里的「拿下证据」占位。

import (
	"fmt"
	"net/http"
	"strings"
)

// 靶标侧常量：受控环境里的「漏洞证据」占位（进 ground-truth oracle）。
const (
	// weakCredFlag 弱口令靶标的拿下证据：只有带正确凭据访问 /admin/ 才可见。
	weakCredFlag = "FLAG{ARTEX-RANGE-BASIC-AUTH}"
	// cveEchoMarker 回显靶标的漏洞水印：只有命中 /vuln/echo 才出现。
	cveEchoMarker = "CVE-2027-13337"
)

// BuiltinTargets 返回内置靶标全集（每次构造新实例；定义不可变，构造廉价）。
// 回归闸门（ValidateExpAgainstRange）默认对全部内置靶标跑矩阵。
func BuiltinTargets() []*VulnTarget {
	return []*VulnTarget{
		weakCredBasicAuthTarget(),
		cveKnownPathEchoTarget(),
		versionBannerTarget(),
	}
}

// weakCredBasicAuthTarget：Basic Auth 弱口令靶标。
//
// 拓扑：根路径公开（落地页带组件/版本指纹位）；/admin/ 由 admin/admin123
// 保护——匿名或错误凭据 401 质询，正确凭据 200 + FLAG。
// ground truth：正确 EXP 必须带着有效凭据拿到 /admin/ 的受保护内容。
func weakCredBasicAuthTarget() *VulnTarget {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "DummyConsole/2.1.0")
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "admin123" {
				w.Header().Set("WWW-Authenticate", `Basic realm="DummyConsole"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><head><title>DummyConsole Admin</title></head>"+
				"<body><h1>admin console</h1><p>%s</p></body></html>", weakCredFlag)
			return
		}
		// 公开落地页：组件名 + 版本进 title（指纹位，模拟 atomic_fingerprint 的探测面）。
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><head><title>DummyConsole 2.1.0</title></head><body>service ok</body></html>")
	})
	return httptestTarget(
		"weakcred-basic-auth", "DummyConsole", "2.1.0",
		"Basic Auth 弱口令靶标：/admin/ 由 admin/admin123 保护，匿名 401、正确凭据 200+FLAG。"+
			"覆盖 atomic_weak_cred 的验证路径（凭据被接受且拿到受保护内容）。",
		`{"technologies":["DummyConsole/2.1.0"],"path":"/admin/"}`,
		`{"status_codes":[200],"keywords":["`+weakCredFlag+`"]}`,
		h,
	)
}

// cveKnownPathEchoTarget：已知路径回显靶标（模拟 CVE 命中）。
//
// 拓扑：只有 /vuln/echo 存在（200，回显 msg 参数并附组件版本与 CVE 水印）；
// 其余路径 404。正确 EXP 必须知道漏洞路径，且判据能捕获回显内容。
func cveKnownPathEchoTarget() *VulnTarget {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "EchoService/1.4.2")
		if r.URL.Path == "/vuln/echo" {
			msg := r.URL.Query().Get("msg")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "echo:%s | EchoService/1.4.2 | %s", msg, cveEchoMarker)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
	return httptestTarget(
		"cve-known-path-echo", "EchoService", "1.4.2",
		"已知路径回显靶标（模拟 CVE 命中）：/vuln/echo 回显 msg 并附 CVE 水印，其余 404。"+
			"覆盖 atomic_verify_poc 的验证路径（请求模板 + 判据命中回显）。",
		`{"technologies":["EchoService/1.4.2"]}`,
		`{"status_codes":[200],"regex":"`+cveEchoMarker+`"}`,
		h,
	)
}

// versionBannerTarget：指纹版本区间靶标。
//
// 拓扑：根路径 200，横幅与 Server 头携带 MiniProxy 0.9.7；其余路径 403。
// 正确 EXP 的 fingerprint_match 版本区间必须覆盖 0.9.7（区间外 →
// version_mismatch），执行后横幅可验证。
func versionBannerTarget() *VulnTarget {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "MiniProxy/0.9.7")
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprint(w, "MiniProxy 0.9.7 ready — admin console disabled")
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	return httptestTarget(
		"version-banner-gate", "MiniProxy", "0.9.7",
		"指纹版本区间靶标：根路径横幅携带组件版本，EXP 指纹的 version_range 覆盖 0.9.7 "+
			"才命中，执行后横幅可验证。覆盖 atomic_fingerprint 的验证路径（版本采集与区间判定）。",
		`{"technologies":["MiniProxy/0.9.7"]}`,
		`{"status_codes":[200],"keywords":["MiniProxy 0.9.7"]}`,
		h,
	)
}
