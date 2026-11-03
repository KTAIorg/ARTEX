package vrange

// 回归执行器测试：mock EXP × 内置靶标，覆盖三类场景——
//   全 Pass（正确 EXP 打下自己的靶标）、有 Fail（凭据错误，执行成功但判据不中）、
//   oracle 不匹配（EXP 判据与靶标现实脱节，两个方向：判据写错 / 判据过松）。
// 另有跨靶标矩阵、版本区间不命中、非 http 模板拒执行。
// 全部纯 Go（httptest 靶标 + 标准库），无 PG、无 docker、无外网。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// canonicalWeakCredExp 是 weakcred-basic-auth 靶标的「标准答案」EXP：
// 指纹声明 DummyConsole 2.x + /admin/ 路径，模板带正确弱凭据，判据要求 FLAG。
func canonicalWeakCredExp() *db.ExpAsset {
	return &db.ExpAsset{
		Name:   "exp-weakcred-dummyconsole",
		FP:     json.RawMessage(`{"components":[{"name":"DummyConsole","version_range":">=2.0,<3.0"}],"paths":["/admin/"]}`),
		Exec:   json.RawMessage(`{"kind":"http","method":"GET","url":"{target}/admin/","auth_user":"admin","auth_pass":"admin123"}`),
		Oracle: json.RawMessage(`{"status_codes":[200],"keywords":["FLAG"]}`),
	}
}

// canonicalEchoExp 是 cve-known-path-echo 靶标的标准答案 EXP：
// 知道漏洞路径 /vuln/echo，判据捕获回显内容。
func canonicalEchoExp() *db.ExpAsset {
	return &db.ExpAsset{
		Name:   "exp-echo-cve",
		FP:     json.RawMessage(`{"components":[{"name":"echoservice"}]}`),
		Exec:   json.RawMessage(`{"kind":"http","method":"GET","url":"{target}/vuln/echo?msg=artex-regression"}`),
		Oracle: json.RawMessage(`{"status_codes":[200],"keywords":["echo:"]}`),
	}
}

// canonicalVersionExp 是 version-banner-gate 靶标的标准答案 EXP：
// 指纹版本区间 [0.9.0, 0.9.9) 覆盖靶标 0.9.7，执行后横幅可验证。
func canonicalVersionExp() *db.ExpAsset {
	return &db.ExpAsset{
		Name:   "exp-miniproxy-banner",
		FP:     json.RawMessage(`{"components":[{"name":"MiniProxy","version_range":">=0.9.0,<0.9.9"}]}`),
		Exec:   json.RawMessage(`{"kind":"http","method":"GET","url":"{target}/"}`),
		Oracle: json.RawMessage(`{"status_codes":[200],"keywords":["MiniProxy"]}`),
	}
}

// findCase 取报告中指定 (exp, target) 的组合结果。
func findCase(t *testing.T, rep *Report, expName, target string) CaseResult {
	t.Helper()
	for _, c := range rep.Cases {
		if c.ExpName == expName && c.Target == target {
			return c
		}
	}
	t.Fatalf("case (%s × %s) not found in report", expName, target)
	return CaseResult{}
}

// TestRunRegressionAllPass 场景一：三条标准答案 EXP 分别对自己的靶标——
// 全部 Pass，双判据命中，耗时与 evidence 留痕齐全。
func TestRunRegressionAllPass(t *testing.T) {
	pairs := []struct {
		exp    *db.ExpAsset
		target *VulnTarget
	}{
		{canonicalWeakCredExp(), weakCredBasicAuthTarget()},
		{canonicalEchoExp(), cveKnownPathEchoTarget()},
		{canonicalVersionExp(), versionBannerTarget()},
	}
	for _, p := range pairs {
		rep := RunRegression(context.Background(), []*db.ExpAsset{p.exp}, []*VulnTarget{p.target})
		if rep.Total != 1 || rep.Passed != 1 || rep.FailedApplicable != 0 || rep.FailedMismatch != 0 {
			t.Fatalf("%s × %s: want 1 pass, got total=%d passed=%d failApp=%d failMM=%d (cases=%+v)",
				p.exp.Name, p.target.Name, rep.Total, rep.Passed, rep.FailedApplicable, rep.FailedMismatch, rep.Cases)
		}
		c := rep.Cases[0]
		if !c.Applicable || !c.Executed || !c.ExpOracleOK || !c.TargetOracleOK {
			t.Fatalf("%s: case flags wrong: %+v", p.exp.Name, c)
		}
		if c.DurationMS < 0 || c.Evidence == "" {
			t.Fatalf("%s: duration/evidence missing: %+v", p.exp.Name, c)
		}
	}
}

// TestRunRegressionWithFail 场景二：有 Fail——弱口令 EXP 带错口令，
// 指纹命中、请求执行成功（HTTP 401），但 EXP 判据与靶标判据双双未命中。
func TestRunRegressionWithFail(t *testing.T) {
	e := canonicalWeakCredExp()
	e.Name = "exp-weakcred-wrong-pass"
	e.Exec = json.RawMessage(`{"kind":"http","method":"GET","url":"{target}/admin/","auth_user":"admin","auth_pass":"wrong-password"}`)
	rep := RunRegression(context.Background(), []*db.ExpAsset{e}, []*VulnTarget{weakCredBasicAuthTarget()})
	if rep.Passed != 0 || rep.FailedApplicable != 1 {
		t.Fatalf("want 1 applicable failure, got %+v", rep.Cases)
	}
	c := rep.Cases[0]
	if !c.Applicable || !c.Executed || c.Pass {
		t.Fatalf("case should be applicable+executed+not-pass: %+v", c)
	}
	if c.HTTPStatus != 401 {
		t.Fatalf("want 401 challenge, got %d", c.HTTPStatus)
	}
	if c.ExpOracleOK || c.TargetOracleOK {
		t.Fatalf("neither oracle may pass on wrong creds: %+v", c)
	}
	if !strings.Contains(c.ExpOracleFail, "状态码") {
		t.Fatalf("exp oracle fail should mention status: %q", c.ExpOracleFail)
	}
}

// TestRunRegressionOracleMismatch 场景三：oracle 不匹配——EXP 声明的成功
// 判据与靶标现实脱节。两个方向都要拦：
//
//	a) 判据写错（漏报）：执行命中了漏洞效果，但 EXP 判据声明了不存在的关键字；
//	b) 判据过松（误报/作弊）：打到任意 200 页面就自称成功，靶标 ground truth
//	   揭穿「漏洞效果并未发生」。
func TestRunRegressionOracleMismatch(t *testing.T) {
	ctx := context.Background()

	// a) 判据写错：路径与请求都对，EXP 判据却要一个永远不会出现的关键字。
	strict := canonicalEchoExp()
	strict.Name = "exp-echo-bad-oracle"
	strict.Oracle = json.RawMessage(`{"status_codes":[200],"keywords":["PWNED-ROOT-SHELL"]}`)
	rep := RunRegression(ctx, []*db.ExpAsset{strict}, []*VulnTarget{cveKnownPathEchoTarget()})
	c := rep.Cases[0]
	if c.Pass || c.ExpOracleOK || !c.TargetOracleOK {
		t.Fatalf("oracle-too-strict: want fail with exp oracle miss + target oracle hit: %+v", c)
	}
	if !strings.Contains(c.ExpOracleFail, "PWNED-ROOT-SHELL") {
		t.Fatalf("exp oracle fail should name the missing keyword: %q", c.ExpOracleFail)
	}

	// b) 判据过松：通配指纹 + 只看状态码 200。根路径确实 200（EXP「自称成功」），
	//    但靶标 ground truth 要求 FLAG——弱口令效果并未发生，闸门必须拦下。
	loose := &db.ExpAsset{
		Name:   "exp-any-200-is-win",
		FP:     json.RawMessage(`{}`),
		Exec:   json.RawMessage(`{"kind":"http","method":"GET","url":"{target}/"}`),
		Oracle: json.RawMessage(`{"status_codes":[200]}`),
	}
	rep = RunRegression(ctx, []*db.ExpAsset{loose}, []*VulnTarget{weakCredBasicAuthTarget()})
	c = rep.Cases[0]
	if c.Pass || !c.ExpOracleOK || c.TargetOracleOK {
		t.Fatalf("oracle-too-loose: want fail with exp oracle hit + target oracle miss: %+v", c)
	}
	if !strings.Contains(c.TargetOracleFail, weakCredFlag) {
		t.Fatalf("target oracle fail should name the flag: %q", c.TargetOracleFail)
	}
}

// TestRunRegressionCrossMatrix 三条标准答案 EXP × 三个内置靶标的全矩阵：
// 每条 EXP 恰好通过自己的靶标、指纹不命中另外两个（mismatch 不计罪状）。
func TestRunRegressionCrossMatrix(t *testing.T) {
	exps := []*db.ExpAsset{canonicalWeakCredExp(), canonicalEchoExp(), canonicalVersionExp()}
	rep := RunRegression(context.Background(), exps, BuiltinTargets())
	if rep.Total != 9 || rep.Passed != 3 || rep.FailedApplicable != 0 || rep.FailedMismatch != 6 {
		t.Fatalf("matrix summary wrong: total=%d passed=%d failApp=%d failMM=%d",
			rep.Total, rep.Passed, rep.FailedApplicable, rep.FailedMismatch)
	}
	for _, sum := range rep.PerExp {
		if len(sum.Passed) != 1 || len(sum.FailedApplicable) != 0 || len(sum.Mismatched) != 2 {
			t.Fatalf("per-exp summary wrong: %+v", sum)
		}
	}
	// 弱口令 EXP 在回显靶标上指纹不命中（组件对不上），且不执行。
	c := findCase(t, rep, "exp-weakcred-dummyconsole", "cve-known-path-echo")
	if c.Applicable || c.Executed || c.FPReason != string(db.ExpFailFingerprintMismatch) {
		t.Fatalf("cross mismatch case wrong: %+v", c)
	}
}

// TestRunRegressionVersionMismatch 版本区间不命中：MiniProxy EXP 声明 >=1.0，
// 靶标是 0.9.7 → version_mismatch、不执行（EXP 版本区间与靶标现实脱节）。
func TestRunRegressionVersionMismatch(t *testing.T) {
	e := canonicalVersionExp()
	e.Name = "exp-miniproxy-wrong-range"
	e.FP = json.RawMessage(`{"components":[{"name":"MiniProxy","version_range":">=1.0"}]}`)
	rep := RunRegression(context.Background(), []*db.ExpAsset{e}, []*VulnTarget{versionBannerTarget()})
	c := rep.Cases[0]
	if c.Applicable || c.Executed || c.Pass || c.FPReason != string(db.ExpFailVersionMismatch) {
		t.Fatalf("version mismatch case wrong: %+v", c)
	}
	if rep.FailedMismatch != 1 {
		t.Fatalf("summary should count 1 mismatch: %+v", rep)
	}
}

// TestRunRegressionNonHTTPExec 非 http 模板（command/script）在纯 Go 靶场上
// 无法执行：指纹命中但执行失败，原因写明只支持 kind=http。
func TestRunRegressionNonHTTPExec(t *testing.T) {
	e := canonicalWeakCredExp()
	e.Name = "exp-command-kind"
	e.Exec = json.RawMessage(`{"kind":"command","argv":["curl","{target}/admin/"]}`)
	rep := RunRegression(context.Background(), []*db.ExpAsset{e}, []*VulnTarget{weakCredBasicAuthTarget()})
	c := rep.Cases[0]
	if c.Applicable && !c.Executed && c.Pass {
		// fallthrough 到具体断言
	}
	if !c.Applicable || c.Executed || c.Pass {
		t.Fatalf("non-http exec should be applicable-but-not-executed: %+v", c)
	}
	if !strings.Contains(c.ExecError, "kind=http") {
		t.Fatalf("exec error should name supported kind: %q", c.ExecError)
	}
}
