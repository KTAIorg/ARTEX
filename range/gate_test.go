package vrange

// 入库闸门测试：Pass 放行、Fail 拒绝（含分层拒绝原因——指纹面全不命中
// vs 命中却打不下来）。纯 Go，无 PG。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestValidateExpAgainstRangePass Pass 放行：标准答案 EXP 至少通过一个
// 内置靶标，PassedTargets 留痕、Report 齐全。
func TestValidateExpAgainstRangePass(t *testing.T) {
	for _, e := range []*db.ExpAsset{canonicalWeakCredExp(), canonicalEchoExp(), canonicalVersionExp()} {
		res := ValidateExpAgainstRange(context.Background(), e)
		if !res.Allowed {
			t.Fatalf("%s should pass the gate, reason=%s", e.Name, res.Reason)
		}
		if len(res.PassedTargets) == 0 || res.Reason != "" {
			t.Fatalf("%s: allowed result malformed: %+v", e.Name, res)
		}
		if res.Report == nil || len(res.Report.Cases) != len(BuiltinTargets()) {
			t.Fatalf("%s: report must cover all builtin targets: %+v", e.Name, res.Report)
		}
	}
}

// TestValidateExpAgainstRangeFail 凭据打错：指纹命中靶标但双判据不中 → 拒绝，
// 原因指向执行模板/判据（而非指纹面）。
func TestValidateExpAgainstRangeFail(t *testing.T) {
	e := canonicalWeakCredExp()
	e.Name = "exp-weakcred-wrong-pass"
	e.Exec = json.RawMessage(`{"kind":"http","method":"GET","url":"{target}/admin/","auth_user":"admin","auth_pass":"nope"}`)
	res := ValidateExpAgainstRange(context.Background(), e)
	if res.Allowed {
		t.Fatal("wrong-credential exp must be rejected")
	}
	if !strings.Contains(res.Reason, "执行模板或成功判据有误") {
		t.Fatalf("reject reason should blame exec/oracle: %q", res.Reason)
	}
	if !strings.Contains(res.Reason, "weakcred-basic-auth") {
		t.Fatalf("reject reason should name the failed target: %q", res.Reason)
	}
}

// TestValidateExpAgainstRangeFingerprintMiss 指纹面全不命中：EXP 声明的组件
// 与所有内置靶标对不上 → 拒绝，原因指向指纹面（修复方向不同于判据错误）。
func TestValidateExpAgainstRangeFingerprintMiss(t *testing.T) {
	e := &db.ExpAsset{
		Name:   "exp-unknown-component",
		FP:     json.RawMessage(`{"components":[{"name":"NoSuchComponent","version_range":">=1.0"}]}`),
		Exec:   json.RawMessage(`{"kind":"http","method":"GET","url":"{target}/anything"}`),
		Oracle: json.RawMessage(`{"status_codes":[200]}`),
	}
	res := ValidateExpAgainstRange(context.Background(), e)
	if res.Allowed {
		t.Fatal("exp matching no builtin target must be rejected")
	}
	if !strings.Contains(res.Reason, "未命中任何内置靶标的指纹") {
		t.Fatalf("reject reason should blame fingerprint coverage: %q", res.Reason)
	}
}
