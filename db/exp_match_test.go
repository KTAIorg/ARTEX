package db

import (
	"encoding/json"
	"testing"
)

// ---------- 版本解析与比较 ----------

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		ok   bool
	}{
		{"1.18.0", []int{1, 18, 0}, true},
		{"v2.3", []int{2, 3}, true},
		{"2", []int{2}, true},
		{"V1.0.0-beta", nil, false},
		{"abc", nil, false},
		{"1..2", nil, false},
		{"", nil, false},
	}
	for _, c := range cases {
		got, ok := parseVersion(c.in)
		if ok != c.ok {
			t.Fatalf("parseVersion(%q) ok=%v want %v", c.in, ok, c.ok)
		}
		if !ok {
			continue
		}
		if len(got) != len(c.want) {
			t.Fatalf("parseVersion(%q)=%v want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("parseVersion(%q)=%v want %v", c.in, got, c.want)
			}
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.18", "1.18.0", 0}, // 缺段补 0
		{"1.18.0", "1.18.1", -1},
		{"2.0", "1.9.9", 1},
		{"1.10.0", "1.9.0", 1}, // 数值比较，不是字典序
		{"0.9", "1.0", -1},
	}
	for _, c := range cases {
		va, _ := parseVersion(c.a)
		vb, _ := parseVersion(c.b)
		if got := compareVersions(va, vb); got != c.want {
			t.Fatalf("compareVersions(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestVersionRangeBoundaries 版本区间边界：开闭区间与等值/不等值。
func TestVersionRangeBoundaries(t *testing.T) {
	in := func(rangeExpr, ver string) bool {
		cs, err := parseVersionRange(rangeExpr)
		if err != nil {
			t.Fatalf("parseVersionRange(%q): %v", rangeExpr, err)
		}
		v, ok := parseVersion(ver)
		if !ok {
			t.Fatalf("parseVersion(%q) failed", ver)
		}
		return versionSatisfies(v, cs)
	}
	cases := []struct {
		rangeExpr, ver string
		want           bool
	}{
		// 闭区间边界：>=4.0.0 含 4.0.0，<5.1.0 不含 5.1.0。
		{">=4.0.0,<5.1.0", "4.0.0", true},
		{">=4.0.0,<5.1.0", "3.9.9", false},
		{">=4.0.0,<5.1.0", "5.1.0", false},
		{">=4.0.0,<5.1.0", "5.0.9", true},
		// 开区间边界：>4.0.0 不含 4.0.0。
		{">4.0.0,<=5.0.0", "4.0.0", false},
		{">4.0.0,<=5.0.0", "4.0.1", true},
		{">4.0.0,<=5.0.0", "5.0.0", true},
		{">4.0.0,<=5.0.0", "5.0.1", false},
		// 等值（裸版本与显式 =）、不等值。
		{"1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.4", false},
		{"=1.2.3", "1.2.3", true},
		{"!=1.2.3", "1.2.4", true},
		{"!=1.2.3", "1.2.3", false},
		// 段数不齐的等值（1.18 == 1.18.0）。
		{"=1.18", "1.18.0", true},
		// 通配。
		{"*", "0.0.1", true},
		{"", "9.9.9", true},
	}
	for _, c := range cases {
		if got := in(c.rangeExpr, c.ver); got != c.want {
			t.Fatalf("version %q in range %q = %v, want %v", c.ver, c.rangeExpr, got, c.want)
		}
	}
	if _, err := parseVersionRange(">=foo"); err == nil {
		t.Fatal("parseVersionRange should reject non-numeric versions")
	}
}

// ---------- 技术栈串切分 ----------

func TestSplitTechnology(t *testing.T) {
	cases := []struct {
		in, name, ver string
	}{
		{"Nginx/1.18.0", "Nginx", "1.18.0"},
		{"Apache Tomcat 9.0.30", "Apache Tomcat", "9.0.30"},
		{"redis:6.0.9", "redis", "6.0.9"},
		{"Redis-v7.2.4", "Redis", "7.2.4"},
		{"PHP", "PHP", ""},
		{"Apache-HttpClient 4.5", "Apache-HttpClient", "4.5"},
	}
	for _, c := range cases {
		n, v := splitTechnology(c.in)
		if n != c.name || v != c.ver {
			t.Fatalf("splitTechnology(%q)=(%q,%q) want (%q,%q)", c.in, n, v, c.name, c.ver)
		}
	}
}

// ---------- 指纹匹配语义 ----------

func mustFingerprint(t *testing.T, raw string) *ExpFingerprint {
	t.Helper()
	fp, err := ParseExpFingerprint(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("ParseExpFingerprint(%s): %v", raw, err)
	}
	return fp
}

// TestMatchExpFingerprintSemantics 覆盖：维度 AND、组件条目 OR、版本区间、
// 端口/路径维度、未知版本归因 version_mismatch。
func TestMatchExpFingerprintSemantics(t *testing.T) {
	rocketmq := mustFingerprint(t, `{
		"components": [{"name": "RocketMQ", "version_range": ">=4.0.0,<5.1.0"}],
		"ports": [10911, 9876]
	}`)
	tomcatManager := mustFingerprint(t, `{
		"components": [{"name": "tomcat"}],
		"paths": ["/manager/html"]
	}`)

	cases := []struct {
		name       string
		fp         *ExpFingerprint
		asset      *AssetFingerprint
		wantOK     bool
		wantReason string
	}{
		{
			name:   "版本在区间+端口命中",
			fp:     rocketmq,
			asset:  &AssetFingerprint{Technologies: []string{"Apache RocketMQ 4.9.4"}, Port: 10911},
			wantOK: true,
		},
		{
			name:       "版本在区间但端口不符",
			fp:         rocketmq,
			asset:      &AssetFingerprint{Technologies: []string{"RocketMQ 4.9.4"}, Port: 8080},
			wantReason: string(ExpFailFingerprintMismatch),
		},
		{
			name:       "版本超上限（边界外）",
			fp:         rocketmq,
			asset:      &AssetFingerprint{Components: []AssetComponent{{Name: "rocketmq", Version: "5.1.0"}}, Port: 10911},
			wantReason: string(ExpFailVersionMismatch),
		},
		{
			name:   "版本下边界恰好命中（>=4.0.0 含 4.0.0）",
			fp:     rocketmq,
			asset:  &AssetFingerprint{Components: []AssetComponent{{Name: "rocketmq", Version: "4.0.0"}}, Port: 9876},
			wantOK: true,
		},
		{
			name:       "组件认出但版本未知 → version_mismatch",
			fp:         rocketmq,
			asset:      &AssetFingerprint{Technologies: []string{"RocketMQ"}, Port: 10911},
			wantReason: string(ExpFailVersionMismatch),
		},
		{
			name:       "组件完全不命中 → fingerprint_mismatch",
			fp:         rocketmq,
			asset:      &AssetFingerprint{Technologies: []string{"Nginx/1.18.0"}, Port: 10911},
			wantReason: string(ExpFailFingerprintMismatch),
		},
		{
			name:   "路径从 URL 提取+组件不限版本",
			fp:     tomcatManager,
			asset:  &AssetFingerprint{Technologies: []string{"Apache Tomcat 9.0.30"}, URL: "http://t.example:8080/manager/html"},
			wantOK: true,
		},
		{
			name:       "路径不含特征",
			fp:         tomcatManager,
			asset:      &AssetFingerprint{Technologies: []string{"Tomcat/8.5.0"}, Path: "/index.jsp"},
			wantReason: string(ExpFailFingerprintMismatch),
		},
		{
			name:   "无指纹条件=通配",
			fp:     &ExpFingerprint{},
			asset:  &AssetFingerprint{Port: 12345},
			wantOK: true,
		},
		{
			name:       "声明端口但资产端口未知",
			fp:         &ExpFingerprint{Ports: []int{6379}},
			asset:      &AssetFingerprint{Technologies: []string{"Redis 6.0.9"}},
			wantReason: string(ExpFailFingerprintMismatch),
		},
	}
	for _, c := range cases {
		ok, reason := MatchExpFingerprint(c.fp, c.asset)
		if ok != c.wantOK || (c.wantOK && reason != "") || (!c.wantOK && reason != c.wantReason) {
			t.Fatalf("%s: got (ok=%v, reason=%q) want (ok=%v, reason=%q)",
				c.name, ok, reason, c.wantOK, c.wantReason)
		}
	}
}

// TestMatchExpFingerprintComponentOR 多组件条目之间 OR：任一命中即通过。
func TestMatchExpFingerprintComponentOR(t *testing.T) {
	fp := mustFingerprint(t, `{
		"components": [
			{"name": "Spring Cloud Gateway", "version_range": "<3.1.1"},
			{"name": "thinkphp", "version_range": ">=5.0,<5.1.31"}
		]
	}`)
	ok, reason := MatchExpFingerprint(fp, &AssetFingerprint{
		Technologies: []string{"ThinkPHP 5.0.24"},
	})
	if !ok || reason != "" {
		t.Fatalf("second component entry should hit: ok=%v reason=%q", ok, reason)
	}
	// 两个条目都命中不了：组件认出 thinkphp 但版本超区间 → version_mismatch。
	ok, reason = MatchExpFingerprint(fp, &AssetFingerprint{
		Technologies: []string{"ThinkPHP 5.1.31"},
	})
	if ok || reason != string(ExpFailVersionMismatch) {
		t.Fatalf("out-of-range should be version_mismatch: ok=%v reason=%q", ok, reason)
	}
}

// TestParseExpFingerprintInvalid 坏条件在建库路径被挡：非法版本区间/空 name。
func TestParseExpFingerprintInvalid(t *testing.T) {
	bad := []string{
		`{"components":[{"name":"x","version_range":">=oops"}]}`,
		`{"components":[{"name":""}]}`,
		`{"components":"not-an-array"}`,
	}
	for _, raw := range bad {
		if _, err := ParseExpFingerprint(json.RawMessage(raw)); err == nil {
			t.Fatalf("ParseExpFingerprint(%s) should fail", raw)
		}
	}
	if _, err := ParseExpFingerprint(json.RawMessage(`{}`)); err != nil {
		t.Fatalf("empty object should parse as wildcard: %v", err)
	}
}
