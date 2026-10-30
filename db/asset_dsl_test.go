package db

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// buildOne 解析并编译一条 DSL，返回 WHERE 片段与参数序列（纯函数，不碰数据库）。
func buildOne(t *testing.T, dsl string) (string, []any) {
	t.Helper()
	node, err := ParseDSL(dsl)
	if err != nil {
		t.Fatalf("ParseDSL(%q): %v", dsl, err)
	}
	where, args, err := buildDSLWhere(node)
	if err != nil {
		t.Fatalf("buildDSLWhere(%q): %v", dsl, err)
	}
	return where, args
}

// =====================================================================
// kv_score：数值比较
// =====================================================================

func TestKVScoreNumericOps(t *testing.T) {
	cases := []struct {
		dsl  string
		want string
		arg  int
	}{
		{"kv_score>=85", `(extra->'ktvuln'->>'score')::int >= $1`, 85},
		{"kv_score>80", `(extra->'ktvuln'->>'score')::int > $1`, 80},
		{"kv_score<50", `(extra->'ktvuln'->>'score')::int < $1`, 50},
		{"kv_score<=50", `(extra->'ktvuln'->>'score')::int <= $1`, 50},
		{"kv_score=90", `(extra->'ktvuln'->>'score')::int = $1`, 90},
		{"kv_score==90", `(extra->'ktvuln'->>'score')::int = $1`, 90},
		{"kv_score!=0", `(extra->'ktvuln'->>'score')::int != $1`, 0},
	}
	for _, tc := range cases {
		where, args := buildOne(t, tc.dsl)
		if where != tc.want {
			t.Errorf("%s: where=%q, want %q", tc.dsl, where, tc.want)
		}
		if len(args) != 1 || args[0] != tc.arg {
			t.Errorf("%s: args=%v, want [%d]", tc.dsl, args, tc.arg)
		}
	}
}

func TestKVScoreRejectsNonInteger(t *testing.T) {
	for _, dsl := range []string{"kv_score>=abc", "kv_score=高", "kv_score>8.5"} {
		err := ValidateDSL(dsl)
		if err == nil {
			t.Errorf("ValidateDSL(%q): expected error", dsl)
			continue
		}
		if !strings.Contains(err.Error(), "需要整数值") {
			t.Errorf("ValidateDSL(%q): unexpected error %v", dsl, err)
		}
	}
}

// =====================================================================
// kv_tier / kv_biz_type / kv_engagement / kv_verdict：字符串比较
// =====================================================================

func TestKVStringFields(t *testing.T) {
	cases := []struct {
		dsl  string
		want string
		arg  string
	}{
		{"kv_tier==A", `extra->'ktvuln'->>'tier' = $1`, "A"},
		{"kv_tier=A", `extra->'ktvuln'->>'tier' ILIKE $1`, "%A%"},
		{"kv_engagement=todo", `extra->'ktvuln'->>'engagement_status' ILIKE $1`, "%todo%"},
		{"kv_engagement==todo", `extra->'ktvuln'->>'engagement_status' = $1`, "todo"},
		{"kv_biz_type==盗U盘", `extra->'ktvuln'->>'biz_type' = $1`, "盗U盘"},
		{"kv_verdict!=patched", `COALESCE(extra->'ktvuln'->>'verdict','') NOT ILIKE $1`, "%patched%"},
	}
	for _, tc := range cases {
		where, args := buildOne(t, tc.dsl)
		if where != tc.want {
			t.Errorf("%s: where=%q, want %q", tc.dsl, where, tc.want)
		}
		if len(args) != 1 || args[0] != tc.arg {
			t.Errorf("%s: args=%v, want [%q]", tc.dsl, args, tc.arg)
		}
	}
}

func TestKVStringRejectsNumericOp(t *testing.T) {
	// >= 是数值比较运算符，字符串维度字段不接受；错误文案与普通字符串字段一致。
	err := ValidateDSL("kv_tier>=A")
	if err == nil {
		t.Fatal("ValidateDSL(\"kv_tier>=A\"): expected error")
	}
	if err.Error() != "字符串字段 kv_tier 不支持运算符 >=" {
		t.Fatalf("error=%q, want 字符串字段 kv_tier 不支持运算符 >=", err.Error())
	}
}

// =====================================================================
// 组合查询 / 字段识别 / 占位符偏移
// =====================================================================

func TestKVCombinedQuery(t *testing.T) {
	where, args := buildOne(t, "kv_tier==A AND kv_score>=85")
	want := `(extra->'ktvuln'->>'tier' = $1) AND ((extra->'ktvuln'->>'score')::int >= $2)`
	if where != want {
		t.Fatalf("where=%q, want %q", where, want)
	}
	if len(args) != 2 || args[0] != "A" || args[1] != 85 {
		t.Fatalf("args=%v, want [A 85]", args)
	}
}

func TestKVFieldsKnown(t *testing.T) {
	for _, f := range []string{"kv_score", "kv_tier", "kv_biz_type", "kv_engagement", "kv_verdict", "KV_TIER"} {
		if !isKnownField(f) {
			t.Errorf("isKnownField(%q) = false, want true", f)
		}
	}
	for _, f := range []string{"kv_owner", "kv_scores", "kvtier"} {
		if isKnownField(f) {
			t.Errorf("isKnownField(%q) = true, want false", f)
		}
	}
}

// QueryDSLInScope 把 $1 留给任务 id（scopeTargetCTE），DSL 占位符从 $2 起。
func TestKVPlaceholderOffset(t *testing.T) {
	node, err := ParseDSL("kv_tier==A AND kv_score>=85")
	if err != nil {
		t.Fatal(err)
	}
	where, args, err := buildDSLWhereBase(node, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := `(extra->'ktvuln'->>'tier' = $2) AND ((extra->'ktvuln'->>'score')::int >= $3)`
	if where != want {
		t.Fatalf("where=%q, want %q", where, want)
	}
	if len(args) != 2 || args[0] != "A" || args[1] != 85 {
		t.Fatalf("args=%v, want [A 85]", args)
	}
}

// =====================================================================
// PG 集成（无 ARTEX_PG_DSN 时自动 skip）
// =====================================================================

// TestKVQueryDSLAgainstPG 验证 kv_* 过滤在真实 jsonb 数据上的行为，重点钉住
// NULL 语义：无 kt-vuln 数据（键或子树缺失）的资产被正向比较排除，但在
// kv_verdict!= 这类排除条件下通过 COALESCE 兜底被包含。
func TestKVQueryDSLAgainstPG(t *testing.T) {
	d, assets, _ := testSetup(t)
	defer d.Close()

	stamp := time.Now().UnixNano()
	marker := fmt.Sprintf("kv-dsl-%d", stamp)
	insert := func(url, extra string) int64 {
		var id int64
		if err := d.QueryRow(`INSERT INTO assets(type,url,ip,port,service_type,extra)
			VALUES ('service',$1,'203.0.113.7',443,'http',$2::jsonb) RETURNING id`,
			url, extra).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// a1 维度齐全；a2 只有 score/tier；a3 完全没有 kt-vuln 子树；a4 已修复。
	a1 := insert(marker+"-a1.example.com", `{"ktvuln":{"score":92,"tier":"A","biz_type":"盗U盘","engagement_status":"todo","verdict":"vulnerable"}}`)
	a2 := insert(marker+"-a2.example.com", `{"ktvuln":{"score":40,"tier":"C"}}`)
	a3 := insert(marker+"-a3.example.com", `{}`)
	a4 := insert(marker+"-a4.example.com", `{"ktvuln":{"score":88,"tier":"B","verdict":"patched"}}`)
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=ANY($1::bigint[])`, []int64{a1, a2, a3, a4}) }()

	queryIDs := func(dsl string) []int64 {
		t.Helper()
		got, err := assets.QueryDSL(dsl, "service", 0, 50, 0)
		if err != nil {
			t.Fatalf("QueryDSL(%q): %v", dsl, err)
		}
		var ids []int64
		for _, a := range got {
			ids = append(ids, a.ID)
		}
		slices.Sort(ids)
		return ids
	}

	if got := queryIDs("url=" + marker + " AND kv_tier==A AND kv_score>=85"); !slices.Equal(got, []int64{a1}) {
		t.Errorf("kv_tier==A AND kv_score>=85: got %v, want [%d]", got, a1)
	}
	if got := queryIDs("url=" + marker + " AND kv_engagement=todo"); !slices.Equal(got, []int64{a1}) {
		t.Errorf("kv_engagement=todo: got %v, want [%d]", got, a1)
	}
	if got := queryIDs("url=" + marker + " AND kv_biz_type==盗U盘"); !slices.Equal(got, []int64{a1}) {
		t.Errorf("kv_biz_type==盗U盘: got %v, want [%d]", got, a1)
	}
	// a4 被 != 排除；a1（vulnerable）命中；a2/a3 无 kt-vuln 数据，COALESCE 兜底保留。
	if got := queryIDs("url=" + marker + " AND kv_verdict!=patched"); !slices.Equal(got, []int64{a1, a2, a3}) {
		t.Errorf("kv_verdict!=patched: got %v, want [%d %d %d]", got, a1, a2, a3)
	}
}
