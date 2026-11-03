package db

import (
	"testing"
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

// QueryDSLInScope 把 $1 留给任务 id（scopeTargetCTE），DSL 占位符从 $2 起。
func TestDSLPlaceholderOffset(t *testing.T) {
	node, err := ParseDSL("port==443 AND status_code>=200")
	if err != nil {
		t.Fatal(err)
	}
	where, args, err := buildDSLWhereBase(node, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := `(port = $2) AND (status_code >= $3)`
	if where != want {
		t.Fatalf("where=%q, want %q", where, want)
	}
	if len(args) != 2 || args[0] != 443 || args[1] != 200 {
		t.Fatalf("args=%v, want [443 200]", args)
	}
}
