package server

// 靶场闸门写路径接线测试：WithRangeGate() 可选参数接到 ExpLibrary 的
// Create/Update 上——闸门未过的 EXP 进不了库；不带选项的既有调用路径
// 行为不变（不跑回归）。前半段纯逻辑（无 PG 也能跑），端到端段落无 PG
// 配置时跳过（与 server 侧 EXP 测试同一约定）。

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// gateWeakCredExp 是能过闸门的 EXP（weakcred-basic-auth 靶标的标准答案）。
func gateWeakCredExp(name string) *db.ExpAsset {
	return &db.ExpAsset{
		Name:    name,
		FP:      json.RawMessage(`{"components":[{"name":"DummyConsole","version_range":">=2.0,<3.0"}],"paths":["/admin/"]}`),
		Exec:    json.RawMessage(`{"kind":"http","method":"GET","url":"{target}/admin/","auth_user":"admin","auth_pass":"admin123"}`),
		Oracle:  json.RawMessage(`{"status_codes":[200],"keywords":["FLAG"]}`),
		Enabled: true,
	}
}

// TestCreateExpAssetRangeGateReject 拒绝路径：形状合法但靶场全败的 EXP
// 带 WithRangeGate() 进 Create/Update → 在触库之前就被闸门拦下（nil PG
// 不 panic 即证明闸门先于持久化执行）。
func TestCreateExpAssetRangeGateReject(t *testing.T) {
	lib := &ExpLibrary{} // pg 刻意为 nil：闸门失败路径不得触库

	broken := gateWeakCredExp("exp-gate-broken")
	broken.Exec = json.RawMessage(`{"kind":"http","method":"GET","url":"{target}/admin/","auth_user":"admin","auth_pass":"wrong"}`)
	if _, err := lib.CreateExpAsset(broken, WithRangeGate()); err == nil || !strings.Contains(err.Error(), "靶场闸门未放行") {
		t.Fatalf("create with gate should be rejected before persistence, got %v", err)
	}
	if err := lib.UpdateExpAsset(broken, 0, WithRangeGate()); err == nil || !strings.Contains(err.Error(), "靶场闸门未放行") {
		t.Fatalf("update with gate should be rejected before persistence, got %v", err)
	}

	// 不带闸门选项：语义校验通过后才会触库（这里 pg 为 nil，错误不再是闸门口径，
	// 证明可选参数缺省时行为不变）。
	if _, err := lib.CreateExpAsset(gateWeakCredExp("exp-gate-skip")); err == nil || strings.Contains(err.Error(), "靶场闸门") {
		t.Fatalf("without gate option the rejection must not come from the range gate, got %v", err)
	}
}

// TestExpLibraryRangeGateEndToEnd 放行路径：带闸门创建成功入库、坏迭代被
// 闸门拒绝、好迭代过闸更新（版本递增）。无 PG 配置时跳过。
func TestExpLibraryRangeGateEndToEnd(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	lib := &ExpLibrary{pg: pg}
	name := fmt.Sprintf("exp_gate_e2e_%d", time.Now().UnixNano())
	id, err := lib.CreateExpAsset(gateWeakCredExp(name), WithRangeGate())
	if err != nil {
		t.Fatalf("create with gate should pass: %v", err)
	}
	t.Cleanup(func() { _ = lib.DeleteExpAsset(id) })

	got, err := lib.GetExpAsset(id)
	if err != nil || got == nil {
		t.Fatalf("get after gated create: %v", err)
	}

	// 坏迭代：判据声明了不存在的关键字 → 闸门拒绝，库里不动。
	got.Oracle = json.RawMessage(`{"status_codes":[200],"keywords":["PWNED"]}`)
	if err := lib.UpdateExpAsset(got, got.Version, WithRangeGate()); err == nil || !strings.Contains(err.Error(), "靶场闸门未放行") {
		t.Fatalf("gated update with broken oracle must be rejected, got %v", err)
	}

	// 好迭代：描述更新过闸，版本 +1。
	got.Oracle = json.RawMessage(`{"status_codes":[200],"keywords":["FLAG"]}`)
	got.Desc = "迭代后的描述"
	if err := lib.UpdateExpAsset(got, got.Version, WithRangeGate()); err != nil {
		t.Fatalf("gated update with valid exp should pass: %v", err)
	}
	if g2, _ := lib.GetExpAsset(id); g2.Version != got.Version+1 || g2.Desc != "迭代后的描述" {
		t.Fatalf("gated update not applied: %+v", g2)
	}
}
