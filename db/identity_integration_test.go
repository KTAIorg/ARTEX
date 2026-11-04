package db

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestIdentityPostgresIntegration 用真实 PostgreSQL 验证新 DDL、重复启动和
// identity/static 两种 profile 的存取与删除约束。默认跳过；仅在显式提供
// 一次性测试库时运行：
//
//	ARTEX_TEST_PG_DSN=postgres://...@127.0.0.1:5433/artex_identity_test?sslmode=disable go test ./db -run IdentityPostgres -count=1
//
// 库名必须带 artex_identity_test 前缀，防止误连业务库执行破坏性升级演练。
func TestIdentityPostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ARTEX_TEST_PG_DSN"))
	if dsn == "" {
		t.Skip("ARTEX_TEST_PG_DSN not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "artex_identity_test") {
		t.Fatalf("ARTEX_TEST_PG_DSN must name a disposable artex_identity_test* database")
	}
	ctx := context.Background()

	d, err := Open(dsn)
	if err != nil {
		t.Fatalf("open fresh database: %v", err)
	}
	defer d.Close()
	// schema.sql 每次启动都会 Exec；第二次 Open 必须完全幂等。
	second, err := Open(dsn)
	if err != nil {
		t.Fatalf("reopen and reapply schema: %v", err)
	}
	_ = second.Close()

	identityID, err := d.SaveIdentity(&LLMIdentity{
		Name: "artex-test", TokenURL: "https://auth.example.test/token", ClientID: "artex",
		ClientSecret: "dummy-client-secret", Scope: "newapi.relay", ManagedTokenName: "artex",
	})
	if err != nil {
		t.Fatalf("save identity: %v", err)
	}
	ident, err := d.IdentityByID(identityID)
	if err != nil || ident == nil {
		t.Fatalf("load identity: ident=%v err=%v", ident, err)
	}
	if ident.ClientSecret != "dummy-client-secret" || ident.ClientSecretHint != "" {
		t.Fatalf("secret-bearing load returned unexpected hint/secret: hint=%q", ident.ClientSecretHint)
	}
	listed, err := d.ListIdentities()
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	var listedIdentity *LLMIdentity
	for _, item := range listed {
		if item.ID == identityID {
			listedIdentity = item
			break
		}
	}
	if listedIdentity == nil || listedIdentity.ClientSecret != "" || listedIdentity.ClientSecretHint != "…cret" {
		t.Fatalf("list must contain only the tail hint: %#v", listedIdentity)
	}

	profileID, err := d.SaveProfile(&LLMProfile{
		Name: "identity-test", Format: "openai", BaseURL: "https://ktapi.cc", Model: "test-model",
		AuthMode: "identity", IdentityID: identityID, Streaming: true,
	})
	if err != nil {
		t.Fatalf("save identity profile: %v", err)
	}
	profile, err := d.ProfileByID(profileID)
	if err != nil || profile == nil {
		t.Fatalf("load identity profile: profile=%v err=%v", profile, err)
	}
	if profile.AuthMode != "identity" || profile.IdentityID != identityID || profile.APIKey != "" {
		t.Fatalf("unexpected identity profile: mode=%q identity=%d key=%q", profile.AuthMode, profile.IdentityID, profile.APIKey)
	}
	pool, err := d.PoolProfiles()
	if err != nil {
		t.Fatalf("pool profiles: %v", err)
	}
	poolContains := false
	for _, item := range pool {
		if item.ID == profileID {
			poolContains = true
			break
		}
	}
	if !poolContains {
		t.Fatalf("identity profile without key must enter failover pool: %#v", pool)
	}
	if err := d.DeleteIdentity(ctx, identityID); !errors.Is(err, ErrIdentityInUse) {
		t.Fatalf("delete referenced identity: err=%v want ErrIdentityInUse", err)
	}

	// 切回 static 时写入 key 并解除身份引用；旧 profile 可无损回滚。
	if _, err := d.SaveProfile(&LLMProfile{
		ID: profileID, Name: "identity-test", Format: "openai", BaseURL: "https://ktapi.cc", Model: "test-model",
		APIKey: "dummy-static-key", AuthMode: "static", Streaming: true,
	}); err != nil {
		t.Fatalf("switch profile to static: %v", err)
	}
	profile, err = d.ProfileByID(profileID)
	if err != nil || profile.AuthMode != "static" || profile.IdentityID != 0 || profile.APIKey != "dummy-static-key" {
		t.Fatalf("unexpected static profile after rollback: %#v err=%v", profile, err)
	}
	if err := d.DeleteIdentity(ctx, identityID); err != nil {
		t.Fatalf("delete unreferenced identity: %v", err)
	}

	// 升级演练：模拟旧库没有本次三处 DDL，再由 Open 补回。只操作一次性测试库。
	if _, err := d.Exec(`ALTER TABLE llm_profiles DROP COLUMN identity_id, DROP COLUMN auth_mode`); err != nil {
		t.Fatalf("simulate pre-identity profile table: %v", err)
	}
	if _, err := d.Exec(`DROP TABLE llm_identities`); err != nil {
		t.Fatalf("simulate pre-identity schema: %v", err)
	}
	upgraded, err := Open(dsn)
	if err != nil {
		t.Fatalf("upgrade pre-identity schema: %v", err)
	}
	defer upgraded.Close()
	profile, err = upgraded.ProfileByID(profileID)
	if err != nil || profile == nil || profile.AuthMode != "static" || profile.IdentityID != 0 {
		t.Fatalf("upgraded legacy profile changed behavior: %#v err=%v", profile, err)
	}
	var fkDef string
	if err := upgraded.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='llm_profiles_identity_id_fkey'`).Scan(&fkDef); err != nil {
		t.Fatalf("read identity FK after upgrade: %v", err)
	}
	if !strings.Contains(fkDef, "ON DELETE RESTRICT") {
		t.Fatalf("identity FK must reject referenced deletion atomically: %s", fkDef)
	}
}
