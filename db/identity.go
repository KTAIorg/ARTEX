package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// ---------- LLM identities（KT 身份直连） ----------
// 见 docs/adr/模型接入认证设计.md：llm_identities 存的是 Casdoor
// client_credentials 身份凭据，不是模型 Key。泄漏它换不到模型额度，
// 只能换短时身份 token，且还要过 kt-identity introspect + NewAPI 影子
// 用户两道闸；权威断供入口是删除 relay scope 或禁用 NewAPI 影子用户。
// Casdoor 应用禁用只阻止签发新 token，旧 JWT 仍受原 exp 约束。

// LLMIdentity 是一条可被多个 llm_profile 共用的机器身份。
type LLMIdentity struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// TokenURL 是 OAuth2 token 端点（grant_type=client_credentials），
	// 如 https://auth.ktyun.cc/api/login/oauth/access_token。
	TokenURL string `json:"token_url"`
	ClientID string `json:"client_id"`
	// ClientSecret 永不序列化给 UI；读取走 IdentityByID（仅服务端使用）。
	ClientSecret     string `json:"-"`
	ClientSecretHint string `json:"client_secret_hint,omitempty"`
	// Scope 是申请的 scope（如 newapi.relay），空=不申请。
	Scope string `json:"scope,omitempty"`
	// ManagedTokenName 是 relay 侧 managed token 名（X-Kito-Token-Name 头的
	// 值，如 artex）。NewAPI 按 principal 换发对应 managed relay token。
	ManagedTokenName string `json:"managed_token_name"`
}

// identityColsHint 是列表查询列（只带 hint，不带 secret）；
// identityColsSecret 是单行加载列（带 secret，仅服务端内部使用）。
const identityColsHint = `id,name,token_url,client_id,COALESCE(client_secret_hint,''),COALESCE(scope,''),COALESCE(managed_token_name,'')`
const identityColsSecret = `id,name,token_url,client_id,client_secret,COALESCE(scope,''),COALESCE(managed_token_name,'')`

func scanIdentity(sc interface{ Scan(...any) error }, into *string, i *LLMIdentity) error {
	return sc.Scan(&i.ID, &i.Name, &i.TokenURL, &i.ClientID, into, &i.Scope, &i.ManagedTokenName)
}

// ListIdentities 返回全部身份（只含 secret 尾 4 位 hint）。
func (d *DB) ListIdentities() ([]*LLMIdentity, error) {
	rows, err := d.Query(`SELECT ` + identityColsHint + ` FROM llm_identities ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*LLMIdentity
	for rows.Next() {
		var i LLMIdentity
		if err := scanIdentity(rows, &i.ClientSecretHint, &i); err != nil {
			return nil, err
		}
		out = append(out, &i)
	}
	return out, rows.Err()
}

// IdentityByID 返回单条身份（含 secret），找不到返回 (nil, nil)。
func (d *DB) IdentityByID(id int64) (*LLMIdentity, error) {
	var i LLMIdentity
	err := scanIdentity(d.QueryRow(`SELECT `+identityColsSecret+` FROM llm_identities WHERE id=$1`, id), &i.ClientSecret, &i)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// ErrIdentityInUse 拒删仍被 profile 引用的身份：静默 SET NULL 会让这些
// profile 悄悄失效（identity 模式无 identity 不可用），必须显式报错。
var ErrIdentityInUse = errors.New("LLM identity is still referenced by profiles")

// SaveIdentity 插入（id==0）或更新。更新时 secret 为空 = 保留原值（与
// SaveProfile 的 api_key 语义一致，避免前端回显不了明文就丢钥匙）。
func (d *DB) SaveIdentity(i *LLMIdentity) (int64, error) {
	i.Name = strings.TrimSpace(i.Name)
	i.TokenURL = strings.TrimSpace(i.TokenURL)
	i.ClientID = strings.TrimSpace(i.ClientID)
	i.Scope = strings.TrimSpace(i.Scope)
	i.ManagedTokenName = strings.TrimSpace(i.ManagedTokenName)
	hint := i.ClientSecretHint
	if len(i.ClientSecret) >= 4 {
		hint = "…" + i.ClientSecret[len(i.ClientSecret)-4:]
	}
	if i.ID == 0 {
		var id int64
		err := d.QueryRow(`INSERT INTO llm_identities(name,token_url,client_id,client_secret,client_secret_hint,scope,managed_token_name)
VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7) RETURNING id`,
			i.Name, i.TokenURL, i.ClientID, i.ClientSecret, hint, i.Scope, i.ManagedTokenName).Scan(&id)
		return id, err
	}
	if i.ClientSecret == "" {
		_, err := d.Exec(`UPDATE llm_identities SET name=$1,token_url=$2,client_id=$3,scope=NULLIF($4,''),managed_token_name=$5 WHERE id=$6`,
			i.Name, i.TokenURL, i.ClientID, i.Scope, i.ManagedTokenName, i.ID)
		return i.ID, err
	}
	_, err := d.Exec(`UPDATE llm_identities SET name=$1,token_url=$2,client_id=$3,client_secret=$4,client_secret_hint=$5,scope=NULLIF($6,''),managed_token_name=$7 WHERE id=$8`,
		i.Name, i.TokenURL, i.ClientID, i.ClientSecret, hint, i.Scope, i.ManagedTokenName, i.ID)
	return i.ID, err
}

// DeleteIdentity 删除身份；仍被 profile 引用时返回 ErrIdentityInUse。
// 原子性由 llm_profiles.identity_id 的 ON DELETE RESTRICT 外键保证：
// 不做 count-then-delete，避免并发绑定落在计数与删除之间被静默置空。
func (d *DB) DeleteIdentity(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM llm_identities WHERE id=$1`, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return ErrIdentityInUse
		}
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
