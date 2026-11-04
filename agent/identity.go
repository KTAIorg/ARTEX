// KT 身份直连（零模型 Key）：见 docs/adr/模型接入认证设计.md。
// ARTEX 只持身份凭据（client_credentials），用它在内存里换短时 access
// token，LLM 请求直接带 `Authorization: Bearer <token>` + `X-Kito-Token-Name`
// 打 NewAPI relay，由网关服务端换 managed relay token——sk- 全程不出网关。
// token 不落盘、不进日志、不进 llmrec 抓包（抓包层只记请求体）。
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IdentitySource 描述一条 KT 机器身份（对应 llm_identities 一行）。
type IdentitySource struct {
	// TokenURL 是 OAuth2 token 端点（grant_type=client_credentials）。
	TokenURL string
	// ClientID / ClientSecret 是 Casdoor 应用凭据。它是「身份凭据」而非
	// 模型 Key：泄漏它换不到模型额度，只能换短时身份 token。
	ClientID     string
	ClientSecret string
	// Scope 申请的 scope，空=不申请。
	Scope string
	// ManagedTokenName 是 X-Kito-Token-Name 头的值（如 artex）。NewAPI 按
	// principal 换发对应 managed relay token。
	ManagedTokenName string
}

const (
	// identityRefreshMargin 提前刷新余量：token 到期前 60s 即视为过期，
	// 避免边界上拿着将死的 token 出门。
	identityRefreshMargin = time.Minute
	// identityMaxTTL 是本地缓存上限；它不会延长签发方 TTL，也不改变
	// NewAPI/kt-identity 对 token 的在线校验。
	identityMaxTTL = 24 * time.Hour
)

// identityTokenSource 懒加载 + 单飞刷新的身份 token 缓存。token 只存在
// 进程内存； Invalidate 之后下一次 Token() 强制重新申请。
// fetcher 由调用方在包 identityTransport 之前快照（只含代理/抓包层），
// 绝不能含 identityTransport 自身——否则取 token 会递归进自己。
type identityTokenSource struct {
	src     IdentitySource
	fetcher *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func newIdentityTokenSource(src IdentitySource, fetcher *http.Client) *identityTokenSource {
	// client_credentials 的 secret 在 POST body 里；禁止跟随重定向，避免
	// 307/308 把表单重放到非预期主机。token 端点必须是最终 URL。
	client := *fetcher
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &identityTokenSource{src: src, fetcher: &client}
}

// FetchIdentityToken 做一次性的身份 token 交换（管理面低频调用用，如「拉取
// 模型列表」）：取一枚短时 token 用完即弃，不缓存。数据面请走 provider 的
// identityTransport（懒加载 + 刷新 + 401 重放）。
func FetchIdentityToken(src IdentitySource) (string, error) {
	fetcher := &http.Client{Timeout: 20 * time.Second}
	return newIdentityTokenSource(src, fetcher).Token()
}

type oauthTokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Token 返回当前可用的身份 token，过期则先刷新。并发调用单飞：拿到锁的
// 那个去刷新，其余等它写回后直接复用。
func (t *identityTokenSource) Token() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && time.Now().Before(t.expiresAt) {
		return t.token, nil
	}
	tok, expiry, err := t.fetch()
	if err != nil {
		return "", err
	}
	t.token, t.expiresAt = tok, expiry
	return tok, nil
}

// InvalidateIf 只丢弃实际遭遇 401 的那一枚 token。并发请求中，如果另一个
// goroutine 已经换到更新 token，就不能把它再清掉造成反复交换。
func (t *identityTokenSource) InvalidateIf(stale string) {
	t.mu.Lock()
	if t.token == stale {
		t.token, t.expiresAt = "", time.Time{}
	}
	t.mu.Unlock()
}

func (t *identityTokenSource) fetch() (string, time.Time, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", t.src.ClientID)
	form.Set("client_secret", t.src.ClientSecret)
	if t.src.Scope != "" {
		form.Set("scope", t.src.Scope)
	}
	// fetcher 已带独立短超时（见 newIdentityTokenSource），不吃 provider
	// 的长流式超时。
	resp, err := t.fetcher.PostForm(t.src.TokenURL, form)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("identity token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("identity token: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// OAuth2 错误响应（400/401）带 JSON body：先解析再报错，把
		// invalid_client 之类的诊断信息带出来，而不是只给一个状态码。
		var er oauthTokenResponse
		_ = json.Unmarshal(body, &er)
		if er.Error != "" {
			return "", time.Time{}, fmt.Errorf("identity token: %s: %s (status %d)", er.Error, er.ErrorDescription, resp.StatusCode)
		}
		return "", time.Time{}, fmt.Errorf("identity token: status %d", resp.StatusCode)
	}
	var tr oauthTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", time.Time{}, fmt.Errorf("identity token: bad json: %w", err)
	}
	if tr.AccessToken == "" {
		return "", time.Time{}, errors.New("identity token: empty access_token")
	}
	return tr.AccessToken, identityTokenExpiry(tr.AccessToken, tr.ExpiresIn, time.Now()), nil
}

// identityTokenExpiry 计算本地刷新时间，绝不延长签发方 TTL：
// expires_in 与 JWT exp 同时存在时取更早者；缺失/过短到期时间则返回 now，
// 让本次请求仍可使用 token，但下一次必须重新交换。JWT 只用于读取缓存
// 期限，不做任何认证决策（验签在 kt-identity introspect 侧）。
func identityTokenExpiry(token string, expiresIn int64, now time.Time) time.Time {
	issuerExpiry := time.Time{}
	if expiresIn > 0 {
		if expiresIn >= int64(identityMaxTTL/time.Second) {
			issuerExpiry = now.Add(identityMaxTTL)
		} else {
			issuerExpiry = now.Add(time.Duration(expiresIn) * time.Second)
		}
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err == nil {
		if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
			if issuerExpiry.IsZero() || exp.Time.Before(issuerExpiry) {
				issuerExpiry = exp.Time
			}
		}
	}
	if issuerExpiry.IsZero() {
		return now
	}
	if issuerExpiry.After(now.Add(identityMaxTTL)) {
		issuerExpiry = now.Add(identityMaxTTL)
	}
	refreshAt := issuerExpiry.Add(-identityRefreshMargin)
	if !refreshAt.After(now) {
		return now
	}
	return refreshAt
}

// identityTransport 在每个 LLM 请求上注入身份认证头：
//
//	Authorization: Bearer <身份 token>
//	X-Api-Key: <身份 token>            （anthropic 路径兼容；网关侧二选一读取）
//	X-Kito-Token-Name: <managed 名>
//
// SDK 侧由占位 APIKey 生成的认证头一律被覆写——占位值永不出门。401 时
// 强制刷新一次并重放（身份轮换窗口内的将死 token），重放仍复用同一体；
// 刷新失败或 token 未变则原样上抛，交给上层 provider 轮换。
type identityTransport struct {
	base    http.RoundTripper
	src     *identityTokenSource
	managed string
}

func (t identityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.src.Token()
	if err != nil {
		return nil, fmt.Errorf("identity auth: %w", err)
	}
	clone := req.Clone(req.Context())
	applyIdentityHeaders(clone, tok, t.managed)
	resp, err := t.base.RoundTrip(clone)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	// 401：token 可能已被轮换（如吊销后重启）。只失效本次失败的 token；
	// 若并发请求已换上新 token，Token() 会直接复用它。
	t.src.InvalidateIf(tok)
	fresh, rerr := t.src.Token()
	if rerr != nil || fresh == tok {
		return resp, nil // 刷新失败或 token 未变 = 真 401，原样上抛
	}
	if clone.GetBody == nil {
		return resp, nil // 无法重放 body（SSE 流已消费），上抛原 401
	}
	_ = resp.Body.Close()
	replay := req.Clone(req.Context())
	rc, gerr := replay.GetBody()
	if gerr != nil {
		return nil, gerr
	}
	replay.Body = rc
	applyIdentityHeaders(replay, fresh, t.managed)
	return t.base.RoundTrip(replay)
}

func applyIdentityHeaders(req *http.Request, token, managed string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Api-Key", token)
	if strings.TrimSpace(managed) != "" {
		req.Header.Set("X-Kito-Token-Name", strings.TrimSpace(managed))
	}
}
