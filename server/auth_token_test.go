package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// extractToken 是三种取令牌方式的唯一入口：Authorization 头 > sid cookie > ?token=。
// cookie 名在指纹中性化时从 artex_token 改成 sid，这里把顺序与旧名失效一起钉住，
// 避免以后有人为兼容又把旧名加回来（旧名本身就是可检索的产品指纹）。
func TestExtractTokenOrderAndCookieRename(t *testing.T) {
	t.Run("Authorization 头优先于 cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/x", nil)
		r.Header.Set("Authorization", "Bearer from-header")
		r.AddCookie(&http.Cookie{Name: "sid", Value: "from-cookie"})
		if got := extractToken(r); got != "from-header" {
			t.Fatalf("extractToken=%q want from-header", got)
		}
	})

	t.Run("无头时读 sid cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/x", nil)
		r.AddCookie(&http.Cookie{Name: "sid", Value: "from-cookie"})
		if got := extractToken(r); got != "from-cookie" {
			t.Fatalf("extractToken=%q want from-cookie", got)
		}
	})

	t.Run("旧 cookie 名不再被接受", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/x", nil)
		r.AddCookie(&http.Cookie{Name: "artex_token", Value: "legacy"})
		if got := extractToken(r); got != "" {
			t.Fatalf("extractToken=%q want empty（旧名必须失效）", got)
		}
	})

	t.Run("SSE 场景的 ?token= 兜底", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/x?token=from-query", nil)
		if got := extractToken(r); got != "from-query" {
			t.Fatalf("extractToken=%q want from-query", got)
		}
	})
}
