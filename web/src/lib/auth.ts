const TOKEN_KEY = "sid";
const ROLES_KEY = "roles";
// KT Identity opaque token：登录换发时原样留存（P1 起不再用完即丢），供
// /api/vuln/* 用户令牌透传代理——vuln 权限按用户判定、审计归因真实用户。
// 只存 localStorage，不写 cookie（不参与服务端路由守卫）。
const IDENTITY_TOKEN_KEY = "idt";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 天（秒）

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo：无真实登录，返回一个假 token 让路由守卫放行、直接进主界面。
    return localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // 同步写 cookie，供 Next.js middleware 服务端读取
    document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ROLES_KEY);
    // identity 令牌与 ARTEX 会话同生共死：登出/401 清理路径一并抹掉，
    // 不给 /api/vuln 代理留下过期 opaque token。
    localStorage.removeItem(IDENTITY_TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
  },

  getIdentityToken(): string | null {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(IDENTITY_TOKEN_KEY);
  },

  setIdentityToken(token: string): void {
    localStorage.setItem(IDENTITY_TOKEN_KEY, token);
  },

  clearIdentityToken(): void {
    localStorage.removeItem(IDENTITY_TOKEN_KEY);
  },

  // 登录角色（admin/operator/viewer），随 token 一起落 localStorage。
  // 缺失/损坏一律回 viewer：前端显隐只是 UX，真正权限由后端 JWT + 403 兜底。
  getRoles(): string[] {
    if (typeof window === "undefined") return ["viewer"];
    try {
      const parsed = JSON.parse(localStorage.getItem(ROLES_KEY) ?? "null");
      if (Array.isArray(parsed) && parsed.length > 0 && parsed.every((r) => typeof r === "string")) {
        return parsed;
      }
    } catch {
      // 落默认 viewer
    }
    return ["viewer"];
  },

  setRoles(roles: string[]): void {
    if (roles.length > 0) localStorage.setItem(ROLES_KEY, JSON.stringify(roles));
    else localStorage.removeItem(ROLES_KEY);
  },

  // 从 JWT payload 的 sub 字段解析当前用户，仅用于展示，不做签名验证。
  getCurrentUser(): CurrentUser | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      // base64url → base64
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      const username: string = payload.sub ?? "admin";
      return { id: "1", name: username, username, email: "", avatar: "", role: "operator" };
    } catch {
      return null;
    }
  },
};
