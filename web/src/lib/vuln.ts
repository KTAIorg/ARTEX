// kt-vuln 用户令牌透传客户端（/api/vuln/*，经 ARTEX Go 代理转发，见 server/vulnproxy.go）。
// 与 lib/api.ts 的 http() 的差异：
// - 路径前缀是 /api/vuln（代理再剥掉 /api/vuln 转发到 kt-vuln 的 /api/*）；
// - 除 ARTEX JWT 外还必须带登录留存的 KT Identity opaque token（X-Identity-Token），
//   vuln 侧权限按真实用户判定；令牌缺失时直接抛友好错误，不打注定失败的请求；
// - 错误体兼容三种线上形态：kt-vuln writeErr 的 {"status":"error","message":"..."}、
//   租户中间件的 {"error":{"code","message"}}、ARTEX 代理/identity 层的 {"error":"..."}；
// - 上游判定 identity 令牌过期/无效时代理会回 X-Identity-Expired: true：只清
//   identity 令牌（不动 ARTEX 会话），提示用户重新通过 Telegram 登录换取新令牌。

import { http } from "@/lib/api";
import { auth } from "@/lib/auth";

export interface VulnAsset {
  id: number;
  ip: string;
  port: number;
  scheme?: string;
  hostnames?: string[];
  title?: string;
  php_version?: string;
  country?: string;
  last_seen?: string;
  component?: string;
  version?: string;
  verdict?: string;
  score?: number;
  tier?: string;
  manual_tier?: string;
  rating_note?: string;
  biz_type?: string;
  engagement_status?: string;
  engagement_owner?: string;
}

export interface VulnCve {
  cve_id: string;
  title: string;
  category?: string;
  severity?: number;
  kev?: boolean;
  affected?: Record<string, string[]>;
  surface?: {
    vulnerable: number;
    executable: number;
    patched: number;
    not_applicable: number;
    unknown: number;
  };
}

// 与 kt-vuln ListAssets 支持的过滤参数对齐。tier 按契约保留发送
// （当前部署版忽略该参数，后端补上后前端无需改动）。
export interface VulnAssetFilters {
  q?: string;
  tier?: string;
  biz_type?: string;
  verdict?: string;
  country?: string;
  min_score?: number;
  cve?: string;
  engagement?: string;
  sort?: string;
}

export type VulnRatingTier = "S" | "A" | "B" | "C" | "D" | "exclude";
export type VulnEngagementStatus =
  | "todo"
  | "claimed"
  | "in_progress"
  | "done_hit"
  | "done_miss"
  | "blocked"
  | "excluded";

// 任务下发的 kt-vuln 资产快照行（vuln-workset）。快照是下发那一刻的凭证：
// 事实源始终在 vuln.ktyun.cc，之后 tier/verdict 变化不会回写到快照。
export interface VulnWorksetItem {
  vuln_asset_id: number;
  url: string;
  host: string;
  port: number;
  scheme: string;
  title?: string;
  tier?: string;
  manual_tier?: string;
  score?: number;
  cve?: string;
  verdict?: string;
  biz_type?: string;
}

// 下发 → 任务创建之间的快照中转：sessionStorage 按页签隔离，任务创建成功
// pin 到新任务后即清除；未清理的残留会在下一次下发时被覆盖。
export const VULN_WS_DRAFT_KEY = "vuln_ws_draft";

export function saveVulnWorksetDraft(items: VulnWorksetItem[]) {
  sessionStorage.setItem(VULN_WS_DRAFT_KEY, JSON.stringify({ items }));
}

// 读回时做最小形状校验：坏数据（手改/旧版本残留）当作没有草稿处理。
export function readVulnWorksetDraft(): VulnWorksetItem[] {
  try {
    const raw = sessionStorage.getItem(VULN_WS_DRAFT_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as { items?: unknown };
    if (!Array.isArray(parsed.items)) return [];
    return parsed.items.filter(
      (item): item is VulnWorksetItem =>
        !!item && typeof item === "object" && typeof (item as VulnWorksetItem).vuln_asset_id === "number",
    );
  } catch {
    return [];
  }
}

export function clearVulnWorksetDraft() {
  sessionStorage.removeItem(VULN_WS_DRAFT_KEY);
}

const MISSING_IDENTITY_MSG = "缺少 KT Identity 令牌，请退出后通过 Telegram 重新登录";

async function vulnHttp<T>(path: string, init?: RequestInit): Promise<T> {
  const identity = auth.getIdentityToken();
  if (!identity) throw new Error(MISSING_IDENTITY_MSG);
  const token = auth.getToken();
  const r = await fetch(`/api/vuln${path}`, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      "X-Identity-Token": identity,
      ...(init?.headers as Record<string, string> | undefined),
    },
  });
  if (r.status === 401) {
    // 上游明确指出是 identity 令牌问题：只清 identity 令牌，保留 ARTEX 会话。
    if (r.headers.get("X-Identity-Expired") === "true") {
      auth.clearIdentityToken();
      throw new Error("KT Identity 令牌已过期或失效，请退出后通过 Telegram 重新登录");
    }
    if (typeof window !== "undefined") {
      localStorage.removeItem("artex_token");
      localStorage.removeItem("artex.identity_token");
      document.cookie = "artex_token=; path=/; max-age=0";
      window.location.href = "/login";
    }
    throw new Error("未授权");
  }
  if (!r.ok) {
    const fallback = `${init?.method ?? "GET"} ${path}: ${r.status}`;
    let message = fallback;
    try {
      const payload = (await r.json()) as {
        error?: unknown;
        message?: unknown;
        status?: unknown;
      };
      // 按优先级取第一个非空文案：message（writeErr / 租户中间件嵌套）→
      // error 字符串（ARTEX 代理 / identity 层）→ status（契约示例形态，writeErr 恒为 "error"）。
      const parts: unknown[] = [
        payload.message,
        typeof payload.error === "string" ? payload.error : undefined,
        typeof payload.error === "object" && payload.error !== null
          ? (payload.error as { message?: unknown }).message
          : undefined,
        payload.status !== "error" ? payload.status : undefined,
      ];
      const found = parts.find((p): p is string => typeof p === "string" && p.trim() !== "");
      if (found) message = found.trim();
    } catch {
      // 空/非 JSON 响应保留状态码兜底信息。
    }
    throw new Error(message);
  }
  if (r.status === 204) return undefined as T;
  return r.json();
}

export const vuln = {
  // 服务端分页的资产目录查询；limit 上限 1000（kt-vuln 侧钳制）。
  assets: (limit: number, offset: number, filters: VulnAssetFilters = {}) => {
    const p = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    for (const [k, v] of Object.entries(filters)) {
      if (v === undefined || v === "") continue;
      if (typeof v === "number" && !Number.isFinite(v)) continue;
      p.set(k, String(v));
    }
    return vulnHttp<{ items: VulnAsset[] | null; total: number }>(`/assets?${p.toString()}`).then((r) => ({
      items: r.items ?? [],
      total: r.total ?? 0,
    }));
  },

  // CVE 情报列表（当前实现一次返回全量，limit 仅作占位）。
  cves: (filters: { kev?: boolean; category?: string; limit?: number } = {}) => {
    const p = new URLSearchParams();
    if (filters.kev) p.set("kev", "true");
    if (filters.category) p.set("category", filters.category);
    if (filters.limit) p.set("limit", String(filters.limit));
    const qs = p.toString();
    return vulnHttp<{ items: VulnCve[] | null }>(`/cves${qs ? `?${qs}` : ""}`).then((r) => r.items ?? []);
  },

  // 人工评级（单资产）：404 = 资产不存在。
  rate: (assetId: number, tier: VulnRatingTier, note?: string) =>
    vulnHttp<{ ok: boolean }>("/ratings", {
      method: "POST",
      body: JSON.stringify({ asset_id: assetId, tier, note: note?.trim() ? note.trim() : undefined }),
    }),

  // 批量打标签：tag_type 如 biz_type / tech / risk；单次上限 5000 条。
  tagBulk: (tags: { asset_id: number; tag_type: string; tag_value: string; confidence?: number }[]) =>
    vulnHttp<{ written: number }>("/tags/bulk", { method: "POST", body: JSON.stringify({ tags }) }),

  // 作业状态流转（单资产）。
  engage: (assetId: number, status: VulnEngagementStatus, owner?: string, note?: string) =>
    vulnHttp<{ asset_id: number; status: string }>("/engagements", {
      method: "POST",
      body: JSON.stringify({
        asset_id: assetId,
        status,
        owner: owner?.trim() ? owner.trim() : undefined,
        note: note?.trim() ? note.trim() : undefined,
      }),
    }),

  // ---- 任务 Vuln 工作集（ARTEX 自有 API /api/tasks/{id}/vuln-workset）----
  // 注意：这两个不是 /api/vuln 代理（不带 X-Identity-Token 双头），走 lib/api
  // 的 http()——与任务页其余调用同一套 ARTEX JWT 鉴权与错误处理。
  // pin：任务创建成功后把下发时抓的资产快照挂到新任务上。
  pinTaskWorkset: (taskId: string, items: VulnWorksetItem[]) =>
    http<{ items: number }>(`/tasks/${encodeURIComponent(taskId)}/vuln-workset`, {
      method: "POST",
      body: JSON.stringify({ items }),
    }),
  // list：任务详情读取工作集快照（空/未部署端点返回空数组）。
  taskWorkset: (taskId: string) =>
    http<{ items: VulnWorksetItem[] | null }>(`/tasks/${encodeURIComponent(taskId)}/vuln-workset`).then(
      (r) => r.items ?? [],
    ),
};
