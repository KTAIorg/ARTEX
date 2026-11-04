"use client";

import { auth } from "@/lib/auth";

// 前端灰度开关（按账号稳定分桶，同一账号每次结果一致）。
//
// 为什么不用随机数：灰度期间用户刷新页面不能一会儿新样式一会儿旧样式，
// 否则会被当成"页面在闪"。所以用「账号标识 → 稳定哈希 → 百分比桶」。
//
// 服务端/构建期读取 NEXT_PUBLIC_* 必须在 dev/build 时注入；改值要重启。

const BUCKET_STORAGE_KEY = "ui.bucket_id";

/** FNV-1a 32bit：够稳定、够短，不需要引依赖。 */
function hash32(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/**
 * 当前浏览器实例的稳定标识：优先账号（JWT sub），其次本地持久化的随机 id。
 * 未登录时也要有值，否则登录前后分桶会跳变。
 */
function bucketSeed(): string {
  const user = auth.getCurrentUser?.();
  if (user?.username) return `u:${user.username}`;
  if (typeof window === "undefined") return "ssr";
  let id = localStorage.getItem(BUCKET_STORAGE_KEY);
  if (!id) {
    id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    localStorage.setItem(BUCKET_STORAGE_KEY, id);
  }
  return `a:${id}`;
}

/** 读取百分比配置；非法值按 0 处理（默认全关）。 */
function percent(): number {
  // 注意：NEXT_PUBLIC_* 必须用静态属性访问，`process.env[name]` 在浏览器包里取不到值。
  const raw = Number.parseFloat(process.env.NEXT_PUBLIC_SORT_ARROW_V2_PERCENT ?? "0");
  if (!Number.isFinite(raw) || raw <= 0) return 0;
  return Math.min(100, raw);
}

/**
 * 排序箭头新版（双三角 caret）的灰度判定。
 * NEXT_PUBLIC_SORT_ARROW_V2_PERCENT：0=全关（默认）、100=全开、其余按账号分桶。
 */
export function sortArrowV2Enabled(): boolean {
  const pct = percent();
  if (pct === 0) return false;
  if (pct >= 100) return true;
  return hash32(bucketSeed()) % 100 < pct;
}
