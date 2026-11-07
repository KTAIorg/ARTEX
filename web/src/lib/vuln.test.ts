// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { auth } from "@/lib/auth";
import { type VulnCveSyncStatus, vuln } from "@/lib/vuln";

function syncStatus(status: VulnCveSyncStatus["status"]): VulnCveSyncStatus {
  return {
    source: "nvd",
    status,
    trigger: "manual",
    cursor: null,
    checkpoint_start: null,
    checkpoint_end: null,
    next_start_index: 0,
    total_results: 0,
    items_upserted: 0,
    started_at: null,
    finished_at: null,
    last_success_at: null,
    last_error: null,
    updated_at: "2026-11-07T04:00:00Z",
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("CVE 同步 API", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    localStorage.clear();
    auth.setToken("artex-test-token");
    auth.setIdentityToken("identity-test-token");
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("经 ARTEX 代理读取状态并透传当前用户双令牌", async () => {
    fetchMock.mockResolvedValue(jsonResponse(syncStatus("idle")));

    await expect(vuln.cveSyncStatus()).resolves.toMatchObject({ source: "nvd", status: "idle" });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(url).toBe("/api/vuln/cve-catalog/sync");
    expect(init.method).toBeUndefined();
    expect(headers.get("Authorization")).toBe("Bearer artex-test-token");
    expect(headers.get("X-Identity-Token")).toBe("identity-test-token");
  });

  it("用无请求体 POST 触发异步同步并接受本轮 running 202", async () => {
    const running = { ...syncStatus("running"), started_at: "2026-11-07T04:01:00Z" };
    fetchMock.mockResolvedValue(jsonResponse({ accepted: true, status: running }, 202));

    await expect(vuln.triggerCveSync()).resolves.toMatchObject({
      accepted: true,
      status: { status: "running", started_at: "2026-11-07T04:01:00Z" },
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/vuln/cve-catalog/sync");
    expect(init.method).toBe("POST");
    expect(init.body).toBeUndefined();
    expect(new Headers(init.headers).get("Content-Type")).toBeNull();
  });

  it("保留上游 403 状态供权限反馈使用", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ status: "error", message: "admin required" }, 403));

    await expect(vuln.triggerCveSync()).rejects.toMatchObject({ status: 403, message: "admin required" });
  });
});
