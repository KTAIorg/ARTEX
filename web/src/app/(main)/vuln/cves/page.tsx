"use client";

// Vuln 情报站 · CVE 列表（kt-vuln CVE 情报）。
// v0.4.0 前是资产页的「CVE 情报」tab；「查看资产」下钻（drill→cveId 锁定视图）留在本页内。
// v0.4.2 起双 tab：关注清单（原面板原样）+ 全量目录（NVD 字典，服务端分页）。

import * as React from "react";

import { RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import { vuln } from "@/lib/vuln";

import { VulnCveSyncControls } from "../_components/cve-sync-controls";
import { VulnCvesPanel } from "../_components/panels";
import { VulnCvesCatalogPanel } from "../_components/panels-catalog";

function VulnCvesContent() {
  // 面板自己的重载信号：等价于原资产页由「刷新」按钮驱动的 vulnRefreshKey。
  const [refreshKey, setRefreshKey] = React.useState(0);
  // Tab 状态进 URL（?tab=focus|catalog）：刷新、分享、从详情返回都停在同一个视图。
  // 用 window 读写而不是 useSearchParams，避免静态预渲染时的 Suspense 约束。
  const [tab, setTab] = React.useState("focus");
  // Tab 上的人数/条数：让「两个目录」一眼可辨（关注清单 36 vs 全量目录 28 万）。
  const [counts, setCounts] = React.useState<{ focus?: number; catalog?: number }>({});

  React.useEffect(() => {
    let cancelled = false;
    Promise.all([
      vuln
        .cves()
        .then((list) => list.length)
        .catch(() => undefined),
      vuln
        .cveCatalog(1, 1)
        .then((r) => r.total)
        .catch(() => undefined),
    ]).then(([focus, catalog]) => {
      if (!cancelled) setCounts({ focus, catalog });
    });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  React.useEffect(() => {
    const value = new URLSearchParams(window.location.search).get("tab");
    if (value === "focus" || value === "catalog") setTab(value);
  }, []);

  const refreshCatalog = React.useCallback(() => setRefreshKey((k) => k + 1), []);

  const handleTabChange = (value: string) => {
    setTab(value);
    const url = new URL(window.location.href);
    url.searchParams.set("tab", value);
    window.history.replaceState(null, "", url.toString());
  };

  return (
    <div className="flex h-[calc(100vh-6rem)] min-h-0 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">CVE列表</h1>
          <p className="text-sm text-muted-foreground">vuln.ktyun.cc CVE 情报 · 唯一事实源</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setRefreshKey((k) => k + 1)}>
          <RefreshCwIcon className="size-4" /> 刷新
        </Button>
      </div>
      <Tabs value={tab} onValueChange={handleTabChange} className="min-h-0 flex-1">
        <TabsList variant="line">
          <TabsTrigger value="focus" className="gap-1.5 px-3 data-[state=active]:font-semibold">
            关注清单
            {counts.focus !== undefined ? (
              <span className="text-muted-foreground text-[11px] tabular-nums">{counts.focus}</span>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="catalog" className="gap-1.5 px-3 data-[state=active]:font-semibold">
            全量目录
            {counts.catalog !== undefined ? (
              <span className="text-muted-foreground text-[11px] tabular-nums">
                {counts.catalog.toLocaleString("zh-CN")}
              </span>
            ) : null}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="focus" className="flex min-h-0 flex-1 flex-col gap-2">
          <p className="text-muted-foreground text-xs">
            关注清单：约 36 条精选 CVE，带资产暴露面统计，可下钻受影响资产。
          </p>
          <VulnCvesPanel refreshKey={refreshKey} />
        </TabsContent>
        <TabsContent value="catalog" className="flex min-h-0 flex-1 flex-col gap-2">
          <p className="text-muted-foreground text-xs">
            全量目录：NVD 同步的全量 CVE 字典（28 万+ 条），仅元数据、无暴露面。
          </p>
          <VulnCveSyncControls onSynced={refreshCatalog} />
          <VulnCvesCatalogPanel refreshKey={refreshKey} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default function VulnCvesPage() {
  return <VulnCvesContent />;
}
