"use client";

// Vuln 情报站 · CVE 列表（kt-vuln CVE 情报）。
// v0.4.0 前是资产页的「CVE 情报」tab；「查看资产」下钻（drill→cveId 锁定视图）留在本页内。
// v0.4.2 起双 tab：关注清单（原面板原样）+ 全量目录（NVD 字典，服务端分页）。

import * as React from "react";

import { RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import { VulnCvesPanel } from "../_components/panels";
import { VulnCvesCatalogPanel } from "../_components/panels-catalog";

function VulnCvesContent() {
  // 面板自己的重载信号：等价于原资产页由「刷新」按钮驱动的 vulnRefreshKey。
  const [refreshKey, setRefreshKey] = React.useState(0);

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
      <Tabs defaultValue="focus" className="min-h-0 flex-1">
        <TabsList>
          <TabsTrigger value="focus">关注清单</TabsTrigger>
          <TabsTrigger value="catalog">全量目录</TabsTrigger>
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
          <VulnCvesCatalogPanel refreshKey={refreshKey} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default function VulnCvesPage() {
  return <VulnCvesContent />;
}
