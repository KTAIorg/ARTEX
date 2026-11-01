"use client";

import * as React from "react";

import { RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";

import { VulnAssetsPanel } from "../_components/panels";

// Vuln 情报站 · 情报（kt-vuln 资产目录）。
// v0.4.0 前是资产页的「漏洞库」tab；数据/筛选/写操作逻辑全在 VulnAssetsPanel，不变。
function VulnAssetsContent() {
  // 面板自己的重载信号：等价于原资产页由「刷新」按钮驱动的 vulnRefreshKey
  // （回到第一页、清空勾选并重拉当前筛选）。
  const [refreshKey, setRefreshKey] = React.useState(0);

  return (
    <div className="flex h-[calc(100vh-6rem)] min-h-0 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">情报</h1>
          <p className="text-sm text-muted-foreground">vuln.ktyun.cc 实时资产目录 · 唯一事实源</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setRefreshKey((k) => k + 1)}>
          <RefreshCwIcon className="size-4" /> 刷新
        </Button>
      </div>
      <VulnAssetsPanel refreshKey={refreshKey} />
    </div>
  );
}

export default function VulnAssetsPage() {
  return <VulnAssetsContent />;
}
