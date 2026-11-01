"use client";

import * as React from "react";

import { RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";

import { VulnCvesPanel } from "../_components/panels";

// Vuln 情报站 · CVE 列表（kt-vuln CVE 情报）。
// v0.4.0 前是资产页的「CVE 情报」tab；「查看资产」下钻（drill→cveId 锁定视图）留在本页内。
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
      <VulnCvesPanel refreshKey={refreshKey} />
    </div>
  );
}

export default function VulnCvesPage() {
  return <VulnCvesContent />;
}
