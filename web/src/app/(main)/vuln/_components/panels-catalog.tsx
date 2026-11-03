"use client";

// CVE 全量目录面板（/api/vuln/cve-catalog 透传代理 → kt-vuln NVD 字典，28 万+ 条）。
// 与 panels.tsx 的 VulnCvesPanel（关注清单）互补：这里只有元数据、无暴露面统计，
// 服务端分页检索（page 从 1 起、page_size 上限 200）；fetch/鉴权走 lib/vuln 的
// vulnHttp 封装（与关注清单同一链路），空态文案与严重度徽章复用 panels.tsx。

import * as React from "react";

import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";

import { PAGE_SIZES } from "@/components/asset-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

import { type VulnCveCatalogItem, type VulnCve, vuln } from "@/lib/vuln";

import { cveEmptyMessage, VulnCollectDialog, VulnSeverityBadge } from "./panels";

export function VulnCvesCatalogPanel({ refreshKey }: { refreshKey: number }) {
  // 草稿筛选：输入中不触发请求，点「筛选」才提交（28 万条目录避免无谓翻页查询）。
  const [fq, setFq] = React.useState("");
  const [fYear, setFYear] = React.useState("all");
  const [applied, setApplied] = React.useState<{ q?: string; year?: number }>({});
  const [rows, setRows] = React.useState<VulnCveCatalogItem[]>([]);
  const [total, setTotal] = React.useState(0);
  // 内部 0-based（与资产面板一致），调 API 时 +1 转成服务端 1-based 页码。
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [years, setYears] = React.useState<{ year: number; count: number }[]>([]);
  // Shodan 采集（#192）：目录无影响组件元数据，查询由用户在弹窗中手填。
  const [collecting, setCollecting] = React.useState(false);
  const [collectTarget, setCollectTarget] = React.useState<{ cve: VulnCve; query: string } | null>(null);

  const submitCollect = async () => {
    if (!collectTarget) return;
    const query = collectTarget.query.trim();
    if (!query) {
      toast.error("请填写 Shodan 查询体，如 \"log4j country:CN\"");
      return;
    }
    setCollecting(true);
    try {
      const resp = await fetch("/api/vuln/shodan-collect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, cve_id: collectTarget.cve.cve_id, max_pages: 5 }),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        toast.error(String(data?.error ?? `入队失败（HTTP ${resp.status}）`));
        return;
      }
      toast.success(`已入队采集（job #${data.job_id}）：${query}，完成后资产自动入库`);
      setCollectTarget(null);
    } catch (e) {
      toast.error(`采集入队失败：${String((e as Error)?.message ?? e)}`);
    } finally {
      setCollecting(false);
    }
  };
  const reqRef = React.useRef(0);

  // 年份桶懒加载一次（下拉数据源）；失败不阻塞主列表，仅少一个筛选项。
  React.useEffect(() => {
    let cancelled = false;
    vuln
      .cveCatalogYears()
      .then((ys) => {
        if (!cancelled) setYears(ys);
      })
      .catch(() => {
        // 年份桶拉取失败时静默降级：下拉只剩「全部年份」，主列表不受影响。
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const applyFilters = () => {
    const y = Number.parseInt(fYear, 10);
    setApplied({ q: fq.trim() || undefined, year: fYear !== "all" && Number.isFinite(y) ? y : undefined });
  };

  const clearFilters = () => {
    setFq("");
    setFYear("all");
    setApplied({});
  };

  // 生效筛选 / 外部刷新回到第一页。
  // biome-ignore lint/correctness/useExhaustiveDependencies: applied/refreshKey 变化是重置分页的显式触发器。
  React.useEffect(() => {
    setPage(0);
  }, [applied, refreshKey]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey 是外部「刷新」按钮的显式重载触发器。
  React.useEffect(() => {
    const request = ++reqRef.current;
    setLoading(true);
    vuln
      .cveCatalog(page + 1, size, applied)
      .then((r) => {
        if (reqRef.current !== request) return;
        setRows(r.items);
        setTotal(r.total);
        setError("");
      })
      .catch((e) => {
        if (reqRef.current !== request) return;
        setError(String((e as Error)?.message ?? e));
        setRows([]);
        setTotal(0);
      })
      .finally(() => {
        if (reqRef.current === request) {
          setLoading(false);
        }
      });
    return () => {
      reqRef.current++;
    };
  }, [applied, page, size, refreshKey]);

  const pageCount = Math.max(1, Math.ceil(total / size));
  const start = total === 0 ? 0 : page * size + 1;
  const end = page * size + rows.length;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="h-8 w-52"
          placeholder="搜索 CVE 编号 / 标题"
          value={fq}
          onChange={(e) => setFq(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") applyFilters();
          }}
        />
        <Select value={fYear} onValueChange={setFYear}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue placeholder="年份" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部年份</SelectItem>
            {years.map((y) => (
              <SelectItem key={y.year} value={String(y.year)}>
                {y.year}（{y.count}）
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={applyFilters} disabled={loading}>
          {loading ? "查询中…" : "筛选"}
        </Button>
        <Button variant="ghost" size="sm" onClick={clearFilters}>
          清空
        </Button>
        <span className="text-muted-foreground ml-auto text-xs">共 {total} 条（NVD 同步，仅元数据）</span>
      </div>
      {error ? (
        <p role="alert" className="text-destructive text-sm">
          {error}
        </p>
      ) : null}
      <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
        <div className="min-h-0 flex-1 overflow-auto scrollbar-thin scrollbar-track-transparent">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-card">
              <TableRow>
                <TableHead className="w-36">CVE</TableHead>
                <TableHead className="w-20">严重度</TableHead>
                <TableHead>标题</TableHead>
                <TableHead className="w-28">发布日期</TableHead>
                <TableHead className="w-16">KEV</TableHead>
                <TableHead className="w-24">来源</TableHead>
                <TableHead className="w-24 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((c) => (
                <TableRow key={c.cve_id}>
                  <TableCell className="font-mono text-xs font-medium">{c.cve_id}</TableCell>
                  <TableCell>
                    <VulnSeverityBadge severity={c.severity ?? undefined} />
                  </TableCell>
                  <TableCell className="max-w-[24rem]">
                    <div className="truncate text-xs" title={c.title ?? undefined}>
                      {c.title || "—"}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-xs whitespace-nowrap">{c.published || "—"}</TableCell>
                  <TableCell>
                    {c.kev ? (
                      <Badge variant="default" className="bg-red-600 text-[10px] hover:bg-red-600">
                        KEV
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{c.source || "—"}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7"
                      title="手填 Shodan 查询体入队采集（异步，完成后进入资产列表）"
                      onClick={() =>
                        setCollectTarget({
                          cve: { cve_id: c.cve_id, title: c.title ?? "" } as VulnCve,
                          query: "",
                        })
                      }
                    >
                      采集
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-muted-foreground py-12 text-center text-sm">
                    {cveEmptyMessage(loading, error)}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
        {total > 0 && (
          <div className="flex shrink-0 items-center gap-2 border-t px-3 py-1.5 text-xs text-muted-foreground">
            <Select value={String(size)} onValueChange={(v) => setSize(Number(v))}>
              <SelectTrigger size="sm" className="h-7 w-24">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {PAGE_SIZES.map((n) => (
                    <SelectItem key={n} value={String(n)}>
                      {n} / 页
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            <span className="tabular-nums">
              {start}–{end} / {total}
            </span>
            {pageCount > 1 && (
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="icon"
                  className="size-7"
                  disabled={page <= 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                >
                  <ChevronLeftIcon />
                </Button>
                <span className="tabular-nums">
                  {page + 1} / {pageCount}
                </span>
                <Button
                  variant="outline"
                  size="icon"
                  className="size-7"
                  disabled={page + 1 >= pageCount}
                  onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                >
                  <ChevronRightIcon />
                </Button>
              </div>
            )}
          </div>
        )}
      </Card>

      <VulnCollectDialog
        target={collectTarget}
        busy={collecting}
        onQueryChange={(q) => setCollectTarget((t) => (t ? { ...t, query: q } : t))}
        onClose={() => setCollectTarget(null)}
        onSubmit={submitCollect}
      />
    </div>
  );
}
