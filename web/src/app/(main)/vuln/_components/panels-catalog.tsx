"use client";

// CVE 全量目录面板（/api/vuln/cve-catalog 透传代理 → kt-vuln NVD 字典，28 万+ 条）。
// 与 panels.tsx 的 VulnCvesPanel（关注清单）互补：这里只有元数据、无暴露面统计，
// 服务端分页检索（page 从 1 起、page_size 上限 200）；fetch/鉴权走 lib/vuln 的
// vulnHttp 封装（与关注清单同一链路），空态文案与严重度徽章复用 panels.tsx。
//
// 排序：全部在服务端完成（28 万条不做前端排序）。sort/order 由表头 SortableHead
// 或工具条下拉驱动，偏好落 localStorage，URL 不承载排序（目录页是长期停留页）。
// 展示：标题两行截断 + 悬停预览 + 详情抽屉；表格 table-fixed，避免 td 的
// max-width 在 auto 布局下失效（此前标题被列边界直接裁掉、连省略号都没有）。

import * as React from "react";

import { ArrowUpRightIcon, ChevronLeftIcon, ChevronRightIcon, CopyIcon, DownloadIcon, EyeIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { PAGE_SIZES } from "@/components/asset-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { SortableHead } from "@/components/ui/sortable-head";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { type SortDirection, useStoredSortPreference } from "@/lib/sort-preference";
import { type VulnCve, type VulnCveCatalogItem, vuln } from "@/lib/vuln";

import { cveEmptyMessage, VulnCollectDialog, VulnSeverityBadge } from "./panels";

// 服务端支持的三档排序（kt-vuln ListCveCatalog: severity | published | cve_id）。
type CatalogSortField = "published" | "severity" | "cve_id" | "epss" | "risk";

const SORT_FIELDS: readonly CatalogSortField[] = ["published", "severity", "cve_id", "epss", "risk"];

const SORT_LABEL: Record<CatalogSortField, string> = {
  published: "发布日期",
  severity: "严重度",
  cve_id: "CVE 编号",
  epss: "EPSS",
  risk: "风险优先",
};

const SORT_STORAGE_KEY = "vuln.cve-catalog.sort";

// 工具条下拉的预设（表头点击是另一种入口，两者共用同一份状态）。
const SORT_PRESETS: { value: string; label: string }[] = [
  { value: "published:desc", label: "发布日期 ↓（最新优先）" },
  { value: "published:asc", label: "发布日期 ↑" },
  { value: "severity:desc", label: "严重度 ↓" },
  { value: "severity:asc", label: "严重度 ↑" },
  { value: "cve_id:asc", label: "CVE 编号 ↑" },
  { value: "cve_id:desc", label: "CVE 编号 ↓" },
  { value: "epss:desc", label: "EPSS ↓（利用概率）" },
  { value: "risk:desc", label: "风险优先（KEV → EPSS → CVSS → 时间）" },
];

const SEVERITY_PRESETS: { value: string; label: string; min?: number }[] = [
  { value: "all", label: "全部评分" },
  { value: "7", label: "≥ 7.0", min: 7 },
  { value: "8", label: "≥ 8.0", min: 8 },
  { value: "9", label: "≥ 9.0", min: 9 },
  { value: "10", label: "= 10.0", min: 10 },
];

const NVD_URL = (cveId: string) => `https://nvd.nist.gov/vuln/detail/${cveId}`;

// 入库时 title 被截断的判定阈值：ks-vuln 侧按字符数截，落在 170+ 基本就是被裁过的。
const TRUNCATED_HINT_LENGTH = 170;

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b py-2 last:border-b-0">
      <span className="text-muted-foreground text-xs">{label}</span>
      <span className="text-right text-xs">{value}</span>
    </div>
  );
}

export function VulnCvesCatalogPanel({ refreshKey }: { refreshKey: number }) {
  // 草稿筛选：输入中不触发请求，点「筛选」才提交（28 万条目录避免无谓翻页查询）。
  const [fq, setFq] = React.useState("");
  const [fYear, setFYear] = React.useState("all");
  const [fSeverity, setFSeverity] = React.useState("all");
  const [fFrom, setFFrom] = React.useState("");
  const [fTo, setFTo] = React.useState("");
  const [fMin, setFMin] = React.useState("");
  const [fMax, setFMax] = React.useState("");
  const [fVendor, setFVendor] = React.useState("");
  const [fCwe, setFCwe] = React.useState("");
  const [applied, setApplied] = React.useState<{
    q?: string;
    year?: number;
    min_severity?: number;
    severity_max?: number;
    published_from?: string;
    published_to?: string;
    vendor?: string;
    cwe?: string;
  }>({});
  const [rows, setRows] = React.useState<VulnCveCatalogItem[]>([]);
  const [total, setTotal] = React.useState(0);
  // 内部 0-based（与资产面板一致），调 API 时 +1 转成服务端 1-based 页码。
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [years, setYears] = React.useState<{ year: number; count: number }[]>([]);
  const [detail, setDetail] = React.useState<VulnCveCatalogItem | null>(null);
  const [sort, setSort] = useStoredSortPreference<CatalogSortField>(SORT_STORAGE_KEY, SORT_FIELDS, "published", "desc");
  // Shodan 采集（上游 #192）：目录本身没有影响组件元数据，查询体由用户在弹窗里手填。
  const [collecting, setCollecting] = React.useState(false);
  const [collectTarget, setCollectTarget] = React.useState<{ cve: VulnCve; query: string } | null>(null);

  const submitCollect = async () => {
    if (!collectTarget) return;
    const query = collectTarget.query.trim();
    if (!query) {
      toast.error('请填写 Shodan 查询体，如 "log4j country:CN"');
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

  // 年份桶随目录刷新（含同步完成）；失败不阻塞主列表，仅少一个筛选项。
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
  }, [refreshKey]);

  const applyFilters = () => {
    const y = Number.parseInt(fYear, 10);
    const presetMin = SEVERITY_PRESETS.find((p) => p.value === fSeverity)?.min;
    const minInput = Number.parseFloat(fMin);
    const maxInput = Number.parseFloat(fMax);
    setApplied({
      q: fq.trim() || undefined,
      // 年份下拉是快捷方式；填了自定义区间时以区间为准，避免两个条件互相打架。
      year: !fFrom && !fTo && fYear !== "all" && Number.isFinite(y) ? y : undefined,
      min_severity: Number.isFinite(minInput) ? minInput : presetMin,
      severity_max: Number.isFinite(maxInput) ? maxInput : undefined,
      published_from: fFrom || undefined,
      published_to: fTo || undefined,
      vendor: fVendor.trim() || undefined,
      cwe: fCwe.trim() || undefined,
    });
  };

  const clearFilters = () => {
    setFq("");
    setFYear("all");
    setFSeverity("all");
    setFFrom("");
    setFTo("");
    setFMin("");
    setFMax("");
    setFVendor("");
    setFCwe("");
    setApplied({});
  };

  // 生效筛选 / 外部刷新回到第一页。
  // biome-ignore lint/correctness/useExhaustiveDependencies: applied/refreshKey 变化是重置分页的显式触发器。
  React.useEffect(() => {
    setPage(0);
  }, [applied, refreshKey]);

  // 排序变化同样回到第一页：第 21 页按新顺序没有意义。
  // biome-ignore lint/correctness/useExhaustiveDependencies: sort 变化是重置分页的显式触发器，effect 体不需要读它。
  React.useEffect(() => {
    setPage(0);
  }, [sort.field, sort.direction]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey 是外部「刷新」按钮的显式重载触发器。
  React.useEffect(() => {
    const request = ++reqRef.current;
    setLoading(true);
    vuln
      .cveCatalog(page + 1, size, { ...applied, sort: sort.field, order: sort.direction })
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
  }, [applied, page, size, refreshKey, sort.field, sort.direction]);

  const pageCount = Math.max(1, Math.ceil(total / size));
  const start = total === 0 ? 0 : page * size + 1;
  const end = page * size + rows.length;

  // 页码与 URL 双向（issue #61 C3）：?page=N 可分享，翻页时同步回地址栏。
  // biome-ignore lint/correctness/useExhaustiveDependencies: 只在首屏读一次 URL。
  React.useEffect(() => {
    const p = Number.parseInt(new URLSearchParams(window.location.search).get("page") ?? "", 10);
    if (Number.isFinite(p) && p > 0) setPage(p - 1);
  }, []);

  React.useEffect(() => {
    const url = new URL(window.location.href);
    if (page > 0) url.searchParams.set("page", String(page + 1));
    else url.searchParams.delete("page");
    window.history.replaceState(null, "", url.toString());
  }, [page]);

  // 排序状态与 URL 双向：URL 优先（链接可分享当前排序），本地偏好作为兜底。
  // biome-ignore lint/correctness/useExhaustiveDependencies: 只在首屏读一次 URL，后续由用户操作驱动。
  React.useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const field = p.get("sort");
    const direction = p.get("order");
    if (field && SORT_FIELDS.includes(field as CatalogSortField) && (direction === "asc" || direction === "desc")) {
      setSort({ field: field as CatalogSortField, direction: direction as SortDirection });
    }
  }, []);

  const commitSort = (field: CatalogSortField, direction: SortDirection) => {
    setSort({ field, direction });
    const url = new URL(window.location.href);
    url.searchParams.set("sort", field);
    url.searchParams.set("order", direction);
    window.history.replaceState(null, "", url.toString());
  };

  const toggleSort = (field: CatalogSortField) => {
    const direction: SortDirection = sort.field === field && sort.direction === "desc" ? "asc" : "desc";
    commitSort(field, direction);
  };

  const applyPreset = (value: string) => {
    const [field, direction] = value.split(":");
    if (!field || (direction !== "asc" && direction !== "desc")) return;
    commitSort(field as CatalogSortField, direction as SortDirection);
  };

  const copyText = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`已复制${label}`);
    } catch {
      toast.error("复制失败，请手动选择文本");
    }
  };

  // 已生效的筛选条件做成可摘除的 chip（issue #61 D3）：
  // 让用户随时看清"我现在被哪几个条件限制着"，不用回头翻输入框。
  const chips = React.useMemo(() => {
    const out: { key: string; label: string }[] = [];
    if (applied.q) out.push({ key: "q", label: `关键词：${applied.q}` });
    if (applied.year) out.push({ key: "year", label: `年份：${applied.year}` });
    if (applied.published_from || applied.published_to) {
      out.push({
        key: "published",
        label: `时间：${applied.published_from ?? "…"} ~ ${applied.published_to ?? "…"}`,
      });
    }
    if (applied.min_severity !== undefined || applied.severity_max !== undefined) {
      out.push({
        key: "severity",
        label: `评分：${applied.min_severity ?? "0"} ~ ${applied.severity_max ?? "10"}`,
      });
    }
    if (applied.vendor) out.push({ key: "vendor", label: `厂商：${applied.vendor}` });
    if (applied.cwe) out.push({ key: "cwe", label: `CWE：${applied.cwe}` });
    return out;
  }, [applied]);

  const removeChip = (key: string) => {
    setApplied((prev) => {
      if (key === "published") return { ...prev, published_from: undefined, published_to: undefined };
      if (key === "severity") return { ...prev, min_severity: undefined, severity_max: undefined };
      return { ...prev, [key]: undefined };
    });
    // 草稿同步清掉，避免 chip 已删、输入框还留着值导致下次"筛选"又加回来。
    if (key === "q") setFq("");
    if (key === "year") setFYear("all");
    if (key === "published") {
      setFFrom("");
      setFTo("");
    }
    if (key === "severity") {
      setFMin("");
      setFMax("");
      setFSeverity("all");
    }
    if (key === "vendor") setFVendor("");
    if (key === "cwe") setFCwe("");
  };

  const sortArrow = sort.direction === "asc" ? "↑" : "↓";
  const truncated = !detail?.description && (detail?.title?.length ?? 0) >= TRUNCATED_HINT_LENGTH;

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
        <Select value={fSeverity} onValueChange={setFSeverity}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue placeholder="评分" />
          </SelectTrigger>
          <SelectContent>
            {SEVERITY_PRESETS.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {p.label}
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
        <Select value={`${sort.field}:${sort.direction}`} onValueChange={applyPreset}>
          <SelectTrigger size="sm" className="w-44">
            <SelectValue placeholder="排序" />
          </SelectTrigger>
          <SelectContent>
            {SORT_PRESETS.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="text-muted-foreground ml-auto text-xs">
          按 {SORT_LABEL[sort.field]} {sortArrow} 排序 · 共 {total} 条
        </span>
      </div>
      {/* 第二行：时间区间 / 评分区间 / 厂商 / CWE —— 组合筛选，全部走服务端参数 */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground text-xs">时间</span>
        <Input
          type="date"
          aria-label="发布日期起"
          className="h-8 w-36"
          value={fFrom}
          onChange={(e) => setFFrom(e.target.value)}
        />
        <span className="text-muted-foreground text-xs">→</span>
        <Input
          type="date"
          aria-label="发布日期止"
          className="h-8 w-36"
          value={fTo}
          onChange={(e) => setFTo(e.target.value)}
        />
        <span className="text-muted-foreground ml-2 text-xs">评分</span>
        <Input
          inputMode="decimal"
          aria-label="评分下限"
          placeholder="≥ 如 9.2"
          className="h-8 w-24"
          value={fMin}
          onChange={(e) => setFMin(e.target.value)}
        />
        <span className="text-muted-foreground text-xs">→</span>
        <Input
          inputMode="decimal"
          aria-label="评分上限"
          placeholder="≤ 如 10"
          className="h-8 w-24"
          value={fMax}
          onChange={(e) => setFMax(e.target.value)}
        />
        <Input
          aria-label="厂商"
          placeholder="厂商（精确）"
          className="h-8 w-36"
          value={fVendor}
          onChange={(e) => setFVendor(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") applyFilters();
          }}
        />
        <Input
          aria-label="CWE"
          placeholder="CWE，如 CWE-94"
          className="h-8 w-40"
          value={fCwe}
          onChange={(e) => setFCwe(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") applyFilters();
          }}
        />
      </div>
      {chips.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-muted-foreground text-xs">已筛选</span>
          {chips.map((c) => (
            <span
              key={c.key}
              className="bg-muted text-foreground/80 inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px]"
            >
              {c.label}
              <button
                type="button"
                className="hover:text-destructive text-muted-foreground"
                aria-label={`移除筛选：${c.label}`}
                onClick={() => removeChip(c.key)}
              >
                ×
              </button>
            </span>
          ))}
          <Button variant="ghost" size="sm" className="h-6 px-2 text-[11px]" onClick={clearFilters}>
            全部清空
          </Button>
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="text-destructive text-sm">
          {error}
        </p>
      ) : null}
      <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
        <div className="hidden min-h-0 flex-1 overflow-auto scrollbar-thin scrollbar-track-transparent md:block">
          <Table className="table-fixed">
            <TableHeader className="sticky top-0 z-10 bg-card">
              <TableRow>
                <SortableHead
                  field="cve_id"
                  label="CVE"
                  activeField={sort.field}
                  direction={sort.direction}
                  onSort={toggleSort}
                  className="w-36"
                />
                <SortableHead
                  field="severity"
                  label="严重度"
                  activeField={sort.field}
                  direction={sort.direction}
                  onSort={toggleSort}
                  className="w-24"
                />
                <TableHead>标题</TableHead>
                <SortableHead
                  field="published"
                  label="发布日期"
                  activeField={sort.field}
                  direction={sort.direction}
                  onSort={toggleSort}
                  className="w-28"
                />
                <TableHead className="hidden w-16 sm:table-cell">KEV</TableHead>
                <TableHead className="hidden w-24 lg:table-cell">来源</TableHead>
                <TableHead className="w-28 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((c) => (
                <TableRow key={c.cve_id}>
                  <TableCell className="font-mono text-xs font-medium">
                    <button
                      type="button"
                      className="hover:underline"
                      onClick={() => setDetail(c)}
                      aria-label={`查看 ${c.cve_id} 详情`}
                    >
                      {c.cve_id}
                    </button>
                  </TableCell>
                  <TableCell>
                    <VulnSeverityBadge severity={c.severity ?? undefined} />
                  </TableCell>
                  <TableCell className="py-2 align-top whitespace-normal">
                    <HoverCard openDelay={300} closeDelay={80}>
                      <HoverCardTrigger asChild>
                        <button
                          type="button"
                          className="block w-full text-left outline-none focus-visible:underline"
                          onClick={() => setDetail(c)}
                        >
                          <span className="line-clamp-2 text-xs leading-5">{c.summary_zh || c.title || "—"}</span>
                        </button>
                      </HoverCardTrigger>
                      <HoverCardContent align="start" className="w-[30rem] max-w-[80vw]">
                        <p className="text-xs leading-5 break-words whitespace-pre-wrap">
                          {c.description || c.title || "—"}
                        </p>
                        <p className="text-muted-foreground mt-2 text-[11px]">点击标题查看详情与 NVD 原文</p>
                      </HoverCardContent>
                    </HoverCard>
                  </TableCell>
                  <TableCell className="font-mono text-xs whitespace-nowrap">{c.published || "—"}</TableCell>
                  <TableCell className="hidden sm:table-cell">
                    {c.kev ? (
                      <Badge variant="default" className="bg-red-600 text-[10px] hover:bg-red-600">
                        KEV
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs lg:table-cell">{c.source || "—"}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-0.5">
                      <Button variant="ghost" size="icon" className="size-7" asChild>
                        <a
                          href={`/vuln/assets?cve=${encodeURIComponent(c.cve_id)}`}
                          title="查看命中资产"
                          aria-label={`查看 ${c.cve_id} 命中的资产`}
                        >
                          <SearchIcon className="size-3.5" />
                        </a>
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-7"
                        title="从 Shodan 采集该 CVE 的暴露资产"
                        aria-label={`从 Shodan 采集 ${c.cve_id}`}
                        onClick={() =>
                          setCollectTarget({ cve: { cve_id: c.cve_id, title: c.title ?? "" } as VulnCve, query: "" })
                        }
                      >
                        <DownloadIcon className="size-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-7"
                        onClick={() => setDetail(c)}
                        aria-label={`查看 ${c.cve_id} 详情`}
                      >
                        <EyeIcon className="size-3.5" />
                      </Button>
                      <Button variant="ghost" size="icon" className="size-7" asChild>
                        <a
                          href={NVD_URL(c.cve_id)}
                          target="_blank"
                          rel="noreferrer"
                          aria-label={`在 NVD 打开 ${c.cve_id}`}
                        >
                          <ArrowUpRightIcon className="size-3.5" />
                        </a>
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-7"
                        onClick={() => copyText(c.cve_id, " CVE 编号")}
                        aria-label={`复制 ${c.cve_id}`}
                      >
                        <CopyIcon className="size-3.5" />
                      </Button>
                    </div>
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
        {/* <md：卡片流替代表格（触屏没有 hover，点击整卡进抽屉） */}
        <div className="min-h-0 flex-1 overflow-auto scrollbar-thin scrollbar-track-transparent md:hidden">
          {rows.length === 0 ? (
            <p className="text-muted-foreground py-12 text-center text-sm">{cveEmptyMessage(loading, error)}</p>
          ) : (
            rows.map((c) => (
              <button
                key={c.cve_id}
                type="button"
                onClick={() => setDetail(c)}
                className="hover:bg-muted/50 w-full border-b px-3 py-3 text-left last:border-b-0"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-medium">{c.cve_id}</span>
                  <VulnSeverityBadge severity={c.severity ?? undefined} />
                </div>
                <p className="mt-1 line-clamp-2 text-xs leading-5">{c.summary_zh || c.title || "—"}</p>
                <div className="text-muted-foreground mt-1 flex items-center gap-2 text-[11px]">
                  <span className="font-mono">{c.published || "—"}</span>
                  {c.kev ? (
                    <Badge variant="default" className="bg-red-600 text-[10px] hover:bg-red-600">
                      KEV
                    </Badge>
                  ) : null}
                </div>
              </button>
            ))
          )}
        </div>
        {total > 0 && (
          <div className="flex shrink-0 items-center gap-2 border-t px-3 py-1.5 text-xs text-muted-foreground">
            <Select value={String(size)} onValueChange={(v) => setSize(Number(v))}>
              <SelectTrigger size="sm" className="hidden h-7 w-24 sm:flex">
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
                  aria-label="上一页"
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
                  aria-label="下一页"
                >
                  <ChevronRightIcon />
                </Button>
              </div>
            )}
          </div>
        )}
      </Card>

      <Sheet
        open={detail !== null}
        onOpenChange={(open) => {
          if (!open) setDetail(null);
        }}
      >
        <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-xl">
          <SheetHeader>
            <SheetTitle className="font-mono text-sm">{detail?.cve_id ?? ""}</SheetTitle>
            <SheetDescription>来自 NVD 全量字典的元数据；原文与 PoC 关联在后续迭代补齐。</SheetDescription>
          </SheetHeader>
          {detail ? (
            <div className="space-y-4 px-4 pb-6">
              <div className="flex flex-wrap items-center gap-2">
                <VulnSeverityBadge severity={detail.severity ?? undefined} />
                {detail.kev ? (
                  <Badge variant="default" className="bg-red-600 text-[10px] hover:bg-red-600">
                    KEV
                  </Badge>
                ) : null}
                <Badge variant="outline" className="text-[10px]">
                  {detail.source || "—"}
                </Badge>
              </div>
              {detail.summary_zh ? (
                <div>
                  <p className="text-muted-foreground mb-1 text-xs">中文摘要</p>
                  <p className="text-xs leading-5 break-words whitespace-pre-wrap">{detail.summary_zh}</p>
                </div>
              ) : null}
              <div>
                <p className="text-muted-foreground mb-1 text-xs">描述（原文）</p>
                <p className="text-xs leading-5 break-words whitespace-pre-wrap">
                  {detail.description || detail.title || "—"}
                </p>
                {truncated ? (
                  <p className="text-muted-foreground mt-2 text-[11px]">该描述在入库时被截断，完整原文待后端补全。</p>
                ) : null}
              </div>
              <div>
                <Metric label="发布日期" value={<span className="font-mono">{detail.published || "—"}</span>} />
                <Metric label="发布年份" value={<span className="font-mono">{detail.published_year ?? "—"}</span>} />
                <Metric
                  label="CVSS"
                  value={
                    <span className="font-mono">
                      {detail.cvss_version ? `v${detail.cvss_version} ` : ""}
                      {detail.cvss_vector || (detail.severity ?? "—")}
                    </span>
                  }
                />
                <Metric label="厂商 / 产品" value={[detail.vendor, detail.product].filter(Boolean).join(" / ") || "—"} />
                <Metric label="CWE" value={detail.cwe?.length ? detail.cwe.join("、") : "—"} />
                <Metric
                  label="EPSS"
                  value={<span className="font-mono">{detail.epss != null ? detail.epss.toFixed(3) : "—"}</span>}
                />
                <Metric label="CVE 编号" value={<span className="font-mono">{detail.cve_id}</span>} />
              </div>
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" onClick={() => copyText(detail.cve_id, " CVE 编号")}>
                  <CopyIcon className="size-3.5" /> 复制编号
                </Button>
                <Button variant="outline" size="sm" asChild>
                  <a href={NVD_URL(detail.cve_id)} target="_blank" rel="noreferrer">
                    <ArrowUpRightIcon className="size-3.5" /> 打开 NVD
                  </a>
                </Button>
              </div>
            </div>
          ) : null}
        </SheetContent>
      </Sheet>

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
