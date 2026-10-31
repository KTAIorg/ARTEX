"use client";

import * as React from "react";

import { useRouter, useSearchParams } from "next/navigation";

import {
  ArrowLeftIcon,
  BugIcon,
  BuildingIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  GlobeIcon,
  KeyRoundIcon,
  LayoutTemplateIcon,
  LinkIcon,
  type LucideIcon,
  NetworkIcon,
  PencilIcon,
  RefreshCwIcon,
  SendIcon,
  ShieldAlertIcon,
  SmartphoneIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { AssetDslSearch } from "@/components/asset-dsl-search";
import { IntelligencePanel } from "@/components/intelligence-panel";
import { ScopeTextEditor } from "@/components/scope-text-editor";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { parseCompanyScopeText } from "@/lib/company-scope";
import { ktVulnOf } from "@/lib/types";
import type { Asset, Company, CompanyScopeRule } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  type VulnAsset,
  type VulnAssetFilters,
  type VulnCve,
  type VulnEngagementStatus,
  type VulnRatingTier,
  vuln,
} from "@/lib/vuln";

const METHOD_COLOR: Record<string, string> = {
  GET: "bg-emerald-100 text-emerald-700",
  POST: "bg-blue-100 text-blue-700",
  PUT: "bg-amber-100 text-amber-700",
  PATCH: "bg-orange-100 text-orange-700",
  DELETE: "bg-red-100 text-red-700",
  HEAD: "bg-purple-100 text-purple-700",
  OPTIONS: "bg-slate-100 text-slate-600",
};

function MethodBadge({ method }: { method: string }) {
  const m = method.toUpperCase();
  return (
    <span
      className={cn(
        "inline-block rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold leading-none",
        METHOD_COLOR[m] ?? "bg-muted text-muted-foreground",
      )}
    >
      {m || "—"}
    </span>
  );
}

function statusTone(code: number) {
  if (code >= 500) return "text-red-500";
  if (code >= 400) return "text-amber-500";
  if (code >= 300) return "text-blue-500";
  if (code >= 200) return "text-emerald-500";
  return "text-muted-foreground";
}

const PAGE_SIZES = [25, 50, 100, 200];

// ── kt-vuln 协同维度（assets.extra.ktvuln，随同步写入）────────────────────────

const KV_TIERS = ["A", "B", "C", "D", "E"];
const KV_ENGAGEMENTS: { value: string; label: string }[] = [
  { value: "todo", label: "待处理" },
  { value: "claimed", label: "已认领" },
  { value: "in_progress", label: "进行中" },
  { value: "done_hit", label: "已命中" },
  { value: "done_miss", label: "未命中" },
  { value: "blocked", label: "受阻" },
  { value: "excluded", label: "已排除" },
];

// 价值列：tier 徽章 + 分数（如 A·92）。A/B 是高价值目标用醒目填充色，
// C/D/E 是低价值长尾，用 slate/zinc/stone 中性淡色阶区分。
const KV_TIER_TONE: Record<string, { variant: "default" | "secondary"; cls: string }> = {
  A: { variant: "default", cls: "bg-rose-600 hover:bg-rose-600" },
  B: { variant: "default", cls: "bg-amber-500 hover:bg-amber-500" },
  C: { variant: "secondary", cls: "bg-slate-200 text-slate-700" },
  D: { variant: "secondary", cls: "bg-zinc-200 text-zinc-700" },
  E: { variant: "secondary", cls: "bg-stone-200 text-stone-700" },
};

function KVValueBadge({ tier, score }: { tier?: string; score?: number }) {
  if (!tier) return <span className="font-mono text-xs tabular-nums">{score ?? "—"}</span>;
  const tone = KV_TIER_TONE[tier];
  return (
    <Badge variant={tone?.variant ?? "outline"} className={cn("font-mono text-[10px]", tone?.cls)}>
      {tier}
      {score != null ? `·${score}` : ""}
    </Badge>
  );
}

// 作业状态徽章配色：todo=灰、claimed=蓝、in_progress=琥珀、done*=绿；未列出状态走中性 outline。
const KV_ENGAGEMENT_TONE: Record<string, string> = {
  todo: "bg-slate-100 text-slate-600",
  claimed: "bg-blue-100 text-blue-700",
  in_progress: "bg-amber-100 text-amber-700",
  done_hit: "bg-emerald-100 text-emerald-700",
  done_miss: "bg-emerald-100 text-emerald-700",
};

// 判定（verdict）中文与配色：可确认=红、疑似漏洞=橙、已修复=绿、不适用=灰、未知=金。
const KV_VERDICT_LABEL: Record<string, string> = {
  executable: "可确认",
  vulnerable: "疑似漏洞",
  patched: "已修复",
  not_applicable: "不适用",
  unknown: "未知",
};
const KV_VERDICT_TONE: Record<string, string> = {
  executable: "bg-red-600 hover:bg-red-600",
  vulnerable: "bg-orange-100 text-orange-700",
  patched: "bg-emerald-100 text-emerald-700",
  not_applicable: "bg-slate-100 text-slate-600",
  unknown: "bg-yellow-100 text-yellow-700",
};

function KVEngagementBadge({ status }: { status: string }) {
  const tone = KV_ENGAGEMENT_TONE[status];
  const label = KV_ENGAGEMENTS.find((v) => v.value === status)?.label ?? status;
  return (
    <Badge variant={tone ? "secondary" : "outline"} className={cn("text-[10px]", tone)}>
      {label}
    </Badge>
  );
}

function KVVerdictBadge({ verdict }: { verdict: string }) {
  const tone = KV_VERDICT_TONE[verdict];
  return (
    <Badge variant={tone ? "secondary" : "outline"} className={cn("text-[10px]", tone)}>
      {KV_VERDICT_LABEL[verdict] ?? verdict}
    </Badge>
  );
}

// DSL 值没有转义语法（readToken 的引号即边界）：去掉值里的引号，含空白/括号时整体加引号。
function kvDslValue(v: string): string {
  const clean = v.replaceAll('"', "");
  return /[\s()]/.test(clean) ? `"${clean}"` : clean;
}

// 服务 tab 的 kt-vuln 快捷筛选：条件拼成 kv_* DSL 填进上方 DSL 搜索框并触发查询。
function KVQuickFilter({ onApply }: { onApply: (dsl: string) => void }) {
  const [minScore, setMinScore] = React.useState("");
  const [tier, setTier] = React.useState("all");
  const [bizType, setBizType] = React.useState("");
  const [engagement, setEngagement] = React.useState("all");

  const apply = () => {
    const parts: string[] = [];
    const score = Number.parseInt(minScore.trim(), 10);
    if (minScore.trim() !== "" && Number.isFinite(score)) parts.push(`kv_score>=${score}`);
    if (tier !== "all") parts.push(`kv_tier==${tier}`);
    if (bizType.trim() !== "") parts.push(`kv_biz_type==${kvDslValue(bizType.trim())}`);
    if (engagement !== "all") parts.push(`kv_engagement==${engagement}`);
    if (parts.length === 0) return toast.error("请至少填写一个筛选条件");
    onApply(parts.join(" AND "));
  };

  const clear = () => {
    setMinScore("");
    setTier("all");
    setBizType("");
    setEngagement("all");
    onApply("");
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-muted-foreground text-xs">kt-vuln：</span>
      <Input
        className="h-8 w-24"
        type="number"
        min={0}
        max={100}
        placeholder="分数 ≥"
        value={minScore}
        onChange={(e) => setMinScore(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") apply();
        }}
      />
      <Select value={tier} onValueChange={setTier}>
        <SelectTrigger size="sm" className="w-24">
          <SelectValue placeholder="等级" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">全部等级</SelectItem>
          {KV_TIERS.map((t) => (
            <SelectItem key={t} value={t}>
              {t} 级
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Input
        className="h-8 w-40"
        placeholder="业务类型，如 盗U盘"
        value={bizType}
        onChange={(e) => setBizType(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") apply();
        }}
      />
      <Select value={engagement} onValueChange={setEngagement}>
        <SelectTrigger size="sm" className="w-28">
          <SelectValue placeholder="作业状态" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">全部状态</SelectItem>
          {KV_ENGAGEMENTS.map((v) => (
            <SelectItem key={v.value} value={v.value}>
              {v.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Button variant="outline" size="sm" onClick={apply}>
        筛选
      </Button>
      <Button variant="ghost" size="sm" onClick={clear}>
        清空
      </Button>
    </div>
  );
}

// kt-vuln 漏洞库相关 tab：不共用本地资产页的加载/选择/删除逻辑（数据源、ID 空间都不同）。
const VULN_TABS = new Set(["vuln", "cves"]);

const TABS: { key: string; label: string; icon: LucideIcon }[] = [
  { key: "company", label: "企业", icon: BuildingIcon },
  { key: "root_domain", label: "根域名", icon: GlobeIcon },
  { key: "ip", label: "IP", icon: NetworkIcon },
  { key: "subdomain", label: "子域名", icon: GlobeIcon },
  { key: "app", label: "应用", icon: SmartphoneIcon },
  { key: "service", label: "服务", icon: LayoutTemplateIcon },
  { key: "endpoint", label: "接口", icon: LinkIcon },
  { key: "vuln", label: "漏洞库", icon: ShieldAlertIcon },
  { key: "cves", label: "CVE 情报", icon: BugIcon },
];

function AssetsContent() {
  const searchParams = useSearchParams();
  const requestedAsset = searchParams.get("asset") ?? "";
  const [assetTarget, setAssetTarget] = React.useState<{ id: number; type: string }>();
  const [assetTargetError, setAssetTargetError] = React.useState("");
  React.useEffect(() => {
    let alive = true;
    setAssetTarget(undefined);
    setAssetTargetError("");
    if (!/^[1-9]\d*$/.test(requestedAsset)) return;
    api
      .searchAssets(`id==${requestedAsset}`, "", 1)
      .then((r) => {
        if (!alive) return;
        const asset = r.assets[0];
        if (!asset) {
          setAssetTargetError(`资产 #${requestedAsset} 不存在或已删除`);
          return;
        }
        setAssetTarget({ id: asset.id, type: asset.type });
        setTab(asset.type);
        setPage(0);
        setIntelligenceAsset(null);
      })
      .catch((e) => {
        if (alive) setAssetTargetError((e as Error).message);
      });
    return () => {
      alive = false;
    };
  }, [requestedAsset]);
  const [intelligenceAsset, setIntelligenceAsset] = React.useState<number | null>(null);
  const [rows, setRows] = React.useState<Asset[]>([]);
  const [total, setTotal] = React.useState(0);
  const [companies, setCompanies] = React.useState<Company[]>([]);
  const [counts, setCounts] = React.useState<Record<string, number>>({});
  const [tab, setTab] = React.useState("company");
  const [query, setQuery] = React.useState("");
  const [loaded, setLoaded] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  const [dslError, setDslError] = React.useState("");
  const [refreshKey, setRefreshKey] = React.useState(0);
  // 漏洞库/CVE 面板自己的重载信号：与本地资产的 refreshKey 分开递增，但由同一个「刷新」按钮驱动。
  const [vulnRefreshKey, setVulnRefreshKey] = React.useState(0);
  const assetsRequestRef = React.useRef(0);
  const [rowsTab, setRowsTab] = React.useState("");

  // asset selection & delete
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [deleteIds, setDeleteIds] = React.useState<number[]>([]);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);

  // company delete
  const [companyDeleteTarget, setCompanyDeleteTarget] = React.useState<Company | null>(null);
  const [companyDeleteAssets, setCompanyDeleteAssets] = React.useState(false);
  const [companyDeleting, setCompanyDeleting] = React.useState(false);

  // Companies + per-type counts (tab badges) — loaded on demand, no background polling.
  const loadMeta = React.useCallback(() => {
    api
      .companies()
      .then(setCompanies)
      .catch(() => {
        /* Keep the last successful company snapshot on a transient failure. */
      });
    api
      .assetCounts()
      .then(setCounts)
      .catch(() => {
        /* Keep the last successful counters on a transient failure. */
      });
  }, []);

  // Manual refresh: reload counts/companies and re-fetch the current page.
  const refresh = React.useCallback(() => {
    loadMeta();
    setRefreshKey((k) => k + 1);
    setVulnRefreshKey((k) => k + 1);
    setSelected(new Set());
  }, [loadMeta]);

  const toggleSelect = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = (ids: number[]) => {
    setSelected((prev) => {
      const allSelected = ids.every((id) => prev.has(id));
      const next = new Set(prev);
      if (allSelected) {
        ids.forEach((id) => {
          next.delete(id);
        });
      } else {
        ids.forEach((id) => {
          next.add(id);
        });
      }
      return next;
    });
  };

  const openDelete = (ids: number[]) => {
    setDeleteIds(ids);
    setDeleteOpen(true);
  };

  const confirmDelete = async () => {
    setDeleting(true);
    try {
      const res = await api.deleteAssets(deleteIds);
      toast.success(`已删除 ${res.deleted} 条资产`);
      setSelected(new Set());
      refresh();
    } catch (e) {
      toast.error("删除失败：" + String((e as Error)?.message ?? e));
    } finally {
      setDeleting(false);
      setDeleteOpen(false);
    }
  };

  const confirmDeleteCompany = async () => {
    if (!companyDeleteTarget) return;
    setCompanyDeleting(true);
    try {
      const res = await api.deleteCompany(companyDeleteTarget.id, companyDeleteAssets);
      const msg =
        companyDeleteAssets && res.assets_deleted > 0
          ? `已删除企业，同时删除 ${res.assets_deleted} 条资产`
          : "已删除企业";
      toast.success(msg);
      refresh();
    } catch (e) {
      toast.error("删除失败：" + String((e as Error)?.message ?? e));
    } finally {
      setCompanyDeleting(false);
      setCompanyDeleteTarget(null);
      setCompanyDeleteAssets(false);
    }
  };

  React.useEffect(() => {
    loadMeta();
  }, [loadMeta]);

  // Reset query + page + selection when switching tabs
  // biome-ignore lint/correctness/useExhaustiveDependencies: tab changes intentionally reset tab-local controls.
  React.useEffect(() => {
    setQuery(assetTarget?.type === tab ? `id==${assetTarget.id}` : "");
    setDslError("");
    setSelected(new Set());
    setRows([]);
    setRowsTab("");
    setTotal(0);
    setLoaded(false);
  }, [tab, assetTarget]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: these controls intentionally reset server pagination.
  React.useEffect(() => setPage(0), [tab, size, query]);

  const dslMode = query.trim() !== "";

  // Server-side paginated page loader for the active data tab (company tab excluded).
  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    if (tab === "company" || VULN_TABS.has(tab)) return;
    const request = ++assetsRequestRef.current;
    const dsl = query.trim();
    setLoading(true);
    const offset = page * size;
    const run = async () => {
      try {
        const r = dsl ? await api.searchAssets(dsl, tab, size, offset) : await api.assets(tab, size, offset);
        if (assetsRequestRef.current !== request) return;
        setRows(r.assets);
        setRowsTab(tab);
        setTotal(r.total);
        setDslError("");
      } catch (e) {
        if (assetsRequestRef.current !== request) return;
        setDslError(String((e as Error)?.message ?? e));
        setRows([]);
        setRowsTab(tab);
        setTotal(0);
      } finally {
        if (assetsRequestRef.current === request) {
          setLoading(false);
          setLoaded(true);
        }
      }
    };
    const tid = setTimeout(run, dsl ? 400 : 0);
    return () => {
      clearTimeout(tid);
      if (assetsRequestRef.current === request) assetsRequestRef.current++;
    };
  }, [tab, page, size, query, refreshKey]);

  React.useEffect(() => {
    if (tab === "company" || VULN_TABS.has(tab)) return;
    const lastPage = Math.max(0, Math.ceil(total / size) - 1);
    if (page > lastPage) setPage(lastPage);
  }, [page, size, tab, total]);

  const companyById = React.useMemo(() => {
    const m = new Map<number, string>();
    for (const c of companies) m.set(c.id, c.name);
    return m;
  }, [companies]);

  const companyName = (id?: number) => (id ? (companyById.get(id) ?? "") : "");

  const tabCounts: Record<string, number> = { ...counts, company: companies.length };
  const totalAssets = Object.values(counts).reduce((a, b) => a + b, 0);

  // rows are already the current server-side page.
  const tabData = (type: string): Asset[] => (rowsTab === type ? rows : []);
  const currentRows = tabData(tab);
  const slice = <T,>(list: T[]) => list;

  const searchBox = (
    <AssetDslSearch
      query={query}
      onChange={setQuery}
      loading={loading}
      error={dslError}
      count={dslMode ? total : undefined}
    />
  );

  return (
    <div className="flex h-[calc(100vh-6rem)] min-h-0 flex-col gap-4">
      {assetTargetError ? (
        <p role="alert" className="text-sm text-destructive">
          {assetTargetError}
        </p>
      ) : null}
      <Dialog
        open={intelligenceAsset !== null}
        onOpenChange={(open) => {
          if (!open) setIntelligenceAsset(null);
        }}
      >
        <DialogContent className="sm:max-w-5xl">
          <DialogHeader>
            <DialogTitle>资产 #{intelligenceAsset} 的关联情报</DialogTitle>
            <DialogDescription>按来源任务查看凭据、线索和敏感数据。</DialogDescription>
          </DialogHeader>
          {intelligenceAsset !== null ? (
            <IntelligencePanel
              key={intelligenceAsset}
              scope="assets"
              scopeId={String(intelligenceAsset)}
              onNavigate={() => setIntelligenceAsset(null)}
            />
          ) : null}
        </DialogContent>
      </Dialog>
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">资产</h1>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-muted-foreground">
            共 <span className="tabular-nums">{totalAssets}</span> 项资产
          </span>
          {tab !== "company" && !VULN_TABS.has(tab) ? (
            <Button
              variant="outline"
              size="sm"
              disabled={selected.size !== 1}
              title="选择一项资产查看关联情报"
              onClick={() => setIntelligenceAsset(Array.from(selected)[0])}
            >
              关联情报
            </Button>
          ) : null}
          {selected.size > 0 && !VULN_TABS.has(tab) && (
            <Button variant="destructive" size="sm" onClick={() => openDelete(Array.from(selected) as number[])}>
              <Trash2Icon className="size-3.5" /> 删除已选 ({selected.size})
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
            <RefreshCwIcon className={cn("size-4", loading && "animate-spin")} /> 刷新
          </Button>
          <CompanyDialog onSaved={refresh} />
        </div>
      </div>

      <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col gap-4">
        <div className="overflow-x-auto overflow-y-hidden">
          <TabsList variant="default">
            {TABS.map((t) => (
              <TabsTrigger key={t.key} value={t.key}>
                <t.icon className="size-3.5" />
                {t.label}
                <span className="ml-1 tabular-nums text-muted-foreground">{tabCounts[t.key]}</span>
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        {/* 企业 */}
        <TabsContent value="company" className="mt-0 flex min-h-0 flex-1 flex-col">
          <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
            <div className="min-h-0 flex-1 overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>企业</TableHead>
                    <TableHead className="w-24 text-right">资产数</TableHead>
                    <TableHead>资产范围</TableHead>
                    <TableHead className="w-36 text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {companies.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <CompanyAvatar name={c.name} logo={c.logo} />
                          <span className="font-medium">{c.name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right tabular-nums text-sm">{c.asset_count}</TableCell>
                      <TableCell>
                        {c.scope?.length ? (
                          <div className="flex flex-wrap gap-1">
                            {c.scope.map((s, i) => (
                              <Badge key={i} variant="secondary" className="font-mono text-[11px]">
                                {s.raw}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">未设置范围</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <EditScopeDialog company={c} onSaved={refresh} />
                          <AppendScopeDialog company={c} onSaved={refresh} />
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7 text-muted-foreground hover:text-destructive"
                            onClick={() => {
                              setCompanyDeleteTarget(c);
                              setCompanyDeleteAssets(false);
                            }}
                            aria-label={`删除企业 ${c.name}`}
                          >
                            <Trash2Icon className="size-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {companies.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">
                        还没有企业。点击右上角「新增企业」并填写资产范围，系统会自动认领命中的资产。
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          </Card>
        </TabsContent>

        {/* 根域名 */}
        <TabsContent value="root_domain" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", "域名", "ICP 备案", "归属企业", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("root_domain")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="font-mono text-xs font-medium">{a.domain}</TableCell>
                <TableCell className="text-xs">{a.icp || "—"}</TableCell>
                <TableCell className="text-xs">
                  {companyName(a.company_id) || <span className="text-muted-foreground">未归属</span>}
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.domain || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* IP */}
        <TabsContent value="ip" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", "IP", "C段", "绑定域名", "开放端口", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("ip")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="font-mono text-xs font-medium">{a.ip}</TableCell>
                <TableCell className="font-mono text-xs">{a.c_segment || "—"}</TableCell>
                <TableCell>
                  <Chips items={a.bound_domains ?? []} mono />
                </TableCell>
                <TableCell>
                  <Chips
                    items={(a.open_ports ?? []).map((p) => (p.service ? `${p.port}/${p.service}` : String(p.port)))}
                    mono
                  />
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.ip || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 子域名 */}
        <TabsContent value="subdomain" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", "域名", "根域名", "解析类型", "解析值", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("subdomain")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="font-mono text-xs font-medium">{a.domain}</TableCell>
                <TableCell className="font-mono text-xs">{a.root_domain || "—"}</TableCell>
                <TableCell className="text-xs">{a.record_type || "—"}</TableCell>
                <TableCell className="max-w-xs truncate font-mono text-xs">
                  {(Array.isArray(a.record_value) ? a.record_value.join(", ") : a.record_value) || "—"}
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.domain || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 应用 */}
        <TabsContent value="app" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", "应用名", "Bundle ID", "分类", "ICP 备案", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("app")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="text-xs font-medium">{a.app_name || "—"}</TableCell>
                <TableCell className="font-mono text-xs">{a.bundle_id || "—"}</TableCell>
                <TableCell className="text-xs">{a.category || "—"}</TableCell>
                <TableCell className="text-xs">{a.app_icp || "—"}</TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.app_name || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 服务 */}
        <TabsContent value="service" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <KVQuickFilter onApply={setQuery} />
          <AssetCard
            cols={["", "服务", "域名", "IP", "端口", "状态码", "标题", "指纹", "认证", "价值", "业务", "国家", "作业状态", "判定", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("service")).map((a) => {
              const isHttp = a.service_type === "http";
              const svc = a.service_name || (isHttp ? "http" : "") || a.service_type || "";
              const kv = ktVulnOf(a);
              let domainCell: React.ReactNode = "—";
              if (isHttp && a.url) {
                domainCell = (
                  <a
                    href={a.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-blue-600 hover:underline dark:text-blue-400"
                  >
                    {a.domain || a.url}
                  </a>
                );
              } else if (a.domain) {
                domainCell = a.domain;
              }
              return (
                <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                  <TableCell className="w-8 pr-0">
                    <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                  </TableCell>
                  <TableCell className="text-xs">
                    <Badge variant={isHttp ? "default" : "secondary"} className="font-mono text-[10px]">
                      {svc || "—"}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[14rem] truncate font-mono text-xs" title={a.domain || a.url}>
                    {domainCell}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{a.ip || "—"}</TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">{a.port || "—"}</TableCell>
                  <TableCell>
                    {a.status_code != null ? (
                      <span className={cn("font-mono text-xs font-semibold tabular-nums", statusTone(a.status_code))}>
                        {a.status_code}
                      </span>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell className="max-w-[12rem] truncate text-xs" title={a.page_title}>
                    {a.page_title || "—"}
                  </TableCell>
                  <TableCell>
                    <Chips items={a.technologies ?? []} />
                  </TableCell>
                  <TableCell>
                    {(a.auth ?? []).length === 0 ? (
                      <span className="text-xs text-muted-foreground">—</span>
                    ) : (
                      (a.auth ?? []).map((authItem, i) => {
                        const item = authItem as Record<string, string>;
                        const label = item.type || item.username || "认证";
                        return (
                          <span key={i} className="inline-flex items-center gap-1 text-[11px]">
                            <KeyRoundIcon className="size-3 text-muted-foreground" />
                            <span className="font-mono">{label}</span>
                          </span>
                        );
                      })
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    {kv ? <KVValueBadge tier={kv.tier} score={kv.score} /> : <span className="text-muted-foreground text-xs">—</span>}
                  </TableCell>
                  <TableCell className="max-w-[8rem]" title={kv?.biz_type}>
                    {kv?.biz_type ? (
                      <Badge variant="secondary" className="max-w-full truncate text-[10px]">
                        {kv.biz_type}
                      </Badge>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{kv?.country ?? "—"}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    {kv?.engagement_status ? (
                      <KVEngagementBadge status={kv.engagement_status} />
                    ) : (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    {kv?.verdict ? (
                      <KVVerdictBadge verdict={kv.verdict} />
                    ) : (
                      <span className="text-muted-foreground text-xs">—</span>
                    )}
                  </TableCell>
                  <TableCell className="w-8 pl-0">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7 text-muted-foreground hover:text-destructive"
                      onClick={() => openDelete([a.id])}
                      aria-label={`删除资产 ${a.url || a.id}`}
                    >
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })}
          </AssetCard>
        </TabsContent>

        {/* 接口 */}
        <TabsContent value="endpoint" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", "方法", "完整地址", "参数", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("endpoint")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="w-16">
                  <MethodBadge method={a.method || ""} />
                </TableCell>
                <TableCell className="max-w-sm truncate font-mono text-xs" title={a.url}>
                  {a.url || "—"}
                </TableCell>
                <TableCell>
                  <Chips
                    items={(a.params ?? []).map((p) => {
                      const item = p as Record<string, string>;
                      return item.name ? `${item.name}(${item.location || "?"})` : "?";
                    })}
                    mono
                  />
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.url || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 漏洞库（kt-vuln 资产目录，服务端分页 + 筛选 + 写操作） */}
        <TabsContent value="vuln" className="mt-0 flex min-h-0 flex-1 flex-col">
          <VulnAssetsPanel refreshKey={vulnRefreshKey} />
        </TabsContent>

        {/* CVE 情报（下钻到受影响资产并下发任务） */}
        <TabsContent value="cves" className="mt-0 flex min-h-0 flex-1 flex-col">
          <VulnCvesPanel refreshKey={vulnRefreshKey} />
        </TabsContent>
      </Tabs>

      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除</AlertDialogTitle>
            <AlertDialogDescription>
              将永久删除 <span className="font-semibold tabular-nums">{deleteIds.length}</span>{" "}
              条资产记录，此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                void confirmDelete();
              }}
              disabled={deleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleting ? "删除中…" : "确认删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={!!companyDeleteTarget}
        onOpenChange={(o) => {
          if (!o) {
            setCompanyDeleteTarget(null);
            setCompanyDeleteAssets(false);
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除企业 · {companyDeleteTarget?.name}</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-3">
                <p>此操作将永久删除该企业及其资产范围配置，不可撤销。</p>
                <label
                  htmlFor="delete-assets-opt"
                  className="flex cursor-pointer items-center gap-2.5 rounded-md border p-3 hover:bg-muted/50"
                >
                  <Checkbox
                    id="delete-assets-opt"
                    checked={companyDeleteAssets}
                    onCheckedChange={(v) => setCompanyDeleteAssets(!!v)}
                  />
                  <span className="text-sm leading-snug">
                    同时删除该企业下的所有资产
                    <span className="block text-xs text-muted-foreground">不勾选则保留资产，仅取消归属关系</span>
                  </span>
                </label>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={companyDeleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                void confirmDeleteCompany();
              }}
              disabled={companyDeleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {companyDeleting ? "删除中…" : "确认删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function AssetCard({
  cols,
  loaded,
  total,
  page,
  size,
  onSize,
  onPage,
  rows: dataRows,
  selected,
  onToggleAll,
  children,
}: {
  cols: string[];
  loaded: boolean;
  total: number;
  page: number;
  size: number;
  onSize: React.Dispatch<React.SetStateAction<number>>;
  onPage: React.Dispatch<React.SetStateAction<number>>;
  rows?: { id: number }[]; // 只用于表头全选；本地资产与漏洞库行都有 number 型 id
  selected?: Set<number>;
  onToggleAll?: (ids: number[]) => void;
  children: React.ReactNode;
}) {
  const childRows = React.Children.toArray(children);
  const pageCount = Math.max(1, Math.ceil(total / size));
  const start = total === 0 ? 0 : page * size + 1;
  const end = page * size + childRows.length;

  const pageIds = dataRows?.map((r) => r.id) ?? [];
  const allSelected = pageIds.length > 0 && selected != null && pageIds.every((id) => selected.has(id));
  const someSelected = selected != null && pageIds.some((id) => selected.has(id));

  return (
    <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
      <div className="min-h-0 flex-1 overflow-auto scrollbar-thin scrollbar-track-transparent">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-card">
            <TableRow>
              {cols.map((c, i) =>
                c === "" && i === 0 && onToggleAll ? (
                  <TableHead key={i} className="w-8 pr-0">
                    <Checkbox
                      checked={allSelected ? true : someSelected ? "indeterminate" : false}
                      onCheckedChange={() => onToggleAll(pageIds)}
                    />
                  </TableHead>
                ) : (
                  <TableHead key={c + i}>{c}</TableHead>
                ),
              )}
            </TableRow>
          </TableHeader>
          <TableBody>
            {childRows.length > 0 ? (
              childRows
            ) : (
              <TableRow>
                <TableCell colSpan={cols.length} className="py-12 text-center text-sm text-muted-foreground">
                  {loaded ? "暂无数据。" : "加载中…"}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      {total > 0 && (
        <div className="flex shrink-0 items-center gap-2 border-t px-3 py-1.5 text-xs text-muted-foreground">
          <Select value={String(size)} onValueChange={(v) => onSize(Number(v))}>
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
                onClick={() => onPage((p) => Math.max(0, p - 1))}
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
                onClick={() => onPage((p) => Math.min(pageCount - 1, p + 1))}
              >
                <ChevronRightIcon />
              </Button>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function Chips({ items, mono }: { items: string[]; mono?: boolean }) {
  const clean = items.filter(Boolean);
  if (clean.length === 0) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {clean.map((s, i) => (
        <Badge key={i} variant="outline" className={cn("text-[10px]", mono && "font-mono")}>
          {s}
        </Badge>
      ))}
    </div>
  );
}

function CompanyAvatar({ name, logo }: { name: string; logo?: string }) {
  const initial = (name.trim()[0] ?? "?").toUpperCase();
  return (
    <Avatar className="size-7 shrink-0">
      {logo ? <AvatarImage src={logo} alt={name} /> : null}
      <AvatarFallback className="text-xs">{initial}</AvatarFallback>
    </Avatar>
  );
}

// 后端返回的 warnings 说的是既有数据问题（不是本次提交的行有错），保存本身已经
// 成功。给更长的停留时间，因为它需要用户去处理具体的资产，扫一眼标题不够。
function showScopeWarnings(warnings?: string[]) {
  for (const warning of warnings ?? []) {
    toast.warning(warning, { duration: 15000 });
  }
}

function savedScopeRules(company: Company): CompanyScopeRule[] {
  return (company.scope ?? [])
    .map((scope) => ({ kind: scope.kind, value: scope.raw.trim() }))
    .filter((scope) => scope.value);
}

function savedScopeText(company: Company): string {
  return savedScopeRules(company)
    .map((scope) => scope.value)
    .join("\n");
}

// 新增企业使用与任务、LLM 编辑一致的右侧抽屉。
function CompanyDialog({ onSaved }: { onSaved: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [scopeText, setScopeText] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const parsedScope = React.useMemo(() => parseCompanyScopeText(scopeText), [scopeText]);

  React.useEffect(() => {
    if (!open) return;
    setName("");
    setScopeText("");
  }, [open]);

  const submit = async () => {
    if (!name.trim()) {
      toast.error("请填写企业名称");
      return;
    }
    if (parsedScope.errors.length > 0) {
      toast.error("请修正无效的资产范围");
      return;
    }
    setBusy(true);
    try {
      const res = await api.createCompany(name.trim(), parsedScope.rules);
      const added = res.scope_added ?? 0;
      const invalid = res.scope_invalid ?? 0;
      if (invalid > 0) toast.warning(`已创建企业，添加 ${added} 条范围；${invalid} 行无效`);
      else toast.success(`已创建企业，添加 ${added} 条范围`);
      setOpen(false);
      onSaved();
    } catch (e) {
      const msg = String((e as Error)?.message ?? e);
      if (/:\s*409$/.test(msg)) toast.error("企业已存在，请换个名称");
      else toast.error(`保存失败：${msg}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button size="sm">
          <BuildingIcon data-icon="inline-start" /> 新增企业
        </Button>
      </SheetTrigger>
      <SheetContent className="w-full! max-w-none! gap-0 p-0 sm:w-[520px]! sm:max-w-[520px]!">
        <SheetHeader className="border-b p-6">
          <SheetTitle>新增企业</SheetTitle>
          <SheetDescription>配置企业及其资产范围。关键词只作为 Agent 提示，不会自动归属资产。</SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto p-6">
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="cn-name">企业名称</FieldLabel>
              <Input
                id="cn-name"
                placeholder="如 Acme Corp（名称唯一）"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <ScopeTextEditor id="cn-scope" value={scopeText} onValueChange={setScopeText} parsed={parsedScope} />
          </FieldGroup>
        </div>
        <SheetFooter className="flex-row justify-end gap-2 border-t p-4">
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            取消
          </Button>
          <Button onClick={submit} disabled={busy || !name.trim() || parsedScope.errors.length > 0}>
            {busy ? "保存中…" : "保存"}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

// 编辑（覆盖）资产范围弹窗
function EditScopeDialog({ company, onSaved }: { company: Company; onSaved: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [scopeText, setScopeText] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const preservedScopeRules = React.useMemo(() => savedScopeRules(company), [company]);
  const parsedScope = React.useMemo(
    () => parseCompanyScopeText(scopeText, { preservedRules: preservedScopeRules }),
    [preservedScopeRules, scopeText],
  );

  React.useEffect(() => {
    if (!open) return;
    setScopeText(savedScopeText(company));
    setReason("");
  }, [open, company]);

  const submit = async () => {
    if (parsedScope.errors.length > 0) {
      toast.error("请修正无效的资产范围");
      return;
    }
    setBusy(true);
    try {
      const res = await api.updateCompanyScope(company.id, parsedScope.rules, reason);
      const errCount = res.invalid ?? 0;
      if (errCount > 0) toast.warning(`已保存；${errCount} 行无效`);
      else toast.success(`范围已更新，共 ${res.added} 条`);
      showScopeWarnings(res.warnings);
      setOpen(false);
      onSaved();
    } catch (e) {
      toast.error(`保存失败：${String((e as Error)?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="h-7">
          编辑
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>编辑资产范围 · {company.name}</DialogTitle>
          <DialogDescription>
            编辑后将替换全部现有范围。ICP 精确匹配资产，企业关键词仅作为 Agent 提示。
          </DialogDescription>
        </DialogHeader>
        <FieldGroup className="py-2">
          <ScopeTextEditor
            id={`edit-company-scope-${company.id}`}
            value={scopeText}
            onValueChange={setScopeText}
            parsed={parsedScope}
          />
          <Field>
            <FieldLabel htmlFor="es-reason">归属依据（可选）</FieldLabel>
            <Input
              id="es-reason"
              placeholder="如 证书 / whois / ASN 佐证"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            取消
          </Button>
          <Button onClick={submit} disabled={busy || parsedScope.errors.length > 0}>
            {busy ? "保存中…" : "覆盖保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// 追加资产范围弹窗
function AppendScopeDialog({ company, onSaved }: { company: Company; onSaved: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [scopeText, setScopeText] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const parsedScope = React.useMemo(() => parseCompanyScopeText(scopeText), [scopeText]);

  React.useEffect(() => {
    if (!open) return;
    setScopeText("");
    setReason("");
  }, [open]);

  const submit = async () => {
    if (parsedScope.rules.length === 0) {
      toast.error("请填写要追加的范围");
      return;
    }
    if (parsedScope.errors.length > 0) {
      toast.error("请修正无效的资产范围");
      return;
    }
    setBusy(true);
    try {
      const res = await api.addCompanyScope(company.id, parsedScope.rules, reason);
      const errCount = res.invalid ?? 0;
      if (errCount > 0) toast.warning(`已保存；${errCount} 行无效`);
      else toast.success(`已追加 ${res.added} 条范围`);
      showScopeWarnings(res.warnings);
      setOpen(false);
      onSaved();
    } catch (e) {
      toast.error(`保存失败：${String((e as Error)?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="h-7">
          追加
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>追加资产范围 · {company.name}</DialogTitle>
          <DialogDescription>新范围会追加到现有范围。ICP 精确匹配资产，企业关键词仅作为 Agent 提示。</DialogDescription>
        </DialogHeader>
        <FieldGroup className="py-2">
          <ScopeTextEditor
            id={`append-company-scope-${company.id}`}
            value={scopeText}
            onValueChange={setScopeText}
            parsed={parsedScope}
          />
          <Field>
            <FieldLabel htmlFor="as-reason">归属依据（可选）</FieldLabel>
            <Input
              id="as-reason"
              placeholder="如 证书 / whois / ASN 佐证"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            取消
          </Button>
          <Button onClick={submit} disabled={busy || parsedScope.rules.length === 0 || parsedScope.errors.length > 0}>
            {busy ? "保存中…" : "追加"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── kt-vuln 漏洞库（/api/vuln 用户令牌透传代理）──────────────────────────────
// 与上方「本地资产」完全独立：数据在 kt-vuln 侧、ID 空间不同，筛选/分页全部走服务端。

// 人工评级档位（POST /api/ratings 的 tier）。S 高于自动档 A，exclude 表示人工排除。
const VULN_MANUAL_TIERS: { value: VulnRatingTier; label: string }[] = [
  { value: "S", label: "S · 立即处理" },
  { value: "A", label: "A · 高价值" },
  { value: "B", label: "B" },
  { value: "C", label: "C" },
  { value: "D", label: "D" },
  { value: "exclude", label: "exclude · 排除" },
];
const VULN_MANUAL_TONE: Record<string, { variant: "default" | "secondary" | "outline"; cls: string }> = {
  S: { variant: "default", cls: "bg-fuchsia-700 hover:bg-fuchsia-700" },
  A: { variant: "default", cls: "bg-rose-600 hover:bg-rose-600" },
  B: { variant: "default", cls: "bg-amber-500 hover:bg-amber-500" },
  C: { variant: "secondary", cls: "bg-slate-200 text-slate-700" },
  D: { variant: "secondary", cls: "bg-zinc-200 text-zinc-700" },
  exclude: { variant: "outline", cls: "text-muted-foreground line-through" },
};

function VulnManualTierBadge({ tier, note }: { tier?: string; note?: string }) {
  if (!tier) return <span className="text-xs text-muted-foreground">—</span>;
  const tone = VULN_MANUAL_TONE[tier];
  return (
    <Badge
      variant={tone?.variant ?? "outline"}
      className={cn("font-mono text-[10px]", tone?.cls)}
      title={note ?? undefined}
    >
      {tier}
    </Badge>
  );
}

const VULN_VERDICT_OPTIONS = Object.entries(KV_VERDICT_LABEL).map(([value, label]) => ({ value, label }));
const VULN_SORT_OPTIONS: { value: string; label: string }[] = [
  { value: "default", label: "默认（ID）" },
  { value: "score_desc", label: "分数降序" },
];

function vulnTargetUrl(a: VulnAsset): string {
  return `${a.scheme ?? "http"}://${a.ip}:${a.port}`;
}

// vulnCleanFilters 去掉 undefined/空串键：避免对象展开时空值覆盖固定筛选（如 CVE 下钻的 cve）。
function vulnCleanFilters(f: VulnAssetFilters): VulnAssetFilters {
  const out: VulnAssetFilters = {};
  for (const [k, v] of Object.entries(f)) {
    if (v !== undefined && v !== "") out[k as keyof VulnAssetFilters] = v;
  }
  return out;
}

// 漏洞库资产面板：服务端分页 + 筛选 + 勾选批量写操作 + 下发任务。
// cveId 非空 = CVE 情报下钻视图（锁定 cve 筛选，判定列为该 CVE 下的判定，默认按分数降序）。
function VulnAssetsPanel({
  refreshKey,
  cveId,
  cveContext,
  onBack,
}: {
  refreshKey: number;
  cveId?: string;
  cveContext?: string;
  onBack?: () => void;
}) {
  const router = useRouter();
  // 草稿筛选：输入中不触发请求，点「筛选」才提交（cve 下钻查询线上很慢，避免无谓请求）。
  const [fq, setFq] = React.useState("");
  const [fTier, setFTier] = React.useState("all");
  const [fBizType, setFBizType] = React.useState("");
  const [fVerdict, setFVerdict] = React.useState("all");
  const [fCountry, setFCountry] = React.useState("");
  const [fMinScore, setFMinScore] = React.useState("");
  const [fEngagement, setFEngagement] = React.useState("all");
  const [fSort, setFSort] = React.useState("default");
  const [applied, setApplied] = React.useState<VulnAssetFilters>({});
  const [rows, setRows] = React.useState<VulnAsset[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  const [loading, setLoading] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState("");
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [reloadKey, setReloadKey] = React.useState(0);
  const reqRef = React.useRef(0);

  // 写操作 Dialog（ids 非空即打开；单行走行内「评级」按钮，多行走顶部批量按钮）
  const [rateIds, setRateIds] = React.useState<number[]>([]);
  const [tagIds, setTagIds] = React.useState<number[]>([]);
  const [engageIds, setEngageIds] = React.useState<number[]>([]);

  const applyFilters = () => {
    const min = Number.parseInt(fMinScore.trim(), 10);
    setApplied({
      q: fq.trim() || undefined,
      tier: fTier !== "all" ? fTier : undefined,
      biz_type: fBizType.trim() || undefined,
      verdict: fVerdict !== "all" ? fVerdict : undefined,
      country: fCountry.trim() || undefined,
      min_score: fMinScore.trim() !== "" && Number.isFinite(min) ? min : undefined,
      engagement: fEngagement !== "all" ? fEngagement : undefined,
      sort: fSort !== "default" ? fSort : undefined,
    });
  };

  const clearFilters = () => {
    setFq("");
    setFTier("all");
    setFBizType("");
    setFVerdict("all");
    setFCountry("");
    setFMinScore("");
    setFEngagement("all");
    setFSort("default");
    setApplied({});
  };

  // 生效筛选 = 已提交筛选 + CVE 下钻锁定条件（下钻默认按分数降序）。
  const effective = React.useMemo(() => {
    const sort = applied.sort ?? (cveId ? "score_desc" : undefined);
    return vulnCleanFilters({ ...applied, cve: cveId, sort });
  }, [applied, cveId]);

  // 筛选变更 / 外部刷新回到第一页并清空勾选。
  // biome-ignore lint/correctness/useExhaustiveDependencies: applied/refreshKey 变化是重置分页的显式触发器。
  React.useEffect(() => {
    setPage(0);
    setSelected(new Set());
  }, [applied, refreshKey]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey/reloadKey 是显式重载触发器（含写操作后）。
  React.useEffect(() => {
    const request = ++reqRef.current;
    setLoading(true);
    const run = async () => {
      try {
        const r = await vuln.assets(size, page * size, effective);
        if (reqRef.current !== request) return;
        setRows(r.items);
        setTotal(r.total);
        setError("");
      } catch (e) {
        if (reqRef.current !== request) return;
        setError(String((e as Error)?.message ?? e));
        setRows([]);
        setTotal(0);
      } finally {
        if (reqRef.current === request) {
          setLoading(false);
          setLoaded(true);
        }
      }
    };
    void run();
    return () => {
      reqRef.current++;
    };
  }, [effective, page, size, refreshKey, reloadKey]);

  const toggleSelect = (id: number) => {    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = (ids: number[]) => {
    setSelected((prev) => {
      const allSelected = ids.length > 0 && ids.every((id) => prev.has(id));
      const next = new Set(prev);
      for (const id of ids) {
        if (allSelected) next.delete(id);
        else next.add(id);
      }
      return next;
    });
  };

  // 写操作完成后的统一收尾：清空勾选并重拉当前页（成功与否以 toast 显式呈现，不静默回滚）。
  const afterWrite = () => {
    setSelected(new Set());
    setReloadKey((k) => k + 1);
  };

  // 下发任务：勾选资产拼成描述/目标，经 URL 参数预填到任务页的「新建任务」抽屉。
  const dispatchTask = () => {
    const picked = rows.filter((r) => selected.has(r.id));
    if (picked.length === 0) return;
    const MAX_LIST = 50;
    const lines = picked.slice(0, MAX_LIST).map((a) => {
      const parts = [vulnTargetUrl(a)];
      if (a.title) parts.push(a.title);
      if (a.hostnames?.length) parts.push(a.hostnames.join("; "));
      return `- ${parts.join(" · ")}`;
    });
    const filterSummary = Object.entries(effective)
      .filter(([k]) => k !== "sort" && k !== "cve")
      .map(([k, v]) => `${k}=${v}`)
      .join("，");
    const descLines: string[] = [];
    if (cveContext) descLines.push(cveContext);
    else if (filterSummary) descLines.push(`（kt-vuln 漏洞库筛选：${filterSummary}）`);
    descLines.push(
      `目标资产来自 kt-vuln 漏洞库（共 ${picked.length} 项${picked.length > MAX_LIST ? `，列出前 ${MAX_LIST} 项` : ""}）：`,
    );
    descLines.push(...lines);
    const params = new URLSearchParams({
      new_task: "1",
      name: cveId ? `${cveId} 验证` : `kt-vuln 资产测试（${picked.length} 项）`,
      description: descLines.join("\n"),
      goal: cveId
        ? `针对 ${cveId} 完成可利用性验证：可利用则给出可复现的利用步骤与证据，不可利用则给出明确结论。`
        : "验证以上资产的可利用漏洞（未授权访问/弱口令/RCE 等），输出可复现的证据。",
    });
    router.push(`/function/tasks?${params.toString()}`);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      {cveId ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={onBack}>
            <ArrowLeftIcon className="size-3.5" /> 返回 CVE 列表
          </Button>
          <span className="text-muted-foreground text-xs">
            {cveId} 的受影响资产：判定列为该 CVE 下的判定，按分数降序。此查询线上较慢，首次加载可能需要数十秒。
          </span>
        </div>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="h-8 w-40"
          placeholder="标题/域名 关键词"
          value={fq}
          onChange={(e) => setFq(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") applyFilters();
          }}
        />
        <Select value={fTier} onValueChange={setFTier}>
          <SelectTrigger size="sm" className="w-24">
            <SelectValue placeholder="等级" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部等级</SelectItem>
            {KV_TIERS.map((t) => (
              <SelectItem key={t} value={t}>
                {t} 级
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          className="h-8 w-36"
          placeholder="业务类型，如 盗U盘"
          value={fBizType}
          onChange={(e) => setFBizType(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") applyFilters();
          }}
        />
        <Select value={fVerdict} onValueChange={setFVerdict}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue placeholder="判定" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部判定</SelectItem>
            {VULN_VERDICT_OPTIONS.map((v) => (
              <SelectItem key={v.value} value={v.value}>
                {v.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          className="h-8 w-20"
          placeholder="国家码"
          value={fCountry}
          onChange={(e) => setFCountry(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") applyFilters();
          }}
        />
        <Input
          className="h-8 w-20"
          type="number"
          min={0}
          max={200}
          placeholder="分数 ≥"
          value={fMinScore}
          onChange={(e) => setFMinScore(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") applyFilters();
          }}
        />
        <Select value={fEngagement} onValueChange={setFEngagement}>
          <SelectTrigger size="sm" className="w-28">
            <SelectValue placeholder="作业状态" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            {KV_ENGAGEMENTS.map((v) => (
              <SelectItem key={v.value} value={v.value}>
                {v.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={fSort} onValueChange={setFSort}>
          <SelectTrigger size="sm" className="w-32">
            <SelectValue placeholder="排序" />
          </SelectTrigger>
          <SelectContent>
            {VULN_SORT_OPTIONS.map((v) => (
              <SelectItem key={v.value} value={v.value}>
                {v.label}
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
        <span className="ml-auto flex items-center gap-1.5">
          <Button
            variant="outline"
            size="sm"
            disabled={selected.size === 0}
            title={selected.size === 0 ? "先勾选资产" : undefined}
            onClick={() => setRateIds(Array.from(selected))}
          >
            人工评级
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={selected.size === 0}
            title={selected.size === 0 ? "先勾选资产" : undefined}
            onClick={() => setTagIds(Array.from(selected))}
          >
            业务标签
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={selected.size === 0}
            title={selected.size === 0 ? "先勾选资产" : undefined}
            onClick={() => setEngageIds(Array.from(selected))}
          >
            作业状态
          </Button>
          <Button size="sm" disabled={selected.size === 0} onClick={dispatchTask}>
            <SendIcon className="size-3.5" /> 下发任务{selected.size > 0 ? ` (${selected.size})` : ""}
          </Button>
        </span>
      </div>
      {error ? (
        <p role="alert" className="text-destructive text-sm">
          {error}
        </p>
      ) : null}
      <AssetCard
        cols={["", "目标", "组件", "价值", "人工评级", "业务", "国家", "作业状态", "判定", "最近发现"]}
        loaded={loaded}
        total={total}
        page={page}
        size={size}
        onSize={setSize}
        onPage={setPage}
        rows={rows}
        selected={selected}
        onToggleAll={toggleSelectAll}
      >
        {rows.map((a) => {
          const target = vulnTargetUrl(a);
          const compBits: string[] = [];
          if (a.component) compBits.push(a.php_version ? `${a.component} (${a.version ?? "?"})` : a.component);
          return (
            <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
              <TableCell className="w-8 pr-0">
                <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
              </TableCell>
              <TableCell className="max-w-[18rem]">
                <a
                  href={target}
                  target="_blank"
                  rel="noreferrer"
                  className="text-blue-600 font-mono text-xs font-medium hover:underline dark:text-blue-400"
                  title={target}
                >
                  {target}
                </a>
                {a.title ? (
                  <div className="text-muted-foreground truncate text-xs" title={a.title}>
                    {a.title}
                  </div>
                ) : null}
                {a.hostnames?.length ? (
                  <div className="text-muted-foreground truncate font-mono text-[10px]" title={a.hostnames.join("; ")}>
                    {a.hostnames.join("; ")}
                  </div>
                ) : null}
              </TableCell>
              <TableCell>
                {compBits.length === 0 && !a.php_version ? (
                  <span className="text-xs text-muted-foreground">—</span>
                ) : (
                  <div className="flex flex-wrap items-center gap-1">
                    {compBits.length > 0 && (
                      <Badge variant="secondary" className="font-mono text-[10px]">
                        {compBits[0]}
                      </Badge>
                    )}
                    {a.php_version ? (
                      <Badge variant="outline" className="font-mono text-[10px]">
                        php {a.php_version}
                      </Badge>
                    ) : null}
                  </div>
                )}
              </TableCell>
              <TableCell className="whitespace-nowrap">
                <KVValueBadge tier={a.tier} score={a.score} />
              </TableCell>
              <TableCell>
                <span className="flex items-center gap-1">
                  <VulnManualTierBadge tier={a.manual_tier} note={a.rating_note} />
                  <Button
                    variant="ghost"
                    size="icon"
                    className="text-muted-foreground size-7 hover:text-foreground"
                    aria-label={`编辑资产 ${a.id} 的人工评级`}
                    onClick={() => setRateIds([a.id])}
                  >
                    <PencilIcon className="size-3.5" />
                  </Button>
                </span>
              </TableCell>
              <TableCell className="max-w-[8rem]" title={a.biz_type}>
                {a.biz_type ? (
                  <Badge variant="secondary" className="max-w-full truncate text-[10px]">
                    {a.biz_type}
                  </Badge>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="font-mono text-xs">{a.country || "—"}</TableCell>
              <TableCell className="whitespace-nowrap">
                <div className="flex flex-col items-start gap-0.5">
                  {a.engagement_status ? <KVEngagementBadge status={a.engagement_status} /> : <span className="text-muted-foreground text-xs">—</span>}
                  {a.engagement_owner ? (
                    <span className="text-muted-foreground text-[10px]">{a.engagement_owner}</span>
                  ) : null}
                </div>
              </TableCell>
              <TableCell className="whitespace-nowrap">
                {a.verdict ? <KVVerdictBadge verdict={a.verdict} /> : <span className="text-muted-foreground text-xs">—</span>}
              </TableCell>
              <TableCell className="font-mono text-xs whitespace-nowrap">
                {a.last_seen ? a.last_seen.slice(0, 10) : "—"}
              </TableCell>
            </TableRow>
          );
        })}
      </AssetCard>

      <VulnRateDialog ids={rateIds} onClose={() => setRateIds([])} onDone={afterWrite} />
      <VulnTagDialog ids={tagIds} onClose={() => setTagIds([])} onDone={afterWrite} />
      <VulnEngageDialog ids={engageIds} onClose={() => setEngageIds([])} onDone={afterWrite} />
    </div>
  );
}

// CVE 严重度配色：9+ 红 / 7+ 橙 / 4+ 琥珀 / 其余中性。
function vulnSeverityClass(severity: number): string {
  if (severity >= 9) return "bg-red-600 hover:bg-red-600";
  if (severity >= 7) return "bg-orange-500 hover:bg-orange-500";
  if (severity >= 4) return "bg-amber-400 text-amber-950 hover:bg-amber-400";
  return "bg-slate-300 hover:bg-slate-300";
}

// CVE 严重度徽章。
function VulnSeverityBadge({ severity }: { severity?: number }) {
  if (severity == null) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <Badge variant="default" className={cn("font-mono text-[10px] tabular-nums", vulnSeverityClass(severity))}>
      {severity.toFixed(1)}
    </Badge>
  );
}

// 资产面（surface）计数：可确认/疑似/已修复/未知，颜色与判定徽章一致。
function VulnSurfaceCounts({ surface }: { surface?: { vulnerable: number; executable: number; patched: number; not_applicable: number; unknown: number } }) {
  if (!surface) return <span className="text-xs text-muted-foreground">—</span>;
  const cells: { label: string; value: number; cls: string }[] = [
    { label: "可确认", value: surface.executable, cls: "text-red-600 dark:text-red-400" },
    { label: "疑似", value: surface.vulnerable, cls: "text-orange-600 dark:text-orange-400" },
    { label: "已修复", value: surface.patched, cls: "text-emerald-600 dark:text-emerald-400" },
    { label: "未知", value: surface.unknown, cls: "text-muted-foreground" },
  ];
  return (
    <span className="flex flex-wrap gap-x-2 gap-y-0.5 font-mono text-[10px] tabular-nums">
      {cells.map((c) => (
        <span key={c.label} className={c.cls} title={c.label}>
          {c.label} {c.value}
        </span>
      ))}
    </span>
  );
}

// CVE 列表空态文案（避免 JSX 里嵌套三元）。
function cveEmptyMessage(loading: boolean, error: string): string {
  if (loading) return "加载中…";
  if (error) return "加载失败，请检查上方错误信息。";
  return "暂无匹配的 CVE。";
}

// CVE 情报面板：CVE 列表（客户端过滤）+ 「查看资产」下钻（懒加载：点开才发起 cve 筛选查询）。
function VulnCvesPanel({ refreshKey }: { refreshKey: number }) {
  const [items, setItems] = React.useState<VulnCve[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [q, setQ] = React.useState("");
  const [kevOnly, setKevOnly] = React.useState(false);
  const [category, setCategory] = React.useState("all");
  const [drill, setDrill] = React.useState<VulnCve | null>(null);
  const reqRef = React.useRef(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey 是外部「刷新」按钮的显式重载触发器。
  React.useEffect(() => {
    const request = ++reqRef.current;
    setLoading(true);
    vuln
      .cves()
      .then((r) => {
        if (reqRef.current !== request) return;
        setItems(r);
        setError("");
      })
      .catch((e) => {
        if (reqRef.current !== request) return;
        setError(String((e as Error)?.message ?? e));
      })
      .finally(() => {
        if (reqRef.current === request) setLoading(false);
      });
    return () => {
      reqRef.current++;
    };
  }, [refreshKey]);

  const categories = React.useMemo(
    () => Array.from(new Set(items.map((c) => c.category).filter((c): c is string => !!c))).sort(),
    [items],
  );

  const filtered = React.useMemo(() => {
    const needle = q.trim().toLowerCase();
    return items.filter((c) => {
      if (kevOnly && !c.kev) return false;
      if (category !== "all" && c.category !== category) return false;
      if (!needle) return true;
      return (
        c.cve_id.toLowerCase().includes(needle) ||
        (c.title ?? "").toLowerCase().includes(needle) ||
        (c.category ?? "").toLowerCase().includes(needle) ||
        Object.keys(c.affected ?? {}).some((k) => k.toLowerCase().includes(needle))
      );
    });
  }, [items, q, kevOnly, category]);

  // 下钻视图：挂载即拉 cve 筛选资产（用户主动点击才发生），返回时回列表。
  if (drill) {
    return (
      <VulnAssetsPanel
        refreshKey={refreshKey}
        cveId={drill.cve_id}
        cveContext={`CVE：${drill.cve_id}（${drill.title}，severity ${drill.severity ?? "?"}${drill.kev ? "，在 KEV 清单" : ""}）`}
        onBack={() => setDrill(null)}
      />
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="h-8 w-52"
          placeholder="搜索 CVE 编号 / 标题 / 组件"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <Select value={category} onValueChange={setCategory}>
          <SelectTrigger size="sm" className="w-44">
            <SelectValue placeholder="分类" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部分类</SelectItem>
            {categories.map((c) => (
              <SelectItem key={c} value={c}>
                {c}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <label className="flex cursor-pointer items-center gap-1.5 text-xs" htmlFor="cve-kev-only">
          <Checkbox id="cve-kev-only" checked={kevOnly} onCheckedChange={(v) => setKevOnly(!!v)} />
          仅 KEV（已知被利用）
        </label>
        <span className="text-muted-foreground ml-auto text-xs">
          共 {filtered.length} 条（来自 kt-vuln CVE 情报）
        </span>
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
                <TableHead className="w-32">CVE</TableHead>
                <TableHead className="w-20">严重度</TableHead>
                <TableHead className="w-16">KEV</TableHead>
                <TableHead>标题</TableHead>
                <TableHead className="w-36">影响组件</TableHead>
                <TableHead>资产面</TableHead>
                <TableHead className="w-24 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((c) => {
                const affected = Object.entries(c.affected ?? {});
                return (
                  <TableRow key={c.cve_id}>
                    <TableCell className="font-mono text-xs font-medium">{c.cve_id}</TableCell>
                    <TableCell>
                      <VulnSeverityBadge severity={c.severity} />
                    </TableCell>
                    <TableCell>
                      {c.kev ? (
                        <Badge variant="default" className="bg-red-600 text-[10px] hover:bg-red-600">
                          KEV
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </TableCell>
                    <TableCell className="max-w-[20rem]">
                      <div className="truncate text-xs" title={c.title}>
                        {c.title || "—"}
                      </div>
                      {c.category ? (
                        <div className="text-muted-foreground text-[10px]">{c.category}</div>
                      ) : null}
                    </TableCell>
                    <TableCell title={affected.map(([k, v]) => `${k}: ${v.join(" / ")}`).join("\n")}>
                      {affected.length === 0 ? (
                        <span className="text-xs text-muted-foreground">—</span>
                      ) : (
                        <Chips
                          items={[
                            ...affected.slice(0, 2).map(([k, v]) => `${k} ${v.join("/")}`),
                            ...(affected.length > 2 ? [`+${affected.length - 2} 组件`] : []),
                          ]}
                          mono
                        />
                      )}
                    </TableCell>
                    <TableCell>
                      <VulnSurfaceCounts surface={c.surface} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="outline" size="sm" className="h-7" onClick={() => setDrill(c)}>
                        查看资产
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-muted-foreground py-12 text-center text-sm">
                    {cveEmptyMessage(loading, error)}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </Card>
    </div>
  );
}

// 人工评级 Dialog（单条/批量共用）：逐条调 POST /api/ratings，失败项显式报错、不回滚已成功项。
function VulnRateDialog({
  ids,
  onClose,
  onDone,
}: {
  ids: number[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [tier, setTier] = React.useState<VulnRatingTier>("A");
  const [note, setNote] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (ids.length > 0) {
      setTier("A");
      setNote("");
    }
  }, [ids]);

  const submit = async () => {
    if (ids.length === 0) return;
    setBusy(true);
    const failures: string[] = [];
    for (const id of ids) {
      try {
        await vuln.rate(id, tier, note);
      } catch (e) {
        failures.push(`#${id}：${String((e as Error)?.message ?? e)}`);
      }
    }
    setBusy(false);
    if (failures.length > 0) {
      toast.error(
        `评级失败 ${failures.length}/${ids.length} 项（已成功项不回滚）：${failures.slice(0, 3).join("；")}${failures.length > 3 ? " 等" : ""}`,
        { duration: 12000 },
      );
    }
    if (failures.length < ids.length) toast.success(`已评级 ${ids.length - failures.length} 项为 ${tier}`);
    onClose();
    onDone();
  };

  return (
    <Dialog open={ids.length > 0} onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>人工评级（{ids.length} 项资产）</DialogTitle>
          <DialogDescription>
            覆盖写入 kt-vuln 的人工评级档位；不影响自动 tier。失败会逐条提示，不会回滚已成功项。
          </DialogDescription>
        </DialogHeader>
        <FieldGroup className="py-2">
          <Field>
            <FieldLabel htmlFor="vuln-rate-tier">评级档位</FieldLabel>
            <Select value={tier} onValueChange={(v) => setTier(v as VulnRatingTier)}>
              <SelectTrigger id="vuln-rate-tier" className="w-full bg-background">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {VULN_MANUAL_TIERS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel htmlFor="vuln-rate-note">备注（可选）</FieldLabel>
            <Input
              id="vuln-rate-note"
              placeholder="如 人工复核：确认为高价值目标"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            取消
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "写入中…" : "确认评级"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// 业务标签 Dialog（单条/批量共用）：一次 bulk 调用写全部勾选资产。
function VulnTagDialog({
  ids,
  onClose,
  onDone,
}: {
  ids: number[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [tagType, setTagType] = React.useState("biz_type");
  const [tagValue, setTagValue] = React.useState("");
  const [confidence, setConfidence] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (ids.length > 0) {
      setTagType("biz_type");
      setTagValue("");
      setConfidence("");
    }
  }, [ids]);

  const submit = async () => {
    if (!tagType.trim() || !tagValue.trim()) {
      toast.error("请填写标签类型与标签值");
      return;
    }
    const conf = Number.parseFloat(confidence);
    setBusy(true);
    try {
      const r = await vuln.tagBulk(
        ids.map((id) => ({
          asset_id: id,
          tag_type: tagType.trim(),
          tag_value: tagValue.trim(),
          confidence: Number.isFinite(conf) ? conf : undefined,
        })),
      );
      toast.success(`已写入 ${r.written ?? ids.length} 条标签（${tagType.trim()}=${tagValue.trim()}）`);
      onClose();
      onDone();
    } catch (e) {
      toast.error(`打标签失败：${String((e as Error)?.message ?? e)}`, { duration: 12000 });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={ids.length > 0} onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>业务标签（{ids.length} 项资产）</DialogTitle>
          <DialogDescription>
            批量写入 kt-vuln 资产标签。标签值如：盗U盘 / VPN平台 / 资金盘；置信度 0-1 可留空。
          </DialogDescription>
        </DialogHeader>
        <FieldGroup className="py-2">
          <Field>
            <FieldLabel htmlFor="vuln-tag-type">标签类型</FieldLabel>
            <Input
              id="vuln-tag-type"
              placeholder="biz_type（业务类型）"
              value={tagType}
              onChange={(e) => setTagType(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="vuln-tag-value">标签值</FieldLabel>
            <Input
              id="vuln-tag-value"
              placeholder="如 盗U盘"
              value={tagValue}
              onChange={(e) => setTagValue(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="vuln-tag-conf">置信度（0-1，可选）</FieldLabel>
            <Input
              id="vuln-tag-conf"
              type="number"
              min={0}
              max={1}
              step={0.1}
              placeholder="留空 = 不写置信度"
              value={confidence}
              onChange={(e) => setConfidence(e.target.value)}
            />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            取消
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "写入中…" : "写入标签"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// 作业状态 Dialog（单条/批量共用）：逐条调 POST /api/engagements，失败项显式报错、不回滚已成功项。
function VulnEngageDialog({
  ids,
  onClose,
  onDone,
}: {
  ids: number[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [status, setStatus] = React.useState<VulnEngagementStatus>("claimed");
  const [owner, setOwner] = React.useState("");
  const [note, setNote] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (ids.length > 0) {
      setStatus("claimed");
      setOwner("");
      setNote("");
    }
  }, [ids]);

  const submit = async () => {
    if (ids.length === 0) return;
    setBusy(true);
    const failures: string[] = [];
    for (const id of ids) {
      try {
        await vuln.engage(id, status, owner, note);
      } catch (e) {
        failures.push(`#${id}：${String((e as Error)?.message ?? e)}`);
      }
    }
    setBusy(false);
    if (failures.length > 0) {
      toast.error(
        `作业状态更新失败 ${failures.length}/${ids.length} 项（已成功项不回滚）：${failures.slice(0, 3).join("；")}${failures.length > 3 ? " 等" : ""}`,
        { duration: 12000 },
      );
    }
    if (failures.length < ids.length) {
      const label = KV_ENGAGEMENTS.find((v) => v.value === status)?.label ?? status;
      toast.success(`已更新 ${ids.length - failures.length} 项为「${label}」`);
    }
    onClose();
    onDone();
  };

  return (
    <Dialog open={ids.length > 0} onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>作业状态（{ids.length} 项资产）</DialogTitle>
          <DialogDescription>
            更新 kt-vuln 作业流转状态（认领/进行/完结等）。失败会逐条提示，不会回滚已成功项。
          </DialogDescription>
        </DialogHeader>
        <FieldGroup className="py-2">
          <Field>
            <FieldLabel htmlFor="vuln-engage-status">状态</FieldLabel>
            <Select value={status} onValueChange={(v) => setStatus(v as VulnEngagementStatus)}>
              <SelectTrigger id="vuln-engage-status" className="w-full bg-background">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {KV_ENGAGEMENTS.map((v) => (
                  <SelectItem key={v.value} value={v.value}>
                    {v.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel htmlFor="vuln-engage-owner">负责人（可选）</FieldLabel>
            <Input
              id="vuln-engage-owner"
              placeholder="如 yg"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="vuln-engage-note">备注（可选）</FieldLabel>
            <Input
              id="vuln-engage-note"
              placeholder="如 已在测试，等待出结果"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            取消
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "写入中…" : "更新状态"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function AssetsPage() {
  return (
    <React.Suspense fallback={null}>
      <AssetsContent />
    </React.Suspense>
  );
}
