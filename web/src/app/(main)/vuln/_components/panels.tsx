"use client";

// Vuln 情报站面板（kt-vuln /api/vuln 用户令牌透传代理）。
// v0.3.26 前挂在资产页的两个 tab，v0.4.0 起拆成独立一级菜单：
// /vuln/assets 渲染 VulnAssetsPanel，/vuln/cves 渲染 VulnCvesPanel（下钻留在本页内）。
// 与本地资产页完全独立：数据在 kt-vuln 侧、ID 空间不同，筛选/分页全部走服务端。

import * as React from "react";

import { useRouter } from "next/navigation";

import { ArrowLeftIcon, PencilIcon, SendIcon } from "lucide-react";
import { toast } from "sonner";

import { AssetCard, Chips } from "@/components/asset-card";
import {
  KV_ENGAGEMENTS,
  KV_TIERS,
  KV_VERDICT_LABEL,
  KVEngagementBadge,
  KVValueBadge,
  KVVerdictBadge,
} from "@/components/kv-badges";
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
} from "@/components/ui/dialog";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import {
  type VulnAsset,
  type VulnAssetFilters,
  type VulnCve,
  type VulnEngagementStatus,
  type VulnRatingTier,
  type VulnWorksetItem,
  saveVulnWorksetDraft,
  vuln,
} from "@/lib/vuln";

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

export function vulnTargetUrl(a: VulnAsset): string {
  return `${a.scheme ?? "http"}://${a.ip}:${a.port}`;
}

// vulnCleanFilters 去掉 undefined/空串键：避免对象展开时空值覆盖固定筛选（如 CVE 下钻的 cve）。
export function vulnCleanFilters(f: VulnAssetFilters): VulnAssetFilters {
  const out: VulnAssetFilters = {};
  for (const [k, v] of Object.entries(f)) {
    if (v !== undefined && v !== "") out[k as keyof VulnAssetFilters] = v;
  }
  return out;
}

// 漏洞库资产面板：服务端分页 + 筛选 + 勾选批量写操作 + 下发任务。
// cveId 非空 = CVE 情报下钻视图（锁定 cve 筛选，判定列为该 CVE 下的判定，默认按分数降序）。
export function VulnAssetsPanel({
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

  // 下发任务：勾选资产拼成描述/目标，经 URL 参数预填到任务页的「新建任务」抽屉；
  // 同时把选中行的结构化快照写进 sessionStorage（任务创建成功后 pin 成任务的
  // Vuln 工作集，见 tasks 页）。文本列表仍截前 50 条，快照带上限 500 条。
  const dispatchTask = () => {
    const picked = rows.filter((r) => selected.has(r.id));
    if (picked.length === 0) return;
    const MAX_LIST = 50;
    const MAX_WORKSET = 500;
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
    saveVulnWorksetDraft(
      picked.slice(0, MAX_WORKSET).map(
        (a): VulnWorksetItem => ({
          vuln_asset_id: a.id,
          url: vulnTargetUrl(a),
          host: a.ip,
          port: a.port,
          scheme: a.scheme ?? "http",
          title: a.title ?? "",
          tier: a.tier ?? "",
          manual_tier: a.manual_tier ?? "",
          score: a.score ?? 0,
          cve: cveId ?? "",
          verdict: a.verdict ?? "",
          biz_type: a.biz_type ?? "",
        }),
      ),
    );
    const params = new URLSearchParams({
      new_task: "1",
      vuln_ws: "1",
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
export function vulnSeverityClass(severity: number): string {
  if (severity >= 9) return "bg-red-600 hover:bg-red-600";
  if (severity >= 7) return "bg-orange-500 hover:bg-orange-500";
  if (severity >= 4) return "bg-amber-400 text-amber-950 hover:bg-amber-400";
  return "bg-slate-300 hover:bg-slate-300";
}

// CVE 严重度徽章。
export function VulnSeverityBadge({ severity }: { severity?: number }) {
  if (severity == null) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <Badge variant="default" className={cn("font-mono text-[10px] tabular-nums", vulnSeverityClass(severity))}>
      {severity.toFixed(1)}
    </Badge>
  );
}

// 资产面（surface）计数：可确认/疑似/已修复/未知，颜色与判定徽章一致。
export function VulnSurfaceCounts({ surface }: { surface?: { vulnerable: number; executable: number; patched: number; not_applicable: number; unknown: number } }) {
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
export function cveEmptyMessage(loading: boolean, error: string): string {
  if (loading) return "加载中…";
  if (error) return "加载失败，请检查上方错误信息。";
  return "暂无匹配的 CVE。";
}

// CVE 情报面板：CVE 列表（客户端过滤）+ 「查看资产」下钻（懒加载：点开才发起 cve 筛选查询）。
export function VulnCvesPanel({ refreshKey }: { refreshKey: number }) {
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
