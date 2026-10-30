"use client";

import * as React from "react";

import { AlertCircleIcon, CheckCircle2Icon, DownloadIcon, PlugZapIcon, RefreshCwIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { KTVulnAsset, KTVulnFilters, SSProject, SSTask } from "@/lib/types";

// 数据源状态卡共用的最小形状（ScopeSentry 与 kt-vuln 一致）。
type SyncSourceStatus = {
  exists: boolean;
  configured: boolean;
  enabled: boolean;
  reachable: boolean;
};

type SSStatus = SyncSourceStatus & {
  url?: string;
  tools: string[];
};

type KVStatus = {
  configured: boolean;
  enabled: boolean;
  url: string;
  token_hint: string;
  reachable: boolean;
  stats: { assets_total: number; cves_total: number; assessments_total: number; findings_total: number } | null;
  stats_error: string;
};

// 同步结果面板共用的最小形状（kt-vuln 没有 companies，为可选）。
type SyncResultData = {
  synced?: Record<string, number> | null;
  companies?: string[] | null;
  warnings?: string[] | null;
  errors?: string[] | null;
  fetched?: number; // kt-vuln：本次实际拉取条数
  remote_total?: number; // kt-vuln：远端匹配总数
  truncated?: boolean;
};

type Dimension = "project" | "task";

const ASSET_TYPES: { key: string; label: string }[] = [
  { key: "subdomain", label: "子域名" },
  { key: "service", label: "服务" },
  { key: "app", label: "App" },
];

export default function AssetSyncPage() {
  return (
    <div className="p-4 md:p-6">
      <div className="mb-4">
        <h1 className="font-semibold text-xl">资产同步</h1>
        <p className="text-muted-foreground text-sm">从外部数据源同步资产入库</p>
      </div>
      <Tabs defaultValue="scopesentry">
        <TabsList>
          <TabsTrigger value="scopesentry">ScopeSentry</TabsTrigger>
          <TabsTrigger value="ktvuln">kt-vuln</TabsTrigger>
        </TabsList>
        <TabsContent value="scopesentry" className="mt-4">
          <ScopeSentryPanel />
        </TabsContent>
        <TabsContent value="ktvuln" className="mt-4">
          <KTVulnPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ScopeSentryPanel() {
  const [status, setStatus] = React.useState<SSStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = React.useState(true);

  const loadStatus = React.useCallback(() => {
    setLoadingStatus(true);
    api
      .ssStatus()
      .then(setStatus)
      .catch((e) => toast.error(`读取数据源状态失败：${e.message}`))
      .finally(() => setLoadingStatus(false));
  }, []);

  React.useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  const ready = !!status && status.exists && status.configured && status.enabled;

  return (
    <div className="space-y-4">
      <DataSourceCard status={status} loading={loadingStatus} onChanged={loadStatus} />
      {ready ? (
        <SyncWorkbench />
      ) : (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground text-sm">
            数据源就绪后即可选择项目 / 任务进行同步。
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function KTVulnPanel() {
  const [status, setStatus] = React.useState<KVStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = React.useState(true);

  const loadStatus = React.useCallback(() => {
    setLoadingStatus(true);
    api
      .kvStatus()
      .then(setStatus)
      .catch((e) => toast.error(`读取数据源状态失败：${e.message}`))
      .finally(() => setLoadingStatus(false));
  }, []);

  React.useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  const ready = !!status && status.configured && status.enabled;

  return (
    <div className="space-y-4">
      <KTVulnDataSourceCard status={status} loading={loadingStatus} onChanged={loadStatus} />
      {ready ? (
        <KTVulnWorkbench />
      ) : (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground text-sm">
            数据源就绪后即可筛选资产进行同步。
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── 数据源状态卡 ─────────────────────────────────────────────────────────────

function DataSourceCard({
  status,
  loading,
  onChanged,
}: {
  status: SSStatus | null;
  loading: boolean;
  onChanged: () => void;
}) {
  const [url, setUrl] = React.useState("");
  const [apiKey, setApiKey] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (status?.url) setUrl(status.url);
  }, [status?.url]);

  const create = async () => {
    setBusy(true);
    try {
      await api.ssDatasource({});
      toast.success("已创建 ScopeSentry 数据源，请填写地址与密钥");
      onChanged();
    } catch (e) {
      toast.error(`创建失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    if (!url.trim()) return toast.error("请填写 MCP 地址");
    setBusy(true);
    try {
      const r = await api.ssDatasource({ url: url.trim(), api_key: apiKey.trim() });
      toast.success(r.enabled ? "已保存并启用数据源" : "已保存（尚未满足启用条件）");
      setApiKey("");
      onChanged();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-base">
          <PlugZapIcon className="size-4" /> 数据源状态
          <StatusBadge status={status} loading={loading} />
        </CardTitle>
        <Button variant="ghost" size="sm" onClick={onChanged} disabled={loading}>
          <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} /> 刷新
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {!status?.exists ? (
          <div className="flex items-center justify-between gap-4">
            <p className="text-muted-foreground text-sm">
              尚未创建 ScopeSentry 数据源。创建后会新增一个占位 MCP（地址/密钥为空、未启用）。
            </p>
            <Button onClick={create} disabled={busy}>
              创建数据源
            </Button>
          </div>
        ) : (
          <>
            {!status.configured && (
              <p className="text-amber-600 text-sm dark:text-amber-500">
                数据源已创建但未配置，请填写 MCP 地址与 API Key 后启用。
              </p>
            )}
            {status.configured && !status.enabled && (
              <p className="text-amber-600 text-sm dark:text-amber-500">数据源已配置但未启用，保存后将自动启用。</p>
            )}
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label>MCP 地址</Label>
                <Input placeholder="http://<主机>:8082/mcp" value={url} onChange={(e) => setUrl(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label>API Key（X-API-Key，留空保留原值）</Label>
                <Input
                  type="password"
                  placeholder="ssk_..."
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button onClick={save} disabled={busy}>
                保存并启用
              </Button>
              {status.enabled && status.tools.length > 0 && (
                <span className="text-muted-foreground text-xs">已发现 {status.tools.length} 个工具</span>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function StatusBadge({ status, loading }: { status: SyncSourceStatus | null; loading: boolean }) {
  if (loading || !status) return <Badge variant="secondary">检测中…</Badge>;
  if (!status.exists) return <Badge variant="destructive">未创建</Badge>;
  if (!status.configured) return <Badge variant="outline">未配置</Badge>;
  if (!status.enabled) return <Badge variant="outline">未启用</Badge>;
  if (status.reachable)
    return (
      <Badge className="bg-emerald-600 hover:bg-emerald-600">
        <CheckCircle2Icon className="mr-1 size-3" /> 已连接
      </Badge>
    );
  return (
    <Badge variant="destructive">
      <AlertCircleIcon className="mr-1 size-3" /> 不可达
    </Badge>
  );
}

// ── kt-vuln 数据源状态卡 ──────────────────────────────────────────────────────

const KTVULN_DEFAULT_URL = "https://vuln.ktyun.cc";

function KTVulnDataSourceCard({
  status,
  loading,
  onChanged,
}: {
  status: KVStatus | null;
  loading: boolean;
  onChanged: () => void;
}) {
  const [url, setUrl] = React.useState("");
  const [token, setToken] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    setUrl(status?.url || KTVULN_DEFAULT_URL);
  }, [status?.url]);

  const save = async () => {
    if (!url.trim()) return toast.error("请填写服务地址");
    if (!token.trim() && !status?.configured) return toast.error("首次配置需要填写 Bearer Token");
    setBusy(true);
    try {
      const r = await api.kvDatasource({ url: url.trim(), token: token.trim() });
      toast.success(r.enabled ? "已保存并启用数据源" : "已保存（尚未满足启用条件）");
      setToken("");
      onChanged();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-base">
          <PlugZapIcon className="size-4" /> 数据源状态
          <StatusBadge
            status={
              status
                ? { exists: true, configured: status.configured, enabled: status.enabled, reachable: status.reachable }
                : null
            }
            loading={loading}
          />
        </CardTitle>
        <Button variant="ghost" size="sm" onClick={onChanged} disabled={loading}>
          <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} /> 刷新
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {!status?.configured && (
          <p className="text-amber-600 text-sm dark:text-amber-500">
            数据源未配置，填写服务地址与 Bearer Token 后保存即可启用。
          </p>
        )}
        {status?.configured && !status.enabled && (
          <p className="text-amber-600 text-sm dark:text-amber-500">数据源已配置但未启用，保存后将自动启用。</p>
        )}
        <div className="grid gap-3 md:grid-cols-2">
          <div className="space-y-1.5">
            <Label>服务地址</Label>
            <Input placeholder={KTVULN_DEFAULT_URL} value={url} onChange={(e) => setUrl(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label>Bearer Token（留空保留原值）</Label>
            <Input
              type="password"
              placeholder={status?.token_hint ? `当前 ${status.token_hint}` : "kt-identity 下发的 Token"}
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={save} disabled={busy}>
            保存并启用
          </Button>
          {status?.reachable && status.stats && (
            <span className="text-muted-foreground text-xs">
              资产 {status.stats.assets_total} · CVE {status.stats.cves_total} · 判定 {status.stats.assessments_total} ·
              发现 {status.stats.findings_total}
            </span>
          )}
          {status?.enabled && !status.reachable && status.stats_error && (
            <span className="text-destructive text-xs" title={status.stats_error}>
              连接失败：{status.stats_error}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ── 同步工作区（项目 / 任务维度）────────────────────────────────────────────────

function SyncWorkbench() {
  const [dimension, setDimension] = React.useState<Dimension>("project");
  const [assetTypes, setAssetTypes] = React.useState<Record<string, boolean>>({
    subdomain: true,
    service: true,
    app: true,
  });
  const [createCompany, setCreateCompany] = React.useState(true);

  const [projects, setProjects] = React.useState<SSProject[]>([]);
  const [tasks, setTasks] = React.useState<SSTask[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [selected, setSelected] = React.useState<Set<string>>(new Set());

  const [syncing, setSyncing] = React.useState(false);
  const [result, setResult] = React.useState<Awaited<ReturnType<typeof api.ssSync>> | null>(null);

  const load = React.useCallback(() => {
    setLoading(true);
    setSelected(new Set());
    const fn =
      dimension === "project"
        ? api.ssProjects(page, 50, search).then((r) => setProjects(r.projects))
        : api.ssTasks(page, 50, search).then(setTasks);
    fn.catch((e) => toast.error(`加载列表失败：${e.message}`)).finally(() => setLoading(false));
  }, [dimension, page, search]);

  React.useEffect(() => {
    load();
  }, [load]);

  const rows = dimension === "project" ? projects : tasks;
  const idOf = (row: SSProject | SSTask) => (dimension === "project" ? (row as SSProject).id : (row as SSTask).name);

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const toggleAll = () => {
    setSelected((prev) => (prev.size === rows.length ? new Set() : new Set(rows.map(idOf))));
  };

  const chosenTypes = ASSET_TYPES.filter((t) => assetTypes[t.key]).map((t) => t.key);

  const runSync = async () => {
    if (selected.size === 0) return toast.error(`请至少选择一个${dimension === "project" ? "项目" : "任务"}`);
    if (chosenTypes.length === 0) return toast.error("请至少选择一种资产类型");
    setSyncing(true);
    setResult(null);
    try {
      const r = await api.ssSync({
        dimension,
        targets: [...selected],
        asset_types: chosenTypes,
        create_company: dimension === "project" ? createCompany : false,
      });
      setResult(r);
      const total = Object.values(r.synced ?? {}).reduce((a, b) => a + b, 0);
      toast.success(`同步完成，共入库 ${total} 条资产`);
    } catch (e) {
      toast.error(`同步失败：${(e as Error).message}`);
    } finally {
      setSyncing(false);
    }
  };

  const renderRows = () => {
    if (loading) {
      return (
        <TableRow>
          <TableCell colSpan={4} className="py-8 text-center text-muted-foreground text-sm">
            加载中…
          </TableCell>
        </TableRow>
      );
    }
    if (rows.length === 0) {
      return (
        <TableRow>
          <TableCell colSpan={4} className="py-8 text-center text-muted-foreground text-sm">
            无数据
          </TableCell>
        </TableRow>
      );
    }
    if (dimension === "project") {
      return projects.map((p) => (
        <TableRow key={p.id} className="cursor-pointer" onClick={() => toggle(p.id)}>
          <TableCell onClick={(e) => e.stopPropagation()}>
            <Checkbox checked={selected.has(p.id)} onCheckedChange={() => toggle(p.id)} />
          </TableCell>
          <TableCell className="font-medium">{p.name}</TableCell>
          <TableCell>{p.tag ? <Badge variant="secondary">{p.tag}</Badge> : "—"}</TableCell>
          <TableCell className="text-right">{p.AssetCount ?? 0}</TableCell>
        </TableRow>
      ));
    }
    return tasks.map((t) => (
      <TableRow key={t.id} className="cursor-pointer" onClick={() => toggle(t.name)}>
        <TableCell onClick={(e) => e.stopPropagation()}>
          <Checkbox checked={selected.has(t.name)} onCheckedChange={() => toggle(t.name)} />
        </TableCell>
        <TableCell className="font-medium">{t.name}</TableCell>
        <TableCell>
          <Badge variant={t.progress === 100 ? "secondary" : "outline"}>
            {t.progress != null ? `${t.progress}%` : "—"}
          </Badge>
        </TableCell>
        <TableCell className="text-muted-foreground text-xs">{t.endTime || t.creatTime || "—"}</TableCell>
      </TableRow>
    ));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">选择数据同步</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* 维度切换 */}
        <Tabs
          value={dimension}
          onValueChange={(v) => {
            setDimension(v as Dimension);
            setPage(1);
          }}
        >
          <TabsList>
            <TabsTrigger value="project">项目维度</TabsTrigger>
            <TabsTrigger value="task">任务维度</TabsTrigger>
          </TabsList>
        </Tabs>

        {/* 资产类型 + 选项 */}
        <div className="flex flex-wrap items-center gap-4">
          <span className="font-medium text-sm">同步资产：</span>
          {ASSET_TYPES.map((t) => (
            <label key={t.key} htmlFor={`at-${t.key}`} className="flex items-center gap-1.5 text-sm">
              <Checkbox
                id={`at-${t.key}`}
                checked={!!assetTypes[t.key]}
                onCheckedChange={(c) => setAssetTypes((prev) => ({ ...prev, [t.key]: !!c }))}
              />
              {t.label}
            </label>
          ))}
          {dimension === "project" && (
            <label htmlFor="create-company" className="flex items-center gap-1.5 text-sm">
              <Checkbox id="create-company" checked={createCompany} onCheckedChange={(c) => setCreateCompany(!!c)} />
              按项目建立企业并写入资产范围
            </label>
          )}
        </div>

        {/* 搜索 + 操作 */}
        <div className="flex items-center gap-2">
          <div className="relative max-w-xs flex-1">
            <SearchIcon className="absolute top-1/2 left-2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-8"
              placeholder={dimension === "project" ? "搜索项目名" : "搜索任务名"}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  setPage(1);
                  load();
                }
              }}
            />
          </div>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} />
          </Button>
          <div className="flex-1" />
          <span className="text-muted-foreground text-xs">已选 {selected.size}</span>
          <Button onClick={runSync} disabled={syncing || selected.size === 0}>
            <DownloadIcon className={syncing ? "size-4 animate-pulse" : "size-4"} /> 同步选中
          </Button>
        </div>

        {/* 列表 */}
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox checked={rows.length > 0 && selected.size === rows.length} onCheckedChange={toggleAll} />
                </TableHead>
                <TableHead>{dimension === "project" ? "项目名" : "任务名"}</TableHead>
                {dimension === "project" ? (
                  <>
                    <TableHead>标签</TableHead>
                    <TableHead className="text-right">资产数</TableHead>
                  </>
                ) : (
                  <>
                    <TableHead>状态</TableHead>
                    <TableHead>时间</TableHead>
                  </>
                )}
              </TableRow>
            </TableHeader>
            <TableBody>{renderRows()}</TableBody>
          </Table>
        </div>

        {/* 分页 */}
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1 || loading} onClick={() => setPage((p) => p - 1)}>
            上一页
          </Button>
          <span className="text-muted-foreground text-xs">第 {page} 页</span>
          <Button
            variant="outline"
            size="sm"
            disabled={rows.length < 50 || loading}
            onClick={() => setPage((p) => p + 1)}
          >
            下一页
          </Button>
        </div>

        {/* 结果 */}
        {result && <SyncResult result={result} />}
      </CardContent>
    </Card>
  );
}

// ── kt-vuln 同步工作区（资产筛选预览 + 按条件导入）──────────────────────────────

const KV_TIERS = ["A", "B", "C", "D", "E"];
const KV_VERDICTS: { value: string; label: string }[] = [
  { value: "executable", label: "已验证可利用" },
  { value: "vulnerable", label: "版本命中" },
  { value: "patched", label: "已修复" },
  { value: "not_applicable", label: "不适用" },
  { value: "unknown", label: "未知" },
];
const KV_ENGAGEMENTS: { value: string; label: string }[] = [
  { value: "todo", label: "待处理" },
  { value: "claimed", label: "已认领" },
  { value: "in_progress", label: "进行中" },
  { value: "done_hit", label: "已命中" },
  { value: "done_miss", label: "未命中" },
  { value: "blocked", label: "受阻" },
  { value: "excluded", label: "已排除" },
];
const KV_PAGE_SIZE = 50;
const KV_DEFAULT_MAX = 5000;

const kvVerdictLabel = (v?: string | null) => KV_VERDICTS.find((x) => x.value === v)?.label ?? v ?? "—";

function KTVulnWorkbench() {
  const [filters, setFilters] = React.useState<KTVulnFilters>({});
  const [assets, setAssets] = React.useState<KTVulnAsset[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(1);
  const [loading, setLoading] = React.useState(false);
  const [importDomains, setImportDomains] = React.useState(true);
  const [maxAssets, setMaxAssets] = React.useState(KV_DEFAULT_MAX);
  const [syncing, setSyncing] = React.useState(false);
  const [result, setResult] = React.useState<SyncResultData | null>(null);

  const setFilter = (key: keyof KTVulnFilters, value: string | undefined) => {
    const v = value && value.trim() !== "" ? value.trim() : undefined;
    setFilters((prev) => (prev[key] === v ? prev : { ...prev, [key]: v }));
    setPage(1);
  };

  const setMinScore = (raw: string) => {
    const n = Number.parseInt(raw, 10);
    const v = Number.isFinite(n) && n > 0 ? n : undefined;
    setFilters((prev) => (prev.min_score === v ? prev : { ...prev, min_score: v }));
    setPage(1);
  };

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .kvAssets(KV_PAGE_SIZE, (page - 1) * KV_PAGE_SIZE, filters)
      .then((r) => {
        setAssets(r.items);
        setTotal(r.total);
      })
      .catch((e) => toast.error(`加载资产失败：${e.message}`))
      .finally(() => setLoading(false));
  }, [page, filters]);

  React.useEffect(() => {
    load();
  }, [load]);

  const runSync = async () => {
    setSyncing(true);
    setResult(null);
    try {
      const r = await api.kvSync({
        ...filters,
        import_domains: importDomains,
        max_assets: maxAssets > 0 ? maxAssets : undefined,
      });
      setResult(r);
      const totalSynced = Object.values(r.synced ?? {}).reduce((a, b) => a + b, 0);
      toast.success(`同步完成，共入库 ${totalSynced} 条资产`);
    } catch (e) {
      toast.error(`同步失败：${(e as Error).message}`);
    } finally {
      setSyncing(false);
    }
  };

  const renderRows = () => {
    if (loading) {
      return (
        <TableRow>
          <TableCell colSpan={7} className="py-8 text-center text-muted-foreground text-sm">
            加载中…
          </TableCell>
        </TableRow>
      );
    }
    if (assets.length === 0) {
      return (
        <TableRow>
          <TableCell colSpan={7} className="py-8 text-center text-muted-foreground text-sm">
            无数据
          </TableCell>
        </TableRow>
      );
    }
    return assets.map((a) => (
      <TableRow key={a.id}>
        <TableCell>
          <div className="font-medium font-mono">
            {a.scheme ? `${a.scheme}://` : ""}
            {a.ip}:{a.port}
          </div>
          {a.hostnames && a.hostnames.length > 0 && (
            <div className="max-w-64 truncate text-muted-foreground text-xs">
              {a.hostnames[0]}
              {a.hostnames.length > 1 ? ` +${a.hostnames.length - 1}` : ""}
            </div>
          )}
        </TableCell>
        <TableCell className="max-w-48 truncate">{a.title || "—"}</TableCell>
        <TableCell>
          {a.component ? (
            <div>
              <span className="font-mono text-sm">
                {a.component}
                {a.version ? `/${a.version}` : ""}
              </span>
              {a.php_version && <div className="text-muted-foreground text-xs">php/{a.php_version}</div>}
            </div>
          ) : (
            "—"
          )}
        </TableCell>
        <TableCell>{a.biz_type ? <Badge variant="secondary">{a.biz_type}</Badge> : "—"}</TableCell>
        <TableCell>
          {a.tier ? <Badge variant={a.tier === "A" ? "secondary" : "outline"}>{a.tier}</Badge> : "—"}
        </TableCell>
        <TableCell>
          <Badge
            variant={a.verdict === "executable" ? "secondary" : "outline"}
            className={a.verdict === "executable" ? "bg-emerald-600 hover:bg-emerald-600" : ""}
          >
            {kvVerdictLabel(a.verdict)}
          </Badge>
        </TableCell>
        <TableCell className="text-right font-mono">{a.score ?? "—"}</TableCell>
      </TableRow>
    ));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">按筛选条件同步</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* 入库选项 */}
        <div className="flex flex-wrap items-center gap-4">
          <label htmlFor="kv-import-domains" className="flex items-center gap-1.5 text-sm">
            <Checkbox id="kv-import-domains" checked={importDomains} onCheckedChange={(c) => setImportDomains(!!c)} />
            域名优先入库（hostnames 落成子域名资产）
          </label>
          <label htmlFor="kv-max-assets" className="flex items-center gap-1.5 text-sm">
            单次上限
            <Input
              id="kv-max-assets"
              type="number"
              min={1}
              max={50000}
              className="w-24"
              value={maxAssets}
              onChange={(e) => setMaxAssets(Number.parseInt(e.target.value, 10) || 0)}
            />
            条
          </label>
          <span className="text-muted-foreground text-xs">服务资产（HTTP / 端口）始终入库。</span>
        </div>

        {/* 筛选 */}
        <div className="flex flex-wrap items-center gap-2">
          <Select value={filters.tier ?? "all"} onValueChange={(v) => setFilter("tier", v === "all" ? undefined : v)}>
            <SelectTrigger size="sm" className="w-28">
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
          <Select
            value={filters.verdict ?? "all"}
            onValueChange={(v) => setFilter("verdict", v === "all" ? undefined : v)}
          >
            <SelectTrigger size="sm" className="w-36">
              <SelectValue placeholder="判定" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部判定</SelectItem>
              {KV_VERDICTS.map((v) => (
                <SelectItem key={v.value} value={v.value}>
                  {v.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select
            value={filters.engagement ?? "all"}
            onValueChange={(v) => setFilter("engagement", v === "all" ? undefined : v)}
          >
            <SelectTrigger size="sm" className="w-32">
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
          <Input
            className="w-40"
            placeholder="业务类型，如 盗U盘"
            defaultValue={filters.biz_type ?? ""}
            onKeyDown={(e) => {
              if (e.key === "Enter") setFilter("biz_type", e.currentTarget.value.trim());
            }}
          />
          <Input
            className="w-36"
            placeholder="组件，如 tomcat"
            defaultValue={filters.component ?? ""}
            onKeyDown={(e) => {
              if (e.key === "Enter") setFilter("component", e.currentTarget.value.trim());
            }}
          />
          <Input
            className="w-28"
            type="number"
            min={0}
            max={100}
            placeholder="分数 ≥"
            defaultValue={filters.min_score ?? ""}
            onKeyDown={(e) => {
              if (e.key === "Enter") setMinScore(e.currentTarget.value.trim());
            }}
          />
          <div className="relative w-56 flex-1">
            <SearchIcon className="absolute top-1/2 left-2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-8"
              placeholder="搜索标题 / 域名"
              defaultValue={filters.q ?? ""}
              onKeyDown={(e) => {
                if (e.key === "Enter") setFilter("q", e.currentTarget.value.trim());
              }}
            />
          </div>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} />
          </Button>
        </div>

        {/* 操作 */}
        <div className="flex items-center gap-2">
          <p className="text-muted-foreground text-xs">
            预览仅展示前 {KV_PAGE_SIZE} 条；同步会按相同筛选拉取全部匹配资产（价值分降序，受单次上限保护）。
          </p>
          <div className="flex-1" />
          <Button onClick={runSync} disabled={syncing}>
            <DownloadIcon className={syncing ? "size-4 animate-pulse" : "size-4"} /> 同步
          </Button>
        </div>

        {/* 列表 */}
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>目标</TableHead>
                <TableHead>标题</TableHead>
                <TableHead>组件</TableHead>
                <TableHead>业务类型</TableHead>
                <TableHead>等级</TableHead>
                <TableHead>判定</TableHead>
                <TableHead className="text-right">价值分</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>{renderRows()}</TableBody>
          </Table>
        </div>

        {/* 分页 */}
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1 || loading} onClick={() => setPage((p) => p - 1)}>
            上一页
          </Button>
          <span className="text-muted-foreground text-xs">
            第 {page} 页 · 共 {total} 条
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page * KV_PAGE_SIZE >= total || loading}
            onClick={() => setPage((p) => p + 1)}
          >
            下一页
          </Button>
        </div>

        {/* 结果 */}
        {result && <SyncResult result={result} />}
      </CardContent>
    </Card>
  );
}

function SyncResult({ result }: { result: SyncResultData }) {
  const synced = result.synced ?? {};
  const labels: Record<string, string> = {
    subdomain: "子域名",
    service: "服务",
    app: "App",
    ip: "IP",
    http_service: "HTTP 服务",
    other_service: "端口服务",
  };
  return (
    <div className="space-y-2 rounded-md border bg-muted/40 p-3 text-sm">
      <div className="flex flex-wrap gap-3">
        {Object.entries(synced).map(([k, v]) => (
          <Badge key={k} variant="secondary">
            {labels[k] ?? k}: {v}
          </Badge>
        ))}
      </div>
      {result.fetched != null && (
        <p className="text-muted-foreground">
          拉取 {result.fetched} 条{result.remote_total ? ` / 远端匹配 ${result.remote_total} 条` : ""}
          {result.truncated ? "（达到单次上限已截断）" : ""}
        </p>
      )}
      {result.companies && result.companies.length > 0 && (
        <p className="text-muted-foreground">新建/更新企业：{result.companies.join("、")}</p>
      )}
      {result.warnings && result.warnings.length > 0 && (
        <ul className="list-inside list-disc text-amber-600 dark:text-amber-500">
          {result.warnings.map((wm) => (
            <li key={wm}>{wm}</li>
          ))}
        </ul>
      )}
      {result.errors && result.errors.length > 0 && (
        <ul className="list-inside list-disc text-destructive">
          {result.errors.slice(0, 20).map((em) => (
            <li key={em}>{em}</li>
          ))}
          {result.errors.length > 20 && <li>…共 {result.errors.length} 条错误</li>}
        </ul>
      )}
    </div>
  );
}
