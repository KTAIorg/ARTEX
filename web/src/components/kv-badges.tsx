"use client";

// kt-vuln 协同维度徽章与快捷筛选（assets.extra.ktvuln，随同步写入）。
// 本地资产页「服务」tab 与 Vuln 情报站面板共用，抽到这里避免两份拷贝。

import * as React from "react";

import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";

export const KV_TIERS = ["A", "B", "C", "D", "E"];
export const KV_ENGAGEMENTS: { value: string; label: string }[] = [
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
export const KV_TIER_TONE: Record<string, { variant: "default" | "secondary"; cls: string }> = {
  A: { variant: "default", cls: "bg-rose-600 hover:bg-rose-600" },
  B: { variant: "default", cls: "bg-amber-500 hover:bg-amber-500" },
  C: { variant: "secondary", cls: "bg-slate-200 text-slate-700" },
  D: { variant: "secondary", cls: "bg-zinc-200 text-zinc-700" },
  E: { variant: "secondary", cls: "bg-stone-200 text-stone-700" },
};

export function KVValueBadge({ tier, score }: { tier?: string; score?: number }) {
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
export const KV_ENGAGEMENT_TONE: Record<string, string> = {
  todo: "bg-slate-100 text-slate-600",
  claimed: "bg-blue-100 text-blue-700",
  in_progress: "bg-amber-100 text-amber-700",
  done_hit: "bg-emerald-100 text-emerald-700",
  done_miss: "bg-emerald-100 text-emerald-700",
};

// 判定（verdict）中文与配色：可确认=红、疑似漏洞=橙、已修复=绿、不适用=灰、未知=金。
export const KV_VERDICT_LABEL: Record<string, string> = {
  executable: "可确认",
  vulnerable: "疑似漏洞",
  patched: "已修复",
  not_applicable: "不适用",
  unknown: "未知",
};
export const KV_VERDICT_TONE: Record<string, string> = {
  executable: "bg-red-600 hover:bg-red-600",
  vulnerable: "bg-orange-100 text-orange-700",
  patched: "bg-emerald-100 text-emerald-700",
  not_applicable: "bg-slate-100 text-slate-600",
  unknown: "bg-yellow-100 text-yellow-700",
};

export function KVEngagementBadge({ status }: { status: string }) {
  const tone = KV_ENGAGEMENT_TONE[status];
  const label = KV_ENGAGEMENTS.find((v) => v.value === status)?.label ?? status;
  return (
    <Badge variant={tone ? "secondary" : "outline"} className={cn("text-[10px]", tone)}>
      {label}
    </Badge>
  );
}

export function KVVerdictBadge({ verdict }: { verdict: string }) {
  const tone = KV_VERDICT_TONE[verdict];
  return (
    <Badge variant={tone ? "secondary" : "outline"} className={cn("text-[10px]", tone)}>
      {KV_VERDICT_LABEL[verdict] ?? verdict}
    </Badge>
  );
}

// DSL 值没有转义语法（readToken 的引号即边界）：去掉值里的引号，含空白/括号时整体加引号。
export function kvDslValue(v: string): string {
  const clean = v.replaceAll('"', "");
  return /[\s()]/.test(clean) ? `"${clean}"` : clean;
}

// 服务 tab 的 kt-vuln 快捷筛选：条件拼成 kv_* DSL 填进上方 DSL 搜索框并触发查询。
export function KVQuickFilter({ onApply }: { onApply: (dsl: string) => void }) {
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
