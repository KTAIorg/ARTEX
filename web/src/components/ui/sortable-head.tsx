"use client";

import { ArrowDownIcon, ArrowUpDownIcon, ArrowUpIcon } from "lucide-react";
import type * as React from "react";

import { TableHead } from "@/components/ui/table";
import { sortArrowV2Enabled } from "@/lib/feature-flags";
import type { SortDirection } from "@/lib/sort-preference";
import { cn } from "@/lib/utils";

// SortableHead is a table header cell that toggles a column's sort on click.
//
// 两套箭头样式，由灰度开关 NEXT_PUBLIC_SORT_ARROW_V2_PERCENT 控制：
//   v1（默认，未放量）：lucide 单箭头 + 未激活时的 ArrowUpDown 图标，沿用旧观感
//   v2（灰度中）：双三角 caret，激活方向高亮、另一方向压暗；未激活时两个三角同色弱化
// 灰度按账号稳定分桶（见 lib/feature-flags），同一账号刷新不会来回闪。
export function SortableHead<Field extends string>({
  field,
  label,
  activeField,
  direction,
  align = "left",
  className,
  onSort,
}: {
  field: Field;
  label: string;
  activeField: Field | null;
  direction: SortDirection;
  align?: "left" | "right";
  className?: string;
  onSort: (field: Field) => void;
}) {
  const active = activeField === field;
  const v2 = sortArrowV2Enabled();

  let ariaSort: React.AriaAttributes["aria-sort"] = "none";
  if (active) ariaSort = direction === "asc" ? "ascending" : "descending";

  let actionLabel = `按${label}倒序排序`;
  if (active) actionLabel = `${label}当前${direction === "asc" ? "正序" : "倒序"}，点击切换排序方向`;

  let icon: React.ReactNode = (
    <ArrowUpDownIcon className="size-3.5 opacity-40 transition-opacity group-hover/sort:opacity-100" />
  );
  if (active) {
    icon = direction === "asc" ? <ArrowUpIcon className="size-3.5" /> : <ArrowDownIcon className="size-3.5" />;
  }
  if (v2) icon = <SortCaret active={active} direction={direction} />;

  return (
    <TableHead className={className} aria-sort={ariaSort}>
      <button
        type="button"
        className={cn(
          "group/sort inline-flex h-full w-full items-center justify-between gap-2 outline-none focus-visible:underline",
          align === "right" && "justify-end",
        )}
        aria-label={actionLabel}
        onClick={() => onSort(field)}
        data-sort-icon={v2 ? "v2" : "v1"}
      >
        <span>{label}</span>
        {icon}
      </button>
    </TableHead>
  );
}

/**
 * 双三角排序指示器（v2）。
 *
 * 视觉规则：
 *   · 未排序列：上下两个三角都弱化（35%），悬停升到 70% —— 提示"可点"，但不抢视线
 *   · 已排序列：命中方向 100% + 前景色，另一方向 15% —— 一眼看出当前方向
 * 尺寸 8×5，两个三角间隔 2px，整体与文字居中对齐。
 */
function SortCaret({ active, direction }: { active: boolean; direction: SortDirection }) {
  const upOn = active && direction === "asc";
  const downOn = active && direction === "desc";
  // 配色对齐 KtPay 参考图：命中方向用品牌蓝，未命中方向用中性灰；
  // 未排序列两个都灰，悬停时略微加深提示「可点」。
  const blue = "text-[#1677ff]";
  const grey = "text-muted-foreground/45 group-hover/sort:text-muted-foreground/75";
  const dim = "text-muted-foreground/20";

  return (
    <span className="inline-flex shrink-0 flex-col items-center justify-center gap-[3px]" aria-hidden="true">
      <svg
        width="9"
        height="6"
        viewBox="0 0 9 6"
        className={cn("transition-colors", active ? (upOn ? blue : dim) : grey)}
      >
        <path d="M4.5 0 9 6H0z" fill="currentColor" />
      </svg>
      <svg
        width="9"
        height="6"
        viewBox="0 0 9 6"
        className={cn("transition-colors", active ? (downOn ? blue : dim) : grey)}
      >
        <path d="M4.5 6 0 0h9z" fill="currentColor" />
      </svg>
    </span>
  );
}
