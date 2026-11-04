"use client";

import Link from "next/link";

import { Button } from "@/components/ui/button";

// 统一 404：不回显框架默认文案，也不暴露内部路由结构（issue #61 A4）。
export default function NotFound() {
  return (
    <div className="flex h-dvh flex-col items-center justify-center gap-3 text-center">
      <p className="font-mono text-muted-foreground text-xs">404</p>
      <h1 className="font-semibold text-xl">页面不存在</h1>
      <p className="text-muted-foreground max-w-sm text-sm">
        链接可能已失效，或者你没有该页面的访问权限。可以返回工作台继续操作。
      </p>
      <Button asChild variant="outline" size="sm">
        <Link href="/function/tasks" prefetch={false}>
          返回工作台
        </Link>
      </Button>
    </div>
  );
}
