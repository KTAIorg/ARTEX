"use client";

// 左上角余额徽章：进站时 ensure 一次 ktapi 账号，常显余额（点击进钱包页）。
// 无 identity 令牌（账密登录）或上游失败时整体隐藏——不给用户看无意义的错误。
import * as React from "react";
import Link from "next/link";
import { auth } from "@/lib/auth";
import { Wallet } from "lucide-react";

export function SidebarWalletBadge() {
  const [balance, setBalance] = React.useState<number | null>(null);
  const [show, setShow] = React.useState(false);

  React.useEffect(() => {
    const identity = auth.getIdentityToken();
    if (!identity) return;
    const token = auth.getToken();
    let cancelled = false;
    fetch("/api/wallet/ensure", {
      method: "POST",
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        "X-Identity-Token": identity,
      },
    })
      .then(async (r) => {
        if (!r.ok) return;
        const body = await r.json().catch(() => ({}));
        if (!cancelled) {
          setBalance(typeof body.balance === "number" ? body.balance : 0);
          setShow(true);
        }
      })
      .catch(() => {
        // ensure 失败也显示入口（文案退化为「钱包」），详情进钱包页看
        if (!cancelled) setShow(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!show) return null;
  return (
    <Link
      prefetch={false}
      href="/system/wallet"
      className="text-muted-foreground hover:bg-accent hover:text-accent-foreground ml-auto flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs tabular-nums"
      title="KT AI 钱包余额，点击进入钱包页"
    >
      <Wallet className="size-3" />
      {balance === null ? "钱包" : `$${balance.toFixed(2)}`}
    </Link>
  );
}
