"use client";

// Kito 统一 AI 钱包（kt-k8s#194）：余额卡片 + 可用模型列表 + 充值弹窗。
// 后端透传 ktapi.cc（NewAPI IAM），用户 identity 令牌从登录态取（X-Identity-Token）。
// 充值纪律（对齐 kt-opencode kito-wallet skill）：打开充值、选定网络时才取地址，
// 不在进页/登录时预创建；地址页面上只显示前 6 后 6，完整地址仅通过复制按钮给出。
import * as React from "react";
import QRCode from "qrcode";
import { toast } from "sonner";
import { auth } from "@/lib/auth";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Copy, QrCode, RefreshCw, Wallet } from "lucide-react";

interface WalletAccount {
  id: number;
  username: string;
  displayName: string;
}

interface DepositAddress {
  chain: string;
  asset: string;
  address: string;
}

const CHAIN_OPTIONS = [
  { value: "tron", label: "TRON（TRC20）— USDT" },
  { value: "ethereum", label: "Ethereum（ERC20）— USDT / USDC" },
];

const ASSET_OPTIONS = [
  { value: "usdt", label: "USDT" },
  { value: "usdc", label: "USDC", chains: ["ethereum"] },
];

async function walletHttp<T>(path: string, init?: RequestInit): Promise<T> {
  const identity = auth.getIdentityToken();
  if (!identity) throw new Error("缺少 identity 令牌，请重新通过 KT Identity 登录");
  const token = auth.getToken();
  const r = await fetch(`/api/wallet${path}`, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      "X-Identity-Token": identity,
      ...(init?.headers as Record<string, string> | undefined),
    },
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    throw new Error(body.message || body.error || `请求失败（${r.status}）`);
  }
  return body as T;
}

function maskAddress(address: string): string {
  if (address.length <= 12) return address;
  return `${address.slice(0, 6)}…${address.slice(-6)}（${address.length} 位）`;
}

export default function WalletPage() {
  const [balance, setBalance] = React.useState<number | null>(null);
  const [account, setAccount] = React.useState<WalletAccount | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState("");
  const [models, setModels] = React.useState<{ id: string }[]>([]);
  const [modelsLoading, setModelsLoading] = React.useState(false);

  const [rechargeOpen, setRechargeOpen] = React.useState(false);
  const [chain, setChain] = React.useState("");
  const [asset, setAsset] = React.useState("usdt");
  const [deposit, setDeposit] = React.useState<DepositAddress | null>(null);
  const [depositLoading, setDepositLoading] = React.useState(false);
  const [qrDataUrl, setQrDataUrl] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    setErr("");
    try {
      const body = await walletHttp<{ account: WalletAccount; balance?: number }>("/ensure", { method: "POST" });
      setAccount(body.account ?? null);
      setBalance(typeof body.balance === "number" ? body.balance : null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadModels = React.useCallback(async () => {
    setModelsLoading(true);
    try {
      const body = await walletHttp<{ models: { id: string }[] }>("/models");
      setModels(body.models ?? []);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "模型列表加载失败");
    } finally {
      setModelsLoading(false);
    }
  }, []);

  React.useEffect(() => { void load(); }, [load]);
  React.useEffect(() => { void loadModels(); }, [loadModels]);

  // 充值地址只在弹窗打开且选定网络后才取（登录/进页不预创建）。
  const fetchDeposit = React.useCallback(async (chainValue: string, assetValue: string) => {
    if (!chainValue) return;
    setDepositLoading(true);
    setDeposit(null);
    setQrDataUrl("");
    try {
      const body = await walletHttp<DepositAddress>(
        `/deposit-address?chain=${encodeURIComponent(chainValue)}&asset=${encodeURIComponent(assetValue)}`,
      );
      setDeposit(body);
      setQrDataUrl(await QRCode.toDataURL(body.address, { margin: 1, width: 220 }));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "充值地址获取失败");
    } finally {
      setDepositLoading(false);
    }
  }, []);

  const onChainChange = (value: string) => {
    setChain(value);
    const nextAsset = value === "tron" ? "usdt" : asset === "usdt" || value === "ethereum" ? asset : "usdt";
    setAsset(nextAsset);
    void fetchDeposit(value, nextAsset);
  };

  const onAssetChange = (value: string) => {
    setAsset(value);
    void fetchDeposit(chain, value);
  };

  const copyAddress = async () => {
    if (!deposit) return;
    try {
      await navigator.clipboard.writeText(deposit.address);
      toast.success("充值地址已复制");
    } catch {
      toast.error("复制失败，请手动复制");
    }
  };

  const assetOptions = ASSET_OPTIONS.filter((o) => !o.chains || o.chains.includes(chain));

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">AI 钱包</h1>
        <p className="text-sm text-muted-foreground">
          Kito 统一 AI 账户（ktapi.cc）：余额与可用模型按你的 KT Identity 账号实时查询。
        </p>
      </div>

      {err ? (
        <Card>
          <CardContent className="pt-6 text-sm text-destructive">{err}</CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Wallet className="size-4" /> 余额
            </CardTitle>
            <CardDescription>
              {account?.displayName || account?.username || "当前登录账号"} 的共享 AI 余额（USD）
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" disabled={loading} onClick={() => { void load(); void loadModels(); }}>
            {loading ? <Spinner className="size-4" /> : <RefreshCw className="size-4" />} 刷新
          </Button>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-4">
          <div className="text-3xl font-semibold tabular-nums">
            {loading ? <Spinner className="size-6" /> : balance === null ? "—" : `$${balance.toFixed(2)}`}
          </div>
          <Button onClick={() => setRechargeOpen(true)}>
            <QrCode className="size-4" /> 充值
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">可用模型（{models.length}）</CardTitle>
          <CardDescription>当前账号在 ktapi.cc 可调用的模型列表。</CardDescription>
        </CardHeader>
        <CardContent>
          {modelsLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground"><Spinner className="size-4" /> 加载中…</div>
          ) : models.length === 0 ? (
            <div className="text-sm text-muted-foreground">暂无可用模型</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="py-2 font-medium">模型 ID</th>
                </tr>
              </thead>
              <tbody>
                {models.map((m) => (
                  <tr key={m.id} className="border-b last:border-0">
                    <td className="py-2 font-mono text-xs">{m.id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      <Dialog open={rechargeOpen} onOpenChange={(open) => { setRechargeOpen(open); if (!open) { setDeposit(null); setQrDataUrl(""); } }}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-md">
          <DialogHeader>
            <DialogTitle>充值</DialogTitle>
            <DialogDescription>选择网络后生成专属充值地址；请只向该地址转入所选网络的币种。</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid gap-2">
              <span className="text-sm font-medium">网络</span>
              <Select value={chain} onValueChange={onChainChange}>
                <SelectTrigger><SelectValue placeholder="选择网络" /></SelectTrigger>
                <SelectContent>
                  {CHAIN_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {chain ? (
              <div className="grid gap-2">
                <span className="text-sm font-medium">币种</span>
                <Select value={asset} onValueChange={onAssetChange}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {assetOptions.map((o) => (
                      <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            ) : null}
            {depositLoading ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground"><Spinner className="size-4" /> 正在获取充值地址…</div>
            ) : deposit && qrDataUrl ? (
              <div className="space-y-3">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={qrDataUrl} alt="充值地址二维码" className="mx-auto rounded border" width={220} height={220} />
                <div className="break-all text-center font-mono text-xs text-muted-foreground">
                  {maskAddress(deposit.address)}
                </div>
                <Button className="w-full" variant="outline" onClick={copyAddress}>
                  <Copy className="size-4" /> 复制完整地址
                </Button>
                <p className="text-xs text-muted-foreground">
                  {deposit.chain === "tron" ? "TRC20 仅支持 USDT，请核对地址以 T 开头。" : "ERC20 的 USDT 与 USDC 共用同一条地址，请核对地址以 0x 开头。"}
                </p>
              </div>
            ) : chain ? (
              <div className="text-sm text-muted-foreground">选择网络后展示地址。</div>
            ) : null}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
