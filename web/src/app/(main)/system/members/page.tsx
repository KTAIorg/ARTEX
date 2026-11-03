"use client";

// 站点成员与角色管理（identity 委派，workspace=artex）。
// 登录者为 artex ADMIN 时可用：填同事的 KT 账号编号授 VIEWER/OPERATOR/ADMIN，
// 点角色标签撤销；最后一个 ADMIN 的撤销、跨域操作由 identity 侧拦截。
import * as React from "react";
import { toast } from "sonner";
import { auth } from "@/lib/auth";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { UserPlus } from "lucide-react";

interface Member {
  accountId: string;
  accountNo: string;
  displayName: string;
  roleKey: string;
  dataScope: string;
}

const ROLE_OPTIONS = [
  { value: "VIEWER", label: "VIEWER — 只读" },
  { value: "OPERATOR", label: "OPERATOR — 建任务 / 读写资产" },
  { value: "ADMIN", label: "ADMIN — 站点管理员" },
];

async function membersHttp<T>(path: string, init?: RequestInit): Promise<T> {
  const identity = auth.getIdentityToken();
  if (!identity) throw new Error("缺少 identity 令牌，请重新通过 KT Identity 登录");
  const token = auth.getToken();
  const r = await fetch(`/api/admin/members${path}`, {
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

export default function MembersPage() {
  const [members, setMembers] = React.useState<Member[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState("");
  const [accountNo, setAccountNo] = React.useState("");
  const [role, setRole] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    setErr("");
    try {
      const body = await membersHttp<{ members: Member[] }>("");
      setMembers(body.members ?? []);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => { void load(); }, [load]);

  const grant = async () => {
    const no = accountNo.trim().toUpperCase();
    if (!/^KT[0-9A-Z]{6,}$/.test(no)) {
      toast.error("请输入完整的 KT 账号编号（例如 KT260829GUSXV3QY4I6NA）");
      return;
    }
    if (!role) {
      toast.error("请选择角色");
      return;
    }
    setBusy(true);
    try {
      await membersHttp("/assign", {
        method: "POST",
        body: JSON.stringify({ accountNo: no, roleKey: role, workspace: "artex", reason: "ARTEX 站点管理员委派" }),
      });
      toast.success(`已授 ${no} → ${role}`);
      setAccountNo("");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "授权失败");
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (m: Member) => {
    if (!window.confirm(`撤销 ${m.accountNo} 的 ${m.roleKey}？`)) return;
    try {
      await membersHttp("/revoke", {
        method: "POST",
        body: JSON.stringify({ accountNo: m.accountNo, roleKey: m.roleKey, workspace: "artex", reason: "ARTEX 站点管理员撤销" }),
      });
      toast.success(`已撤销 ${m.accountNo} 的 ${m.roleKey}`);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "撤销失败");
    }
  };

  // 按账号聚合角色
  const rows = React.useMemo(() => {
    const by = new Map<string, { accountNo: string; displayName: string; roles: Member[] }>();
    for (const m of members) {
      const cur = by.get(m.accountId) ?? { accountNo: m.accountNo, displayName: m.displayName || "—", roles: [] };
      cur.roles.push(m);
      by.set(m.accountId, cur);
    }
    return Array.from(by.values());
  }, [members]);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">成员与角色</h1>
        <p className="text-sm text-muted-foreground">
          站点成员由 KT Identity 统一管理；你是本站 ADMIN，可自助邀请与撤销（即时生效）。
        </p>
      </div>

      {err ? (
        <Card>
          <CardContent className="pt-6 text-sm text-destructive">{err}</CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">邀请成员</CardTitle>
          <CardDescription>
            对方需先在任一站点用 Telegram 登录一次拿到 KT 账号编号；ADMIN 数量为 1 时不可撤销最后一个。
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-2">
          <Input
            className="w-72"
            placeholder="KT 账号编号，例如 KT260829GUSXV3QY4I6NA"
            value={accountNo}
            onChange={(e) => setAccountNo(e.target.value.toUpperCase().trim())}
          />
          <Select value={role} onValueChange={setRole}>
            <SelectTrigger className="w-64"><SelectValue placeholder="选择角色" /></SelectTrigger>
            <SelectContent>
              {ROLE_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button disabled={busy || !accountNo || !role} onClick={grant}>
            {busy ? <Spinner className="size-4" /> : <UserPlus className="size-4" />} 授权
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">当前成员（{rows.length} 人）</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground"><Spinner className="size-4" /> 加载中…</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="py-2 font-medium">账号编号</th>
                  <th className="py-2 font-medium">显示名</th>
                  <th className="py-2 font-medium">角色</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.accountNo} className="border-b last:border-0">
                    <td className="py-2 font-mono text-xs">{r.accountNo}</td>
                    <td className="py-2">{r.displayName}</td>
                    <td className="py-2">
                      <div className="flex flex-wrap gap-1">
                        {r.roles.map((m) => (
                          <button
                            key={m.roleKey}
                            title="点击撤销"
                            onClick={() => revoke(m)}
                            className={`rounded px-2 py-0.5 text-xs ${
                              m.roleKey === "ADMIN"
                                ? "bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-200"
                                : m.roleKey === "OPERATOR"
                                  ? "bg-blue-100 text-blue-900 dark:bg-blue-900/40 dark:text-blue-200"
                                  : "bg-muted text-muted-foreground"
                            }`}
                          >
                            {m.roleKey} ✕
                          </button>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
