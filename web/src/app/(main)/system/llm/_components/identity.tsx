"use client";

import * as React from "react";

import { ArrowLeftIcon, KeyRoundIcon, Loader2Icon, PencilIcon, PlusIcon, SaveIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { api } from "@/lib/api";
import type { LLMIdentity } from "@/lib/types";

const DEFAULT_TOKEN_URL = "https://auth.ktyun.cc/api/login/oauth/access_token";

function IdentityForm({
  identity,
  onCancel,
  onSaved,
}: {
  identity: LLMIdentity | null;
  onCancel: () => void;
  onSaved: () => Promise<void>;
}) {
  const [name, setName] = React.useState(identity?.name ?? "");
  const [tokenURL, setTokenURL] = React.useState(identity?.token_url ?? DEFAULT_TOKEN_URL);
  const [clientID, setClientID] = React.useState(identity?.client_id ?? "");
  const [clientSecret, setClientSecret] = React.useState("");
  const [scope, setScope] = React.useState(identity?.scope ?? "newapi.relay");
  const [managedTokenName, setManagedTokenName] = React.useState(identity?.managed_token_name ?? "artex");
  const [saving, setSaving] = React.useState(false);

  async function save() {
    if (!name.trim() || !tokenURL.trim() || !clientID.trim() || !managedTokenName.trim()) {
      toast.error("请填写名称、Token URL、Client ID 和 Managed Token Name");
      return;
    }
    if (!identity && !clientSecret) {
      toast.error("新建身份必须填写 Client Secret");
      return;
    }
    if (!tokenURL.trim().startsWith("https://")) {
      toast.error("Token URL 必须是 https:// 端点");
      return;
    }
    if (saving) return;
    setSaving(true);
    try {
      await api.saveLLMIdentity({
        ...(identity ? { id: identity.id } : {}),
        name: name.trim(),
        token_url: tokenURL.trim(),
        client_id: clientID.trim(),
        client_secret: clientSecret,
        scope: scope.trim(),
        managed_token_name: managedTokenName.trim(),
      });
      toast.success(identity ? "身份已更新" : "身份已创建");
      await onSaved();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
        <Button variant="ghost" size="sm" className="w-fit px-0" onClick={onCancel}>
          <ArrowLeftIcon /> 返回身份列表
        </Button>
        <div className="rounded-lg border border-dashed p-3 text-muted-foreground text-xs leading-relaxed">
          这里保存的是 KT 机器身份凭据，不是模型 API Key。ARTEX 只在内存中换短时身份 token；删除 relay scope
          或禁用影子用户即断供。
        </div>
        <div className="grid gap-2">
          <Label htmlFor="identity-name">名称</Label>
          <Input
            id="identity-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="例如：ARTEX 生产"
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="identity-token-url">Token URL</Label>
          <Input
            id="identity-token-url"
            className="font-mono"
            value={tokenURL}
            onChange={(e) => setTokenURL(e.target.value)}
            placeholder={DEFAULT_TOKEN_URL}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="identity-client-id">Client ID</Label>
          <Input
            id="identity-client-id"
            className="font-mono"
            autoComplete="off"
            value={clientID}
            onChange={(e) => setClientID(e.target.value)}
            placeholder="artex"
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="identity-client-secret">Client Secret</Label>
          <Input
            id="identity-client-secret"
            type="password"
            autoComplete="new-password"
            value={clientSecret}
            onChange={(e) => setClientSecret(e.target.value)}
            placeholder={
              identity?.client_secret_hint ? `已设置（${identity.client_secret_hint}），留空保持不变` : "新建时必填"
            }
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="identity-scope">Scope（可选）</Label>
          <Input
            id="identity-scope"
            className="font-mono"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder="newapi.relay"
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="identity-managed-name">Managed Token Name</Label>
          <Input
            id="identity-managed-name"
            className="font-mono"
            value={managedTokenName}
            onChange={(e) => setManagedTokenName(e.target.value)}
            placeholder="artex"
          />
          <p className="text-muted-foreground text-xs">对应 NewAPI 的 X-Kito-Token-Name；ARTEX 部署固定使用 artex。</p>
        </div>
      </div>
      <div className="flex gap-2 border-t px-4 py-3">
        <Button variant="outline" onClick={onCancel} disabled={saving}>
          取消
        </Button>
        <Button className="flex-1" onClick={() => void save()} disabled={saving}>
          {saving && <Loader2Icon className="animate-spin" />}
          {!saving && (identity ? <SaveIcon /> : <PlusIcon />)}
          {identity ? "保存" : "新建身份"}
        </Button>
      </div>
    </>
  );
}

export function IdentitySheet({
  open,
  onOpenChange,
  identities,
  onChanged,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  identities: LLMIdentity[];
  onChanged: () => Promise<void>;
}) {
  // undefined=列表；null=新建；对象=编辑。关闭再打开始终回到列表。
  const [editing, setEditing] = React.useState<LLMIdentity | null | undefined>(undefined);
  const [deleteTarget, setDeleteTarget] = React.useState<LLMIdentity | null>(null);
  const [deleting, setDeleting] = React.useState(false);

  React.useEffect(() => {
    if (open) setEditing(undefined);
  }, [open]);

  async function remove() {
    if (!deleteTarget || deleting) return;
    setDeleting(true);
    try {
      await api.deleteLLMIdentity(deleteTarget.id);
      toast.success(`已删除身份：${deleteTarget.name}`);
      setDeleteTarget(null);
      await onChanged();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    } finally {
      setDeleting(false);
    }
  }

  let description = "新建机器身份";
  if (editing === undefined) {
    description = "多个模型配置可共用同一身份；Client Secret 只写入一次，之后仅显示尾 4 位。";
  } else if (editing) {
    description = `编辑：${editing.name}`;
  }

  return (
    <>
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent
          side="right"
          className="flex flex-col gap-0 p-0 data-[side=right]:min-w-[420px] data-[side=right]:sm:max-w-xl"
        >
          <SheetHeader className="px-4">
            <SheetTitle className="flex items-center gap-2">
              <KeyRoundIcon className="size-4" /> KT 身份
            </SheetTitle>
            <SheetDescription>{description}</SheetDescription>
          </SheetHeader>

          {editing !== undefined ? (
            <IdentityForm
              key={editing?.id ?? "new"}
              identity={editing}
              onCancel={() => setEditing(undefined)}
              onSaved={async () => {
                await onChanged();
                setEditing(undefined);
              }}
            />
          ) : (
            <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-4 pb-4">
              <Button variant="outline" onClick={() => setEditing(null)}>
                <PlusIcon /> 新建身份
              </Button>
              {identities.map((identity) => (
                <div key={identity.id} className="grid gap-3 rounded-lg border p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-sm">{identity.name}</span>
                        <Badge variant="outline">{identity.managed_token_name}</Badge>
                      </div>
                      <code className="mt-1 block truncate font-mono text-muted-foreground text-xs">
                        {identity.client_id}
                      </code>
                      <p className="mt-1 break-all font-mono text-muted-foreground text-xs">{identity.token_url}</p>
                    </div>
                    <div className="flex shrink-0 gap-1">
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`编辑身份 ${identity.name}`}
                        onClick={() => setEditing(identity)}
                      >
                        <PencilIcon />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`删除身份 ${identity.name}`}
                        onClick={() => setDeleteTarget(identity)}
                      >
                        <Trash2Icon className="text-destructive" />
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-x-3 text-muted-foreground text-xs">
                    <span>Secret {identity.client_secret_hint || "已配置"}</span>
                    {identity.scope && <span>Scope {identity.scope}</span>}
                  </div>
                </div>
              ))}
              {identities.length === 0 && (
                <div className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
                  还没有 KT 身份。新建后，在模型配置里把认证方式改为「KT 身份直连」。
                </div>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>

      <AlertDialog open={deleteTarget !== null} onOpenChange={(next) => !next && !deleting && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除身份「{deleteTarget?.name}」？</AlertDialogTitle>
            <AlertDialogDescription>
              仍被模型配置引用的身份不能删除。删除本机身份记录不会吊销 Casdoor 应用。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={deleting} onClick={() => void remove()}>
              {deleting ? <Loader2Icon className="animate-spin" /> : <Trash2Icon />}
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
