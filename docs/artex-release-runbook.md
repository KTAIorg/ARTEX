# ARTEX 分阶段发布与回滚运行手册

最后验证：2026-11-07。适用仓库：`kt-security/ARTEX`。

## 发布信任链

1. `CD · Production` 仅由 `main` push 触发，在 `production` environment 审批后构建一次 linux/amd64 镜像，以 digest 部署 `artex-main`。
2. 主站 `/api/health` 必须通过私有 CA 的 HTTPS 校验，且完整 `version` 等于 merge SHA；通过后才创建 `artex-main-receipt-<run_id>-<attempt>-<sha>`。
3. `CD · Partner Production` 必须输入主站成功 run ID。workflow 同时校验 run、attempt、artifact ZIP SHA256、receipt commit/digest 和 registry manifest/config/revision。任何不一致都会停止，包括“同 commit、不同 digest”。
4. Partner 使用 `production-partner` environment，registry 只有 pull 权限；主站健康仍在晋级前复查，Partner 健康成功后才上传 Partner receipt。
5. 生产健康检查禁止 HTTP、系统 CA 回退和一切重定向。仅 CI 的 embedded binary smoke 可显式使用 `--allow-http-loopback`。

## 主站晋级 Partner

在 Actions 打开 `CD · Partner Production`，分支选择 `main`，填写：

- `source_run_id`：已成功验收目标主站版本的 `CD · Production` run ID。
- `source_run_attempt`：通常留空；同一 run 有多个成功 receipt attempt 时必须填写，避免歧义。
- `source_commit`：该 run 的完整 40 位 merge SHA。
- `image`：该 run 摘要中的 `oci.ktyun.cc/ktaiorg/artex@sha256:<digest>`，或与 commit 对应的 `prod-sha-<short10>` tag。

不要只凭 commit 或当前主站健康状态晋级。run 失败、artifact 过期、artifact digest 改变、receipt 与 registry 不一致时，应重新定位正确制品，不能绕过绑定。

## 受控回滚

在 Actions 打开 `Rollback · Production`，必须从 `main` 分支运行。目标决定审批环境：`artex-main` 使用 `production`，`artex-partner` 使用 `production-partner`。所有变更 workflow 共用 `artex-production` concurrency。

填写：

- `target`：只回滚一个目标，不提供双站同时操作。
- `receipt_run_id`：主站回滚填历史成功 `CD · Production` run；Partner 回滚填历史成功 `CD · Partner Production` run。
- `receipt_run_attempt`：有多个成功 attempt 时填写。
- `source_commit`：历史 receipt 的完整 merge SHA，且必须仍是 `main` 祖先。
- `image`：历史 receipt 对应的 tag 或 digest。
- `reason`：事故、变更或回滚原因，写入 rollback receipt。

workflow 不构建镜像，只获取 registry pull token。它先绑定历史成功 receipt，再将 webhook 镜像固定为 receipt 的 `image_ref`，收到 202 后检查目标 HTTPS 健康版本。健康成功后才上传 `artex-rollback-receipt-<rollback_run_id>-<attempt>-<sha>`，其中记录操作者、原因和来源 receipt run。

健康失败表示回滚未验收，不得手工标记成功。应保留失败 run 日志并沿同一 receipt 路径重试，或选择另一张已验证 receipt。当前实现不宣称 webhook 失败后的接收端自动恢复。

2026-11-07 前旧版本 `dev` 的 digest `sha256:7428a591a03318dd287f8b7eb20541f2144373c16ef9b7098fdc5e8d713f5d0a` 没有新格式历史 receipt，只能作为 break-glass 人工恢复线索，不能填入新 rollback workflow 绕过 receipt 门。

## HTTPS 健康入口与恢复点

本次只新增反代，不修改 ARTEX 容器，不移除原 HTTP 业务端口：

- 主站：`https://69.194.14.91:52914/api/health` → `127.0.0.1:52913`。
- Partner：`https://104.225.156.8:48173/api/health` → `127.0.0.1:48172`。
- 两个 Nginx 都只代理精确 `/api/health`，其它路径返回 404，TLS 只允许 1.2/1.3。
- 私有 CA SHA256 指纹：`51:48:23:F8:A4:70:AB:00:4C:50:C7:54:4F:DC:94:C2:4A:CE:E3:AD:05:36:A8:CA:DE:83:27:A8:A8:D1:50:3B`。
- Partner 私钥在 Partner 本机生成，CSR 由主站 CA 签名；CA 私钥只在主站临时目录使用并已清理。
- Partner 私钥已登记 KTSecret：`kt/kt/prod`，path `/16clouds/us-la-main/cd/`，key `CD_TLS_PARTNER_SERVER_PRIVATE_KEY`，active version 1。
- GitHub `CD_TLS_CA` secret 用于生产 webhook 和健康校验；`CD_HEALTH_CA_PUBLIC` variable 只用于 PR CI 的只读连通性探针。

原配置备份目录均为 `0700`：

- 主站：`/root/artex-release-backups/20261107T035209Z-health-tls`，含 `/etc/nginx`、`/etc/nftables.conf` 和 runtime nftables。
- Partner：`/root/artex-release-backups/20261107T035217Z-health-tls`，含安装前包清单、service 状态和 runtime nftables。

### 主站健康入口回滚

在主站以 root 执行；先确认没有其它变更依赖 `52914`：

```bash
rm /etc/nginx/sites-enabled/artex-health-tls
rm /etc/nginx/sites-available/artex-health-tls
cp -a /root/artex-release-backups/20261107T035209Z-health-tls/nftables.conf /etc/nftables.conf
nft -c -f /etc/nftables.conf
nft -a list chain inet ktfirewall input
# 找到 tcp dport 52914 对应 handle 后，以其真实编号替换 <handle>。
nft delete rule inet ktfirewall input handle <handle>
nginx -t && systemctl reload nginx
curl --fail http://127.0.0.1:52913/api/health
```

### Partner 健康入口回滚

在 Partner 以 root 执行：

```bash
systemctl disable --now nginx
rm /etc/nginx/sites-enabled/artex-health-tls
rm /etc/nginx/sites-available/artex-health-tls
rm -rf /etc/artex-health-tls
apt-get purge -y nginx nginx-common
curl --fail http://127.0.0.1:48172/api/health
```

这些恢复操作只撤销本次新增 TLS 入口，不重启或替换 ARTEX。KTSecret 中已登记的 Partner 私钥应按凭据保留策略另行 revoke，不能随目录删除而误认为平台记录自动消失。
