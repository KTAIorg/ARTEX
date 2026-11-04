# ARTEX 灰度发布运行手册（搬瓦工 VPS 形态）

> 目标：新版本先给 KT Identity 内部用户体验（beta 实例），验证调整后再动生产实例，
> 全程不影响线上其他部署。对应 CI 改动：`.forgejo/publish.sh` 双通道
> （`prod-sha-*` / `test-sha-*`）+ 调度仓 `dispatch.yml` 放行 ARTEX `test` ref。

## 通道模型

```
GitHub KTAIorg/ARTEX
  ├─ push main ──► ci.ktyun.cc 构建 ──► oci.ktyun.cc/ktaiorg/artex:prod-sha-<sha>  （生产实例用，现状不变）
  └─ push test ──► ci.ktyun.cc 构建 ──► oci.ktyun.cc/ktaiorg/artex:test-sha-<sha>  （灰度实例用，新增）
```

- `main` = 唯一事实源（治理铁律）；`test` = 长期跟踪分支，只做 `main → test` 快进，禁止在 test 上直接开发
- 同一套构建逻辑，仅 tag 前缀不同；晋升 = 生产实例换上已验证的 digest/tag，**不重新构建**

## 灰度部署形态（单机双实例）

| 实例 | compose 项目 | 镜像 | 端口 | 数据库 | 数据目录 |
|---|---|---|---|---|---|
| 生产 `artex` | 现有 compose（.env 里 `ARTEX_IMAGE=oci.ktyun.cc/ktaiorg/artex`） | `prod-sha-*` | 8787 | `artex` | `./data` |
| 灰度 `artex-canary` | `-p artex-canary` + `deploy/canary/docker-compose.canary.yml` | `test-sha-*` | 127.0.0.1:8789 | `artex_canary`（独立 PG） | `./data-canary` |

隔离边界：独立容器、独立端口、独立数据库（新版启动即幂等迁移 schema，先隔离验证再碰生产库）、独立数据目录。
唯一共享：VPS 资源（ARTEX 常驻 ~30Mi 内存，开销可忽略）与 `skills/` 目录（只读）。

## 操作步骤

### 1. 出一版灰度镜像

```bash
# 本地：把 main（或已评审的 feat 分支合入 main 后）快进到 test
git checkout test && git merge --ff-only main && git push origin test
# ci.ktyun.cc 自动构建 → oci.ktyun.cc/ktaiorg/artex:test-sha-<sha12>
```

### 2. VPS 上起灰度实例

```bash
cd <artex 部署目录>
export ARTEX_CANARY_PG_PASSWORD='<独立密码，勿与生产复用>'
export ARTEX_CANARY_TAG=test-sha-<sha12>
docker compose -p artex-canary -f deploy/canary/docker-compose.canary.yml up -d
curl -s http://127.0.0.1:8789/api/health   # 确认 version 与预期一致
```

### 3. 给内部用户入口（二选一）

- **CF Tunnel 子域（推荐）**：Cloudflare Tunnel 加 hostname `artex-beta.ktyun.cc` → `http://127.0.0.1:8789`，
  内部同事（KT Identity 登录）访问 beta 域名体验；生产入口不变。
- **临时直连**：compose 端口改 `"8789:8787"` 后 `IP:8789` 直访（建议加防火墙白名单，仅体验期间开放）。

### 4. 验证清单（beta 上）

- [ ] `/api/health` version 正确、启动日志无迁移报错
- [ ] KT Identity Telegram 扫码登录 + 角色映射（admin/operator/viewer）
- [ ] 本次变更的功能点逐项过（如：站内成员管理、原子工具、EXP 库……）
- [ ] 核心回归：任务下发、Agent 对话、资产页、CVE 双 tab
- [ ] 观察资源：`docker stats artex-canary`（无泄漏/异常增长）

### 5. 晋升生产

```bash
# 生产 .env 换 tag（用灰度验证过的同一 sha）
sed -i 's/^ARTEX_TAG=.*/ARTEX_TAG=prod-sha-<sha12>/' .env   # 若生产走 prod-sha 通道
docker compose pull artex && docker compose up -d artex
curl -s https://<生产域名>/api/health
```

> 注意：晋升前确认该 sha 的 `prod-sha-*` 镜像存在（push main 时 CI 已产出）；
> 若灰度验证的是 test 分支上领先 main 的提交，先把它合入 main 再晋升——生产只跑 main 可追溯的提交。

### 6. 回滚

```bash
# 灰度实例出问题：直接弃（不影响生产）
docker compose -p artex-canary down

# 生产晋升后出问题：换回上一个 prod-sha tag
sed -i 's/^ARTEX_TAG=.*/ARTEX_TAG=prod-sha-<上一个sha>/' .env
docker compose up -d artex    # 单机 Recreate，秒级回滚
```

## 与治理规范的对齐

- 构建一次、digest 晋升：test/prod 通道镜像都由 main（或其快进 test）的同一 commit 构建，晋升不重构建
- 生产必须灰度：本方案=实例维度灰度（beta 先行）；若未来迁 K8s/Argo，可再上 Rollouts 流量灰度
- 回滚 RTO：单机 compose 换 tag 重启，<1 分钟
