# EXP 资产库设计（复利引擎）

> 授权渗透测试平台的能力沉淀库。战略：每次成功利用自动沉淀为**参数化 EXP**，
> agent 猎杀一次、全平台永久收割同类目标；失败也要结构化沉淀，反哺匹配
> 准确度。这是把「一次性消耗」变成「可复用资产」的复利核心。
>
> **纪律：EXP 只在授权范围内使用。** 授权边界由任务 scope 与拦截层把关；
> 本库只做能力沉淀与匹配查询，不做放行判定。

成功率先验公式：`P(拿下) = P(指纹正确) × P(EXP可用) × P(前置满足) × P(执行无误)`。
本设计修的是 **P(EXP可用)** 的地基：库里有什么、怎么判定一条 EXP 适用于一个
目标、以及怎么用真实执行结果（成功与失败）持续修正这个先验。

## 1. 表结构

迁移风格与仓库一致：`db/schema.sql` 幂等分节（§N），每次启动整体重放，
`CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`。不动现有表，
只新增。

### exp_assets（参数化 EXP）

| 列 | 类型 | 语义 |
|---|---|---|
| id | BIGSERIAL PK | |
| name | TEXT UNIQUE | 人类可读唯一名（如 `tomcat-ghostfile-rce`） |
| description | TEXT | 适用场景/注意事项 |
| fingerprint_match | JSONB | 指纹条件（见 §2） |
| preconditions | JSONB | 前置条件数组，如 `[{"kind":"path_exists","detail":"/manager/html"}]`；执行前逐项核对 |
| params_schema | JSONB | 参数模板 JSON Schema，占位符契约（`{target}`/`{port}`…），与自定义工具 schema 同构 |
| exec_template | JSONB | 执行模板：`{"kind":"http","method":…,"url":…,"headers":…,"body":…,"timeout_ms":…}` 或 `{"kind":"command","command":…}` / `{"kind":"script","code":…}`，与 `server/customtool.go` 的 exec 规格同构，后续执行器直接复用 |
| success_oracle | JSONB | 成功判定：`{"status_codes":[200],"keywords":["root:"],"regex":"…"}` 至少一项 |
| cleanup | JSONB NULL | 清理动作（http/command 模板，参数同一套占位符）；可空 |
| cve_ids | TEXT[] | 关联 CVE |
| tags | TEXT[] | 检索标签（GIN 索引） |
| enabled | BOOLEAN | 停用即从匹配面消失 |
| version | INTEGER | 每次内容更新 +1：乐观锁水位 + 复利迭代计数 |
| created_at / updated_at | TIMESTAMPTZ | updated_at 触发器维护 |

### exp_attempts（失败沉淀台账）

| 列 | 类型 | 语义 |
|---|---|---|
| id | BIGSERIAL PK | |
| exp_id | BIGINT → exp_assets ON DELETE CASCADE | 台账随 EXP 删除级联 |
| target | TEXT | 资产标识（`host[:port]` 或 URL），可回查 |
| status | TEXT CHECK | `success` \| `failed`，成功与失败都记 |
| failure_reason | TEXT CHECK | 闭合枚举（见下）；失败必填、成功必空（CHECK 强制） |
| detail | TEXT | 人类可读事实（失败时必填，service 层校验） |
| evidence | JSONB | 证据快照：请求/响应摘要、判定命中点；接 evidence 体系时存引用 |
| created_at | TIMESTAMPTZ | |

`failure_reason` 枚举与先验公式因子一一对应：

| 枚举 | 对应因子 | 含义 |
|---|---|---|
| `fingerprint_mismatch` | P(指纹正确) | 组件/端口/路径对不上 |
| `version_mismatch` | P(指纹正确) | 版本不在 EXP 声明区间（含版本未知） |
| `precondition_missing` | P(前置满足) | 前置条件不满足 |
| `timeout` | P(执行无误) | 执行超时 |
| `oracle_not_matched` | P(EXP可用) | 执行完成但成功判定未命中——EXP 本身可能坏了，需要迭代 |
| `other` | — | 其他（detail 写清） |

### down / 清理路径

本仓库迁移为幂等加列式（schema.sql 整体重放），无自动 down。回滚本特性
时人工执行（顺序：先 attempts 后 assets）：

```sql
DROP TABLE IF EXISTS exp_attempts;
DROP TABLE IF EXISTS exp_assets;
```

## 2. 指纹匹配语义

实现：`db/exp_match.go`（纯 Go，无 DB 依赖，`MatchExpFingerprint`）。

**EXP 侧条件**（`fingerprint_match`）：

```json
{
  "components": [{"name": "RocketMQ", "version_range": ">=4.0.0,<5.1.0"}],
  "ports":      [10911, 9876],
  "paths":      ["/assets/"]
}
```

**资产侧输入**（agent 从探测结果整理）：

```json
{
  "technologies": ["Nginx/1.18.0", "Apache Tomcat 9.0.30"],
  "components":   [{"name": "tomcat", "version": "9.0.30"}],
  "port": 8080,
  "path": "/manager/html",
  "url":  "http://t:8080/manager/html"
}
```

规则：

- **维度之间 AND**：`components ∧ ports ∧ paths`，未声明的维度恒通过；
  全空 = 通配（慎用）。
- **components 条目之间 OR**；条目内 name 与版本区间是 AND。
- **name 匹配**：忽略大小写 + 双向子串（条件 `tomcat` 命中 `Apache Tomcat`，
  条件 `Apache RocketMQ` 也命中解析出的 `RocketMQ`）。
- **version_range**：逗号分隔 `op version`，op ∈ `>= <= > < = !=`（`=` 可省略；
  `*`/空 = 不限）。版本容忍 `v` 前缀与 1~3+ 段数字（`2`、`2.3`、`2.3.1`），
  缺段补 0 逐段**数值**比较（`1.10 > 1.9`，`1.18 == 1.18.0`）。
- **保守归因**：声明了版本区间而资产只认出组件、认不出版本 → 判
  `version_mismatch`（P(指纹正确) 不允许含糊，宁缺勿假）。
- **ports**：声明即要求资产端口命中其一；资产端口未知（0）→ 不命中。
- **paths**：声明即要求资产路径（显式 `path`，或从 `url` 提取）包含任一特征
  （忽略大小写子串）；路径未知 → 不命中。
- **technologies 解析启发式**：从第一个后跟数字（或 `v`+数字）的分隔符
  (`:` `/` 空格 `-`) 处切成 name/version，如 `Apache Tomcat 9.0.30` →
  (`Apache Tomcat`, `9.0.30`)；显式 `components` 优先参与判定。

未命中原因直接复用 `failure_reason` 口径（`fingerprint_mismatch` /
`version_mismatch`），可原样沉淀进失败台账。

## 3. 失败沉淀语义

- **成功与失败都记**（`db.ExpStore.RecordExpAttempt`），失败必须带结构化
  `failure_reason` + `detail`；成功不允许带 reason（Go 校验 + DB CHECK 双保险）。
- **统计面**（`ExpAssetStats`）：每条 EXP 的 `attempts/success/failed/hit_rate`
  与 `failure_dist`（失败原因分布）。`hit_rate` 是 P(EXP可用) 的实然测量；
  `oracle_not_matched` 扎堆 → EXP 本身要迭代；`version_mismatch` 扎堆 →
  指纹版本区间该收紧。agent 选型时把命中率带在匹配结果里。
- 失败沉淀反哺匹配的方式（本期为人工/agent 迭代，自动收紧列为后续）：
  依据 failure_dist 修正 fingerprint_match 的版本区间/组件条件，每次修正
  `version+1`，形成「执行 → 归因 → 修正」的闭环。

## 4. 复利闭环（文字图）

```
        ┌─────────────────────────────────────────────────────┐
        │                    授权范围内猎杀                     │
        └─────────────────────────────────────────────────────┘
   探测资产指纹（technologies/components/port/path/url）
                    │
                    ▼
        exp_list_matching（只读工具，绑 auto+worker）
        输入指纹 → 命中 EXP（含参数模板/前置/执行模板/成功判定/历史命中率）
                    │
        ┌───────────┴───────────┐
        命中                     未命中
        │                        └──→ agent 现场手工利用 ──┐
        ▼                                                │
   执行（后续接 customtool 执行器）                        │
        │                                                │
   成功判定 oracle                                        │
        │                                                │
   ┌────┴─────┐                                          │
   成功        失败                                       │
   │           │                                          │
   ▼           ▼                                          ▼
 exp_attempts 台账（成功 + 失败带 failure_reason）   手工利用成功
   │           │                                          │
   │           └→ failure_dist → 收紧/修正指纹区间 → version+1
   │                                                      │
   └──────────────────────────────────────────────────────┘
                    │
                    ▼
        参数化沉淀为一条新 EXP（exec_template + oracle + 前置 + 清理）
                    │
                    ▼
        下一个同类目标：指纹一命中即收割（复利）
```

一句话：**成功 → 沉淀配方；失败 → 沉淀归因；两者都让下一次更快。**

## 5. 代码分层与接线现状

| 层 | 文件 | 内容 |
|---|---|---|
| 迁移 | `db/schema.sql` §N | exp_assets / exp_attempts（幂等） |
| repository | `db/exp_assets.go` | `db.ExpStore`：CRUD、启停、乐观版本、attempt 台账、命中率统计 |
| 匹配引擎 | `db/exp_match.go` | 指纹条件/资产指纹解析、版本区间、维度匹配（纯 Go） |
| service | `server/exp_library.go` | `ExpLibrary`：写路径语义校验（exec kind/oracle 非空/fingerprint 合法）、`MatchByFingerprint`、`RecordAttempt`、`Stats` |
| agent 暴露 | `server/exp_tools.go` | 只读工具 `exp_list_matching`（vuln_tools.go 风格），seed 默认绑 `auto`+`worker`，老库一次性补绑（flag 守卫） |

### 已完成

- 迁移 + repository + 匹配引擎 + service + 只读工具 `exp_list_matching`
  （含 tools 表 seed 与 agent 绑定）。
- 测试：`db/exp_match_test.go`（版本区间边界/维度语义/坏条件拒绝，纯逻辑）、
  `db/exp_assets_test.go`（CRUD/乐观版本/台账校验/级联/统计/CHECK 冒烟，
  走 db 现有真库测试基建，无 PG 自动 skip）。

### 接线计划（后续）

1. **EXP 执行器**：`exp_assets.exec_template` 与 `server/customtool.go` 的
   command/script/http 执行规格同构；接线时新增 `exp_execute`（写工具，走
   拦截审批），执行前后自动记 attempt（超时→`timeout`、判定未命中→
   `oracle_not_matched`），成功后提示沉淀。
2. **登记入口**：为 auto/pentest agent 提供从一次成功利用生成 EXP 草稿的
   工具（复用 ExpLibrary 校验），减少手工整理成本。
3. **自动修正**：基于 failure_dist 的指纹区间收紧建议（先出建议、人确认，
   再谈自动改写）。
4. **证据关联**：`exp_attempts.evidence` 与 `evidence/` 体系打通，存引用
   而非快照。

## 6. 使用示例

登记（service 层语义，name 唯一）：

```json
{
  "name": "spring-cloud-gateway-cve-2022-22947",
  "fingerprint_match": {"components": [{"name": "Spring Cloud Gateway", "version_range": "<3.1.1"}]},
  "preconditions": [{"kind": "path_exists", "detail": "/actuator/gateway/routes"}],
  "params_schema": {"type": "object", "properties": {"target": {"type": "string"}, "port": {"type": "integer", "default": 8080}}, "required": ["target"]},
  "exec_template": {"kind": "http", "method": "POST", "url": "http://{target}:{port}/actuator/gateway/routes", "body": "..."},
  "success_oracle": {"status_codes": [201], "keywords": ["route_id"]},
  "cve_ids": ["CVE-2022-22947"],
  "tags": ["spring", "rce"]
}
```

匹配（agent 调 `exp_list_matching`）：

```json
{"fingerprint": {"technologies": ["Spring Cloud Gateway 3.0.7"], "port": 8080, "path": "/actuator/gateway/routes"}}
```

失败沉淀（service `RecordAttempt`）：

```json
{"exp_id": 1, "target": "10.0.0.4:8080", "status": "failed",
 "failure_reason": "oracle_not_matched", "detail": "actuator 未暴露，返回 404",
 "evidence": {"status": 404}}
```
