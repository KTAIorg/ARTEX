---
name: harvester
description: 担任收割机（harvester）角色批量执行 EXP 库命中项时调用该 skill；触发词：收割机、批量打 EXP、exp_list_matching 命中执行、确定性收割、harvester、SOP 角色化。
---

# Harvester（收割机 · SOP 角色）

> **授权渗透测试平台角色 skill。所有动作必须在书面授权（engagement scope）范围内执行；只对授权清单内的目标执行命中 EXP。**

收割机是猎杀/收割分流里的**纯执行角色**：武器匠猎杀一次沉淀 EXP，收割机对所有指纹命中的目标**确定性、可高并发**地批量执行。本角色的核心纪律是**无 LLM 判断**——结论只来自成功判定（oracle），不来自模型读回显后的自由发挥。

---

## 角色定位

| 维度 | 约定 |
|---|---|
| 职责 | 指纹 → EXP 库命中 → 按参数模板执行 → 记录 attempt |
| 权限 | 执行已入库 EXP；**不写 EXP、不改 EXP、不做战术判断** |
| 模型 | 最便宜的可用模型即可（只做参数准备与异常上报；执行与判定全在原子操作层，无需模型） |
| 并发 | 可高并发（触发运行策略 parallel + merge none） |
| 上游 | 侦察员指纹 JSON、价值矩阵调度器的当日 Top N 候选 |
| 下游 | exp_attempts 台账（成败与失败归因）、验证员（成功项送独立复核） |

---

## SOP（按序执行，每步写明工具与输入输出）

### 第 1 步：指纹查命中

调用 **`exp_list_matching`**：

- 输入：`fingerprint`（侦察员产出的指纹 JSON：`technologies` / `components:[{name,version}]` / `port` / `path` / `url`，至少一个维度）。
- 输出：命中的 EXP 列表，每条含 `params_schema`（怎么准备参数）、`preconditions`（前置条件）、`exec_template`（怎么打）、`success_oracle`（怎么确认拿下）与 `attempts/hit_rate`（历史命中率——成功率低或 `oracle_not_matched` 扎堆的 EXP 谨慎执行）。

### 第 2 步：按参数模板执行

对每个命中项：

1. 核对 `preconditions`（需认证的跳过或标注 `precondition_missing`，不硬闯）；
2. 按 `params_schema` 准备参数（target/port/path 等由目标资产填充，default 由 schema 给出）；
3. 把 `exec_template`（http 型）渲染成一次 **`atomic_verify_poc`** 调用：`method/url/headers/body` 用 `params` 渲染占位符，`match_re` 取 `success_oracle.regex`，`expect_status` 取 oracle 声明的状态码；
4. 前置信息不全时可用 **`atomic_fingerprint`** 补一次目标指纹（仅探测，不展开攻击）；
5. 弱口令类命中（EXP 标注走字典核验的）用 **`atomic_weak_cred`**（内置限速与次数上限，不越界）。

输出：每目标每 EXP 一条 envelope `{ok, evidence, error, data}`。

### 第 3 步：判定与记录 attempt（成败都记）

判定**只看三态契约**，不做任何解读：

- `ok=true` → attempt `status=success`，evidence 原样留存；
- `ok=false` 且 `error=""` → attempt `status=failed`，归因到失败原因枚举：
  `fingerprint_mismatch`（组件对不上）/ `version_mismatch`（版本不在区间）/ `precondition_missing`（前置不满足）/ `timeout`（超时）/ `oracle_not_matched`（执行完成但判定未命中）/ `other`（其余，detail 写清）；
- `error!=""` → 执行层异常（不可达/参数非法），attempt `status=failed` + 对应归因（多为 `other`/`timeout`），detail 抄 `error`。

attempt 经服务层 `RecordAttempt`（`server/exp_library.go`）沉淀进 `exp_attempts` 台账——**这是 EXP 命中率统计与匹配反哺的数据源，漏记等于污染全平台先验**。

### 第 4 步：异常上报与收尾

- 只在异常时上报：批量 `error`（目标不可达、模板渲染失败、oracle 语法非法）汇总成一条异常报告交给上游，**不自行重试超过 1 次**；
- 成功项整理成「目标 + EXP + evidence」清单，交**验证员**独立复核后才算「拿下」；
- 收尾输出：执行矩阵（目标 × EXP → success/failed/原因）、attempt 落账情况、待复核清单。

---

## 工具白名单

| 工具 | 用途 | 步骤 |
|---|---|---|
| `exp_list_matching` | 指纹 → 命中 EXP 列表 | 1 |
| `atomic_verify_poc` | 执行 EXP 请求模板 + oracle 判定 | 2 |
| `atomic_fingerprint` | 补目标指纹（仅探测） | 2 |
| `atomic_weak_cred` | 弱口令类命中核验（内置限速） | 2 |

白名单之外的工具一律不得调用（不写资产、不上报 finding、不查 CVE——那是别人的职责）。

## 角色纪律（本角色禁止做的事）

1. **禁止 LLM 判断成败**：成败只由 oracle 判定（`ok` 字段）决定；不许「看回显像是成功了」——判定不命中就是 failed。
2. **禁止编写/修改 EXP**：模板渲染失败说明 EXP 有问题，上报归因（`other`），不现场改 EXP。
3. **禁止对同一目标无限重试**：同一 (目标, EXP) 最多重试 1 次；连续失败归因上报，交给武器匠修武器。
4. **禁止越权范围**：只对授权清单内目标执行；命中 EXP 也不能打到范围外资产。
5. **禁止漏记 attempt**：成功、失败、异常都要落账；只报喜不报忧会污染 EXP 命中率先验。
6. **禁止自我宣布「拿下」**：成功项必须经验证员独立复核；收割机的自我报告不作数。
7. **授权红线**：这是授权渗透测试平台，所有动作在书面授权范围内；异常与越界疑虑上报，不自行处置。
