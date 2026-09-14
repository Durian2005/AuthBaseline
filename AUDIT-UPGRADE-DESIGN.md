# 实验二改造方案｜让所有安全事件可追责

> 审计从「调试输出」升级为**独立安全控制**。
> 本文是动手前的设计确认稿，经确认后再逐项落地。
>
> 决策基线（已确认）：
> | 项 | 选定方案 |
> |---|---|
> | 授权模型 | 引入服务端**不透明随机票据**（Bearer） |
> | 票据有效期 | **滑动过期 2 小时** |
> | 防篡改 | **链式哈希 + 完整性校验接口**（不带定时巡检） |
> | 轮转归档 | **分片集合**（`AuditLogs_yyyyMM`） |
> | 事件字段 | **新增字段，不改旧字段**（追加 `reasonCode`） |
> | 验收脚本 | **四组合一的** `tools/audit_e2e_test.py` |

---

## 一、现状差距（改造前）

| 图片要求 | 现状 | 差距 |
|---|---|---|
| **01 记得全**<br>关键成功、失败、拒绝均生成事件 | `WriteAuditLogAsync` 已覆盖所有分支，`result` 独立成列，`target` 已记 | 缺 `reason_code`（拒绝/失败的具体原因码只落在响应体，没进事件本身） |
| **02 看不到**<br>普通用户查询日志必须被拒绝 | `GET /logs?adminUsername=xxx`、`GET /users?adminUsername=xxx` **只凭 URL 字符串声明身份** | **致命**：任何人带上 `adminUsername=admin` 即可读走全部日志。无任何拒绝事件产生 |
| **03 改不掉**<br>篡改后完整性校验报警 | 无哈希链、无校验接口 | 完全缺失 |
| **04 撑得住**<br>连续写入后轮转/归档仍可查询 | 单集合，`GET /logs` 硬编码 `Limit(200)` | 完全缺失；写多少都只看得到最近 200 条 |

### 必须堵住的洞（02 的实现前提）

```
当前：GET /api/auth/logs?adminUsername=admin   ← 只要知道管理员用户名就能读
攻击：curl "http://localhost:5007/api/auth/logs?adminUsername=admin"
结果：200 + 全部审计日志（含操作者、请求报文）
```

`adminUsername` 是**客户端可控的声明**，不是**凭证**。这是本次改造的核心命题。

---

## 二、总体架构

```
                    ┌──────────────────────────────────┐
   登录成功 ────────▶│ 签发 ticket（32B 随机数）         │
                    │ Sessions 集合：owner/role/expires │
                    └──────────────┬───────────────────┘
                                   │ 返回给前端
                    ┌──────────────▼───────────────────┐
   管理员接口 ◀──────│ Authorization: Bearer <ticket>    │
                    │ TicketAuth → 校验 + 滑动续期        │
                    └──────────────┬───────────────────┘
                                   │ 失败
                    ┌──────────────▼───────────────────┐
                    │ 401/403 + 生成「拒绝」审计事件      │◀── 02 证据
                    └──────────────────────────────────┘

   写入路径：
   WriteAuditLogAsync ──▶ 计算 hash = SHA256(prevHash ‖ 规范化字段)
                      ──▶ 插入 AuditLogs_yyyyMM（按当前月份分片）   ◀── 04 轮转
                      ──▶ 维护 AuditChainHead 集合记录链尾

   校验路径：
   GET /api/audit/verify ──▶ 逐条重算，比对 prevHash/selfHash
                        ──▶ 返回 { intact, firstBrokenIndex, expected, actual }  ◀── 03 证据
```

---

## 三、数据模型改动

### 3.1 `AuditLog` 新增字段（不动旧字段）

```csharp
/// <summary>失败/拒绝的原因码，如 ACCOUNT_LOCKED、UNAUTHORIZED、WEAK_PASSWORD。
/// 成功事件为空串。旧记录缺该字段时读出来也是空串，前端筛选逻辑照旧可用。</summary>
[BsonElement("reasonCode")]
public string ReasonCode { get; set; } = string.Empty;

/// <summary>本条记录的自哈希（SHA-256，64 位小写十六进制）。</summary>
[BsonElement("selfHash")]
public string SelfHash { get; set; } = string.Empty;

/// <summary>前一条记录的 selfHash。链首为 64 个 0。
/// 该字段把「单条被改」升级为「整链可验」。</summary>
[BsonElement("prevHash")]
public string PrevHash { get; set; } = string.Empty;

/// <summary>链内严格递增序号，用于定位断点与跨分片排序（时间戳可能重复）。</summary>
[BsonElement("seq")]
public long Seq { get; set; }

/// <summary>所在分片集合名，如 AuditLogs_202609。便于归档后按片检索。</summary>
[BsonElement("shard")]
public string Shard { get; set; } = string.Empty;
```

字段映射到图片给出的「事件最小骨架」：

| 图片骨架 | 现有字段 | 说明 |
|---|---|---|
| `time` | `timestamp` | 已有（UTC） |
| `actor_type` | —— | **隐含**：`operatorId == "anonymous"` 即访客，否则为已认证主体。可选新增显式字段 |
| `actor_id` | `operatorId` + `operatorName` | 已有 |
| `source` | —— | **新增建议**：`{ ip, userAgent }`，图片明确要求 |
| `action` | `action` | 已有 |
| `object` | `target` | 已有 |
| `result` | `result` | 已有（成功/失败） |
| `reason_code` | **`reasonCode`（本次新增）** | —— |

> **待你决定的一点**：`source`（IP + UA）要不要一并加上？加上后「谁在哪个地址发起了这次越权尝试」这类追责证据会完整很多，成本只是给 `WriteAuditLogAsync` 多传两个参数。

### 3.2 新增 `Session` 集合

```csharp
public class Session
{
    [BsonId][BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    [BsonElement("ticket")]      public string Ticket { get; set; } = string.Empty;   // 32B 随机数的 Base64Url
    [BsonElement("username")]    public string Username { get; set; } = string.Empty;
    [BsonElement("isAdmin")]     public bool IsAdmin { get; set; }
    [BsonElement("issuedAt")]    public DateTime IssuedAt { get; set; }
    [BsonElement("lastSeenAt")]  public DateTime LastSeenAt { get; set; }               // 滑动续期基准
    [BsonElement("expiresAt")]   public DateTime ExpiresAt { get; set; }                // TTL 索引自动清理
    [BsonElement("revokedAt")]   public DateTime? RevokedAt { get; set; }               // 登出即置位
}
```

- `expiresAt` 上建 **TTL 索引**（复用 `EmailCodes` 的成熟做法，无需定时任务）。
- 每次通过校验即刷新 `lastSeenAt`，并把 `expiresAt` 推到 `now + 2h` → 滑动过期。
- **权限实时性**：校验时**重新查库确认该用户当前 `IsAdmin` 与 `Status`**，而不是只信票据里的快照。这样「权限被转让后旧票据立刻失去管理员能力」。

### 3.3 新增 `AuditChainHead` 集合（链尾锚点）

```csharp
public class AuditChainHead
{
    [BsonId] public string Id { get; set; } = "head";   // 固定单文档
    [BsonElement("seq")]      public long Seq { get; set; }
    [BsonElement("lastHash")] public string LastHash { get; set; } = new string('0', 64);
    [BsonElement("shard")]    public string Shard { get; set; } = string.Empty;
}
```

JSON Schema 校验点：哈希输入必须是**规范化**的，否则同一事件在不同序列化顺序下算出不同哈希，校验会误报。规范化规则见 4.2。

---

## 四、实现要点

### 4.1 授权：`TicketAuth` 中间件/过滤器

```csharp
// 逻辑伪码
1. 读取 Authorization: Bearer <ticket>
2. 缺失 → 401 UNAUTHORIZED，并写一条 result=失败、reasonCode=NO_TICKET 的审计事件
3. 查 Sessions：不存在 / revokedAt 非空 / expiresAt < now
         → 401 SESSION_INVALID（区分 SESSION_EXPIRED / SESSION_REVOKED）
4. 滑窗续期：lastSeenAt = now, expiresAt = now + 2h
5. 重新查 Users 确认 Status == Enabled（Locked/Pending/Disabled 一律拒绝）
6. 若接口要求管理员，而该用户 IsAdmin == false
         → 403 FORBIDDEN，写 result=失败、reasonCode=NOT_ADMIN、target=接口名
7. 通过 → 把 (userId, username, isAdmin) 注入 HttpContext.Items 供 Controller 使用
```

**关键点**：第 2/3/6 步的拒绝**本身也要落审计**。这正是 02 要求「拒绝响应 + 被拒绝事件」两份证据的来源——只有拒绝响应是不够的，必须证明系统把这次越权尝试也记下来了。

**要改的接口**：

| 接口 | 现状 | 改后 |
|---|---|---|
| `GET /logs` | `?adminUsername=` | Bearer，仅管理员 |
| `GET /users` | `?adminUsername=` | Bearer，仅管理员 |
| `POST /approve` | body 里 `adminUsername` | Bearer，仅管理员 |
| `POST /unlock` | 同上 | Bearer，仅管理员 |
| `POST /delete-user` | 同上 | Bearer，仅管理员 |
| `POST /transfer-admin` | 同上 + 口令 | Bearer + 保留口令二次校验 |
| **`GET /audit/verify`（新增）** | —— | Bearer，仅管理员 |
| `POST /login` | —— | **改**：成功后签发 ticket 返回 |
| **`POST /logout`（新增）** | —— | Bearer，置 `revokedAt` |

> `change-password` / `register` / `reset-password` / `send-email-code` 维持现状（本就是凭旧口令或验证码操作，不依赖会话）。

### 4.2 防篡改：规范化 + 哈希链

哈希输入的**规范形式**（字段固定顺序、统一格式，避免序列化差异导致误报）：

```
prevHash || seq || timestamp(ISO8601, 毫秒精度, UTC) || actorType || actorId
        || action || object || result || reasonCode || sha256(request) || sha256(response)
```

```
selfHash = SHA256(上述字符串).ToLowerHex()
```

写入是**串行化**的：用一把 `SemaphoreSlim` 保护「读链尾 → 算哈希 → 插入 → 更新链尾」这一临界区，否则并发写入会产生两条 `prevHash` 相同的记录，链就分叉了。

> 这是本次改造里**最容易踩的坑**：`AuthBaseline` 是并发请求的 Web 服务，不做互斥的哈希链在压力测试下必然断裂，然后被自己的校验接口误判为「遭到篡改」。方案里显式用锁串行化。

### 4.3 完整性校验接口

```
GET /api/audit/verify?from=1&to=5000&shard=AuditLogs_202609
```
（参数可省略，默认校验当前分片全量）

响应：
```json
{
  "success": true,
  "data": {
    "intact": false,
    "checked": 5000,
    "firstBrokenSeq": 137,
    "expectedPrevHash": "a3f1...9c",
    "actualPrevHash":   "0000...00",
    "brokenShard": "AuditLogs_202609",
    "brokenAt": "2026-09-14T09:12:33.412Z"
  }
}
```

校验逻辑要做**三类检测**：
1. **内容被改**：重算 `selfHash` ≠ 存储值 → 该条断裂；
2. **顺序被调换 / 中间被删**：本条 `prevHash` ≠ 上一条 `selfHash` → 断点在此；
3. **整段被删**：链尾锚点 `seq` 与实际最大 `seq` 不一致，或 `seq` 出现跳号 → 报告缺口区间。

### 4.4 轮转：分片集合

- 写入时按 `DateTime.UtcNow.ToString("yyyyMM")` 选集合：`AuditLogs_202609`。
- **跨月时链要连续**：链头锚点全局唯一，新分片的第一条 `prevHash` 承接上一分片的链尾，因此链跨分片仍然可验。
- 查询接口支持 `shard` 参数（默认当前月），并返回可用分片清单：

```
GET /api/audit/shards
→ [{ "shard": "AuditLogs_202609", "count": 18243, "firstSeq": 1, "lastSeq": 18243 },
   { "shard": "AuditLogs_202608", "count": 90412, "firstSeq": -90411, "lastSeq": 0 }]
```

- **旧的 `AuditLogs` 集合作为「历史分片」兼容**：`GET /logs` 默认同时查 `AuditLogs` + 当前分片，保证改造前的老日志不消失。

> 演示时按月轮转不好压测（等不到跨月）。方案里额外提供环境变量 `AUDIT_SHARD_UNIT=day|month|count`，压测时切成 `count`（如每 2000 条滚一片），这样**几十秒内就能跑出真实的轮转证据**，答辩时不必伪造。

### 4.5 查询接口改造

```
GET /api/audit/logs?shard=&keyword=&action=&result=&page=&pageSize=
```
- 去掉硬编码 `Limit(200)`，改为**分页**（默认 pageSize=50，上限 500）。
- 支持「含归档」查询：`includeArchived=true` 时跨所有分片聚合。

---

## 五、前端改动（`AuthClient`）

| 文件 | 改动 |
|---|---|
| `api/client.js` | 请求头自动带 `Authorization: Bearer`；新增 `verifyAudit()` / `logout()` / `getShards()` |
| `stores/session.js` | 登录后保存 ticket（`localStorage`）；`logout` 调后端吊销 |
| `views/AuditView.vue` | 新增「完整性校验」按钮 + 结果面板（显示断点 seq、期望/实际哈希）；分片切换；分页控件替代「最近 200 条」 |
| `views/LoginView.vue` | 无改动（登录响应多一个 ticket 字段，store 内部消化） |

> 前端仍走 `npm run build` 输出到 `AuthServer/wwwroot`，后端托管方式不变。

---

## 六、验收证据清单（对照图片四组）

统一脚本 `tools/audit_e2e_test.py`，四组用例各自输出 PASS/FAIL 与原始证据。

### 01 覆盖测试 ·「记得全」
| 用例 | 断言 |
|---|---|
| 依次触发：注册 / 审核 / 登录成功 / 登录失败×3 / 锁定 / 解锁 / 改密 / 越权查询 | 每类都在审计集合中生成事件 |
| 字段覆盖检查 | 每条事件 `time/actorId/action/object/target/result` 非空；失败事件 `reasonCode` 非空 |
| 拒绝也留痕 | 越权与参数校验失败同样生成事件（无盲区） |

**证据**：脚本打印「触发 N 类操作 → 审计事件 M 条 → 字段缺失 0 条」+ 事件清单表格。

### 02 越权测试 ·「看不到」
| 用例 | 断言 |
|---|---|
| 普通用户 ticket 调 `GET /logs` | **403** + `reasonCode=NOT_ADMIN` |
| 无 ticket 调 `GET /logs` | **401** + `reasonCode=NO_TICKET` |
| 伪造 ticket 调 `GET /logs` | **401** + `SESSION_INVALID` |
| 普通用户 ticket 调 `GET /users` | **403** |
| **交叉验证**：上面每次拒绝后，用管理员 ticket 拉日志 | 能找到对应的「被拒绝事件」，且记下尝试者的身份与接口 |

**证据**：拒绝响应 JSON + 被拒绝事件记录，两份对上。

### 03 篡改测试 ·「改不掉」
| 用例 | 断言 |
|---|---|
| 基线：调 `verify` | `intact = true` |
| 用 mongosh 直接改第 137 条的 `action` | 校验返回 `intact=false`、`firstBrokenSeq=137` |
| 用 mongosh 删中间一条 | 校验定位到缺口 |
| 用 mongosh 交换两条顺序 | 校验定位到断点 |

**证据**：修改前值 / 修改后值 / 校验结果三者并列。

> 脚本通过 `mongosh --eval` 或 pymongo 直连 27017 完成篡改，**绕过后端**，这才是真实攻击面。

### 04 增长测试 ·「撑得住」
| 用例 | 断言 |
|---|---|
| 连续写入 ≥ 5000 条（`AUDIT_SHARD_UNIT=count`，每 2000 条滚片） | 出现 ≥ 3 个分片集合 |
| 查 `GET /audit/shards` | 各分片 count / seq 区间正确 |
| 跨分片查日志 | 归档分片内的记录仍可检索 |
| 在全部分片上跑 `verify` | **跨分片链仍然连续，`intact=true`** |

**证据**：分片清单 + 各集合计数 + 归档内记录查询结果 + 跨片校验通过。

---

## 七、风险与注意事项

1. **并发写入断链**（最高风险）：哈希链必须串行化写入，方案已在 4.2 用锁处理。压测前务必确认。
2. **老日志无哈希**：改造前的老记录没有 `prevHash/selfHash`。校验逻辑对「缺失哈希的旧记录」采取**宽容策略**（跳过并计入 `legacySkipped` 计数），否则第一次校验就会报「全链断裂」，无法演示。
3. **审计写入失败不能拖垮主流程**：现有 try-catch 兜底要保留。但注意——加锁后若链尾更新失败，会留下「已插入但链尾未推进」的空隙，需要**插入与链尾更新放在同一临界区内**，校验时对该情况给出明确提示而非误报篡改。
4. **接口签名变更的连锁影响**：现有 `tools/email_e2e_test.py`（34 项）与 `tools/ui_e2e.mjs`（11 项）都直接调管理员接口，改成 Bearer 后会**全部失败**。需要同步更新这两个脚本，并把它们纳入回归验证。
5. **桌面端（Tauri）兼容**：`sidecar` 后端动态端口，Bearer 机制与端口无关，不影响；但要在桌面版上重跑一遍 `ui_e2e.mjs`。
6. **`AuditView.vue` 的 200 条假设**：页面文案「保留最近 200 条记录」需要随分页改造同步更新。

---

## 八、建议的实施顺序

```
Step 1  数据模型：AuditLog 加字段、Session、AuditChainHead + 索引
Step 2  审计写入服务：抽独立 AuditService，加锁串行 + 哈希链 + 分片选择
Step 3  会话票据：签发 / 校验 / 吊销 + TicketAuth 过滤器
Step 4  接口改造：6 个管理员接口切 Bearer；新增 /verify /logout /shards /audit/logs(分页)
Step 5  把 WriteAuditLogAsync 的既有调用点全部迁到 AuditService，并补 reasonCode
Step 6  前端适配（client.js / session.js / AuditView.vue）
Step 7  验收脚本 audit_e2e_test.py 四组用例
Step 8  回归：跑通 email_e2e_test.py 与 ui_e2e.mjs（含桌面版）
Step 9  文档：README 增补实验二章节 + 证据截图
```

---

## 九、需要你确认的最后两点

1. **`source` 字段（IP + UserAgent）要不要加？** 图片骨架里明确列了 `source`。加了追责证据更完整，代价是 `WriteAuditLogAsync` 要多传两个参数（约 20 行改动）。
2. **`actor_type` 要不要显式落字段？** 现在是靠 `operatorId == "anonymous"` 隐含表达。显式落一个 `actorType`（`user` / `anonymous` / `system`）更贴合图片骨架，也方便后续加「系统自动解锁」这类无操作者事件。

这两点你定了，我就开始动手。
