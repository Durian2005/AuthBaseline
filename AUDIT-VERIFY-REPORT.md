# 实验二验收报告｜让所有安全事件可追责

对应验收图片四组要求：**01 记得全 · 02 看不到 · 03 改不掉 · 04 撑得住**。
改造方案见 `AUDIT-UPGRADE-DESIGN.md`，本文件只记录**实测结果与证据**。

交付形态：**Tauri 桌面端软件**（`AuthBaseline_1.0.0_x64-setup.exe`），
内置 .NET 8 后端 sidecar 与 MongoDB 存储，装完即用，无需另起服务。

---

## 一、结论速览

| 验收项 | 要求 | 实测结果 | 状态 |
|--------|------|----------|------|
| 01 记得全 | 成功/失败/拒绝行为全部留痕 | 覆盖测试 57 项全过，含越权与锁定路径 | ✅ |
| 02 看不到 | 未授权者读不到审计数据 | 无票据/坏票据/过期票据均 401，且**被拒行为本身也留痕** | ✅ |
| 03 改不掉 | 改库、删记录、调顺序都能被发现 | 直接改库 → 30 秒内弹阻断式告警（见证据 3） | ✅ |
| 04 撑得住 | 数据量大也能查、能翻、能校验 | 分片集合并行校验，324 条链完整，分页 1/14 页 | ✅ |

**一键验证命令**：

```bash
python tools/audit_e2e_test.py      # 四组验收全流程（57 项断言）
python tools/verify_api.py          # 起后端并校验链完整性
```

---

## 二、01 记得全 · 覆盖测试

所有写审计的入口统一收口到 `AuditService.WriteAsync`，
业务失败不阻断主流程（旁路记录，永不抛异常拖垮注册/登录）。

实测覆盖的事件类型：

| 类别 | 事件动作 | 说明 |
|------|----------|------|
| 认证 | `LOGIN_SUCCESS` / `LOGIN_FAILED` | 含失败次数、剩余机会 |
| 账号状态 | `REGISTER` / `APPROVE` / `UNLOCK` / `DELETE_USER` | 记 `statusBefore → statusAfter` |
| 口令 | `CHANGE_PASSWORD` / `RESET_PASSWORD` / `SEND_EMAIL_CODE` | |
| 越权 | `AUTH_DENIED` | **被拒绝的访问同样入链**，这是"看不到"与"记得全"的交汇点 |
| 审计自省 | `AUDIT_QUERY` / `AUDIT_VERIFY` / `AUDIT_TAMPERED` | 谁看了日志、谁校验过、发现了什么 |
| 锁定 | `ACCOUNT_LOCKED`（失败 3 次锁定 3 分钟） | 锁定期间正确口令也拒绝，理由码 `ACCOUNT_LOCKED` |

每条记录包含：操作者、动作、目标、结果、原因码、前后状态、
来源 IP、请求摘要、响应摘要、精确时间戳。

---

## 三、02 看不到 · 越权测试

- 会话票据为**服务端不透明随机值**（32 字节 CSPRNG，Base64Url），
  数据库只存摘要；客户端拿到的字符串本身不携带任何身份信息，无法伪造或推算。
- 滑动过期 2 小时，退出即失效，TTL 索引自动清理过期会话。
- 审计查询与校验接口均需有效票据 + 管理员身份。

实测：

| 场景 | 期望 | 实测 |
|------|------|------|
| 不带 Authorization 查审计 | 401 | 401 ✅ |
| 伪造票据 | 401 | 401 ✅ |
| 过期票据 | 401 | 401 ✅ |
| 普通用户查审计 | 403 | 403 ✅ |
| 上述**每一次拒绝** | 应写入 `AUTH_DENIED` | 已入链 ✅ |

---

## 四、03 改不掉 · 篡改测试（核心要求）

### 4.1 防护机制

哈希链：每条记录的 `selfHash` 由以下内容确定性拼接后 SHA-256 得出 ——

```
prevHash | seq | timestamp(ISO8601毫秒Z) | actorType | operatorId | operatorName
| action | target | result | reasonCode | statusBefore | statusAfter | sourceIp
| sha256(request) | sha256(response)
```

字段顺序固定、时间格式固定、长文本先各自哈希再入链（保证定长），
因此同一事件在任何机器上都能算出同一个哈希，不会把正常记录误报为篡改。

链尾锚点 `AuditChainHeads` 独立于日志集合存放，用于发现"尾部整段被删"——
这类攻击单靠链式哈希是发现不了的（删掉尾巴后每条记录自身仍然自洽）。

序号由 MongoDB 原子 `$inc` 分配（`FindOneAndUpdate`），
配合进程内临界区锁，保证多进程并发写入时序号唯一、连续、不分叉。

### 4.2 三类攻击的检出

| 攻击手法 | 检出方式 | 报错文案 |
|----------|----------|----------|
| 改内容（改字段但不改哈希） | 重算 `selfHash` 与存储值比对 | 记录内容与签名不符 |
| 删中间 / 调顺序 | 本条 `prevHash` 与上一条 `selfHash` 比对 | 前序哈希不匹配 |
| 删尾部 | 链尾锚点 `seq` 与实际最大 `seq` 比对 | 链尾缺失 |
| 删开头 | 最小序号是否等于 1 | 链首缺失 |

### 4.3 实测：**直接在数据库里非法修改，桌面端弹窗**

这是本次最关键的一条硬性要求。验证步骤：

1. 装好桌面端并正常登录（此时后端与界面均正常运行）；
2. **绕过应用**，用独立进程（pymongo）直接连 MongoDB，
   把 `AuditLogs_202609` 中最新一条记录的 `action` 字段改成 `TAMPERED_BY_ATTACKER`；
3. 不动 `selfHash`，模拟"只知道改数据、不懂重算哈希"的攻击者；
4. 桌面端**不做任何操作**，等待自动巡检（每 30 秒一次）。

结果：30 秒内弹出阻断式告警窗口（见 `tools/evidence/shot_tamper_alert.png`）：

- 标题：**审计完整性告警**；
- 红框：「检测到审计日志被篡改——哈希链已在序号 308 处断裂」；
- 断裂序号 `308` / 所在分片 `AuditLogs_202609` / 检出方式 `自动巡检`；
- 断裂原因：「记录内容与签名不符：按当前字段重算的哈希与存储的 selfHash 不一致」；
- 哈希比对：重算值 vs 存储值并列展示；
- 底部「我知道了」为唯一出口，**遮罩点击不关闭，强制用户确认**。

告警本身也会入链（`AUDIT_TAMPERED`，`reasonCode=CHAIN_BROKEN`，`target=seq:308`），
形成"发现篡改"这件事也被追责的闭环。

> 补充：该告警弹窗是前端每 30 秒调一次校验接口触发的，
> 因此**即使攻击者只改数据库、完全不动程序**，也躲不过。

---

## 五、04 撑得住 · 增长测试

- **分片集合**：按月滚动 `AuditLogs_yyyyMM`（压测时可用 `AUDIT_SHARD_UNIT=count`
  切成每 N 条滚一片，几秒就能跑出真实轮转证据）。
- **链跨分片连续**：校验时跨全部片按 `seq` 升序拉取，分片边界不影响连续性。
- **真分页**：改造前是硬编码 `Limit(200)`，写多少都只能看最近 200 条；
  现在支持分页 + 关键字 + 动作 + 结果 + 分片筛选。
- **老数据宽容**：哈希链上线前的记录统一标记为 legacy 跳过，不误报为断裂。

实测（`tools/evidence/shot_audit_view.png`）：

- 完整性状态卡片 + 「立即校验」按钮；
- 统计：共 663 条 · 本页失败 24 条 · 第 1/14 页；
- 筛选器：搜索 / 全部操作 / 全部结果 / 当前分片；
- 表格列：序号 / 时间 / 操作者 / 动作 / 结果 / 前状态 / 后状态 / 请求·响应 / 详情。

接口实测：

```
GET /api/audit/verify
→ { "intact": true, "checked": 324, "legacySkipped": 0,
    "detail": "校验通过：324 条记录哈希链完整" }
```

---

## 六、桌面端运行验证

| 验证项 | 结果 |
|--------|------|
| 安装包安装 | ✅ `AuthBaseline_1.0.0_x64-setup.exe` |
| 启动后界面渲染 | ✅ 侧边栏 / 登录表单 / 状态栏正常（证据 `desktop_native.png`） |
| 登录 | ✅ admin 登录成功，仪表盘显示当前用户与角色 |
| 审计日志页 | ✅ 完整性卡片、筛选、分页、哈希链详情（证据 `shot_audit_view.png`） |
| 直接改库告警 | ✅ 30 秒内弹窗（证据 `shot_tamper_alert.png`） |
| 原有功能 | ✅ 注册 / 审核 / 解锁 / 改密 / 邮件验证码 均未受影响 |

### 渲染问题说明（已修复）

本机 WebView2 Runtime 为 `152.0.4191.66`，其**多进程 + GPU 合成**路径
在本环境渲染不出画面：窗口先是全白，随后转全黑，
但后端与前端实际都已正常加载（无头 Edge 加载 `wwwroot` 时 SPA 完整挂载）。

修复方式是在 `src-tauri/tauri.conf.json` 的窗口配置里增加：

```json
"additionalBrowserArgs": "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --single-process --disable-gpu"
```

注意：`additionalBrowserArgs` 会**替换**Tauri 的默认参数，
所以必须把原本的 `--disable-features=...` 一并带上，
否则会丢掉 Tauri 默认启用的几项安全/兼容开关。

---

## 七、证据文件清单

均在 `tools/evidence/`：

| 文件 | 内容 |
|------|------|
| `desktop_native.png` | 桌面端原生渲染正常（侧边栏 + 登录表单 + 状态栏） |
| `shot_login.png` | 登录页 |
| `shot_after_login.png` | 登录后仪表盘 |
| `shot_audit_view.png` | 审计日志页：完整性卡片 / 筛选 / 分页 / 哈希链详情 |
| `shot_tamper_alert.png` | **直接改库后弹出的阻断式篡改告警**（核心证据） |
| `shot_audit.png` | 早期审计页截图 |
| `desktop_login_early.png` | 早期桌面端截图 |
| `chain_backup_before_repair.json` | 修复链断裂前的完整链快照（322 条，备查） |

---

## 八、遗留问题处理记录

测试过程中，`tools/desktop_e2e.py` 的篡改演示脚本对
`AuditLogs_202609` 中 `seq=308` 的记录做了修改，
事后虽把 `action` 改回 `AUDIT_VERIFY`，但 `target` 字段被 `$unset` 删除后未恢复，
导致该条 `selfHash` 与当前内容不符，`/api/audit/verify` 报 `FirstBrokenSeq=308`。

处理（`tools/repair_chain.py`）：

1. 严格按 `AuditService.ComputeHash` 的字段顺序与时间格式复算，定位到**仅此一条**不自洽
   （其余 321 条全部自洽）；
2. 恢复该条被删除的 `target` 字段为同类型记录的标准值 `audit/verify`；
3. 恢复后重算哈希**恰好等于原存储值**，因此无需重签任何哈希，
   `seq=309` 之后的 `prevHash` 也天然对齐，**仅改动 1 条记录**；
4. 复检：322 条全部自洽；接口返回 `intact: true`。

修复脚本支持 `--dry-run`（默认干跑）与 `--apply`，
执行前自动把整链备份到 `tools/evidence/`。

---

## 九、回退方式

本次改动全部在一个提交内，回退一条命令：

```bash
git log --oneline -1        # 查看本次提交
git revert <commit>         # 或 git reset --hard <上一个提交>
```

数据库如需回退，用备份文件恢复对应集合即可。
