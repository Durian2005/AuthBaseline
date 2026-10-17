# 代码质量审计报告

> 审计日期：2026-10-05 ｜ 批次 0 整理与复验：2026-10-06
> 范围：`AuthServer/`（C#）、`AuthClient/src/`（Vue/JS）、`tools/`（Python）
> 本报告只记录**结论、证据与决策**；详细的逐条修复过程见 `.workbuddy/memory/2026-10-05.md`。

## 一、总体结论

**尚未成为"屎山"，但已出现 6 类变味信号。** 结构底子是好的，问题集中在"单文件过大"
与"工具链纪律不齐"两处，属于**在还清得起的时候还**的阶段。

规模基线：

| 部分 | 行数 | 文件数 |
|---|---|---|
| 后端 C# | 6,798 | 22 |
| 前端 Vue/JS/CSS | 8,354 | 29 |
| 工具链 Python | 8,376 | 41 |

集中度（**最需要警惕的指标**）：

- 后端 **26.7%** 的代码在 `AuthController.cs` 一个文件里
- 前端 **35.9%** 在 `UsersView.vue` / `session.js` / `LoginView.vue` 三个文件里
- 超过 500 行的文件共 **10 个**

### 已经做得好的（本次不动，勿回退）

1. **分层清晰**：后端 `Controllers / Services / Models`，前端 `api / stores / components / views / composables / utils`。
2. **审计码已收口**：`AuditLog.cs` 里 `ActorType` / `AuditResult` / `AuditAction` / `AuditReason` 四个静态类。
3. **构建产物零入库**：146 个受版本控制的文件里，`dll / exe / pdb / bin / obj / target / node_modules` **一个都没有**。
4. **守卫有自测**：`_probe_common_selftest.py` —— 安全设施自己可被验证，这是很多项目做不到的。

---

## 二、本次已修复

### P0 · 写库脚本的库名门禁（安全）

**问题**：12 个脚本硬编码 `AuthBaselineDb` 且不 import `_probe_common`，即绕过 10-05
事故后建立的库名守卫。其中三个**会写库**且完全没有保护：

| 脚本 | 问题的具体形态 |
|---|---|
| `audit_e2e_test.py` | 591 行、**16 处写操作**、`DB_NAME` 默认真实库、零保护。第 377–444 行**故意删掉审计分片文档再重插**来模拟篡改 —— 在 `delete_one` 与 `insert_one` 之间崩溃，就在哈希链上留下**无法局部修补的洞**。 |
| `desktop_e2e.py` | `tamper` 步骤直接改真实库里最新一条审计记录。 |
| `tamper_helper.py` | `restore` 子命令直接改写审计记录的 `action` / `target`。 |

**修复**：在 `_probe_common.py` 新增 `require_real_db_optin()`，并把上面三处接上。

**为什么新开一个函数而不是复用 `_guard()`** —— 两者语义相反，合并会两败俱伤：

| | `_guard()` | `require_real_db_optin()` |
|---|---|---|
| 面向 | 探针（打测试库） | 管理 / 验收脚本 |
| 真实库 | **一律硬拒** | 合法目标，但必须**显式确认** |
| 放行 | 环境变量逃生舱 | 命令行 `--i-know-this-is-the-real-db` |

探针打真实库 = **bug**（参数错位）；验收脚本打真实库 = **设计意图**。
同一条规则罩不住两种相反的意图。

**刻意保留不动**的：

- `db_survey.py` / `query_tamper_trace.py` / `verify_chain_independent.py` /
  `password_event_probe.py` —— **只读或只追加**，本就是为真实库设计的诊断工具，
  加门禁会让它们失去用途。
- `db_cleanup` / `db_restore` / `consolidate_shards` / `renumber_chain` / `repair_chain`
  —— 已有保护（`--i-know-this-is-the-real-db` 或 dry-run + `--apply`），
  且比通用门禁更严格（含备份核对），**合并会削弱保护**，故不合并。

**自测**：`_probe_common_selftest.py` 从 27 项扩到 **37 项**，新增 10 项覆盖新门禁
（含"近似开关不算数"、"开关夹在参数中间也要认"、"另一个真实库 `ecg_auth_db` 同样受保护"）。

### P0 附带 · 两个脚本 bug

1. **`tamper_helper.py verify` 假阳性**：只看 `data.intact` 的真假，
   于是**任何拿不到结论的响应**（403 / 502 / 空 body）都被打印成"链已断裂！"，
   且断裂字段全是 `None`。实测：库里只有 Admin 账号时，`/api/audit/verify` 恒返回
   403（职责分离），脚本却报"链已断裂"。**修**：区分"没有结论"与"结论是断裂"，
   并对 `NOT_AUDIT_ADMIN` 给出可操作的提示（改用审计管理员账号）。
2. **`verify_chain_independent.py` 在健康状态下崩溃**：第 104 行 `tampered[0]`
   在"无篡改告警"（**正常状态**）时 `IndexError`；第 129 行同一模式。
   **修**：两处都改为空列表安全分支。

### P2 · 业务码收口（消除重复 + 消除串号风险）

**问题**：业务响应码是散落的裸字符串 —— `INVALID_CREDENTIALS` ×7、`EMPTY_FIELDS` ×6、
`NOT_FOUND` ×5、`WEAK_PASSWORD` ×4 …… 而**审计码早已收口**，形成不对称。
更危险的是 `AuditReason.InvalidCredentials` 常量**存在**，业务侧却手打字面量 ——
而"业务 Code 与审计 reasonCode 是两套码、刻意不合并"是明确的设计红线，
手打字面量让这条红线的边界变得模糊。

**修复**：新建 `AuthServer/Models/BusinessCodes.cs`（`BusinessCode` 静态类，25 个常量），
替换 **77 处**字面量（`AuthController.cs` 74 + `AuditController.cs` 3）。

类的注释里写明了**为什么不能与审计码合并**（去向不同 / 用途不同 / 粒度不同），
把这条设计约束从"记忆"变成"代码里看得见的东西"。

**这是纯重构**：值完全不变（`Ok = "OK"`），C# 编译期保证符号正确，
`diff` 恰好 74 行、每行都是一对一替换。

### P2 · 轮询样板收口

**问题**：`session.js` 里 4 组 `start/stop` 轮询（8 个函数、约 99 行）逐字重复同一个模式：
`清理旧定时器 → 角色门禁 → visibilityState 检查 → setInterval`。

**修复**：新建 `AuthClient/src/composables/poller.js`（`createPoller` 工厂），
四处差异只剩「门禁 + 任务 + 周期」三个参数。

命名用 `createPoller` 而非 `usePoller`：`use*()` 的约定是依赖组件实例
（内部用 `onMounted`/`onUnmounted`），但这四处全挂在 **Pinia store 的 setup** 里，
store 只初始化一次、没有组件实例，`onUnmounted` 永不触发 —— 套 `use*()` 命名
只会误导读者以为"组件卸载会自动清理"。

**保守处理**：**保留 `startXxxPolling` / `stopXxxPolling` 公开 API 不变**
（`App.vue` 在 `onBeforeUnmount` 里调用它们），只把内部实现换成 8 个一行委托。
消除的是**重复的逻辑**，不是**公开契约**。

**新增回归测试 `tools/poller_test.mjs`（15 项）**：四个轮询点里有三个跑在
**审计管理员**角色下，而该账号的口令不在自动化脚本掌握范围内 —— 界面级验证覆盖不到。
所以直接对工厂函数做单元断言，把「门禁 / 可见性 / 重复启动 / 立即执行 / 错误吞没」
这些容易在重构中走样的语义固定下来。

### 本次新增/改动的文件

| 文件 | 性质 |
|---|---|
| `AuthServer/Models/BusinessCodes.cs` | 新增（业务码常量类） |
| `AuthClient/src/composables/poller.js` | 新增（轮询器工厂） |
| `tools/poller_test.mjs` | 新增（轮询器语义回归） |
| `tools/_probe_common.py` | 加 `require_real_db_optin()` |
| `tools/_probe_common_selftest.py` | 27 → 37 项 |
| `tools/audit_e2e_test.py` | 接门禁 |
| `tools/desktop_e2e.py` | 接门禁（仅 `tamper` 步骤） |
| `tools/tamper_helper.py` | 接门禁（仅 `restore`）+ 修假阳性 |
| `tools/verify_chain_independent.py` | 修 2 处空列表崩溃 |
| `AuthServer/Controllers/AuthController.cs` | 74 处业务码字面量替换 |
| `AuthServer/Controllers/AuditController.cs` | 3 处业务码字面量替换 |
| `AuthClient/src/stores/session.js` | 轮询逻辑换成工厂 |

---

## 三、整理路线与状态

四项待办按「**谁是别人的安全网**」排序，分三批推进：**先织网 → 再动刀 → 最后扫地**。

| 批次 | 内容 | 状态 |
|---|---|---|
| 0 · 织网 | 前端 linter / tools 分类与证据归档 / 行尾与属性统一 | ✅ 2026-10-06 完成 |
| 1 · 动刀 | God 文件拆分（先抽 AuditWriter，再拆 Controller / store / 模板） | ⏳ 待排期 |
| 2 · 扫地 | README 索引 + 根目录 md 归档 / 构建产物副本收敛 | ⏳ 待排期 |

### 批次 0 已完成（2026-10-06）

**1. 前端 linter**

引入 ESLint 10 + eslint-plugin-vue 10（扁平配置），**只开"真 bug 类"规则**，
不引风格规则 —— 规则取舍与理由写在 `AuthClient/eslint.config.js` 顶部。新增 `npm run lint`。

- 首跑基线：**0 error / 3 warning**（三条都是 `no-unused-vars`）。
- 顺手清掉两条**已确认是死绑定**的告警（`App.vue` 里未使用的 toast store、
  `PasswordField.vue` 里未使用的 `props` 对象），基线降到 **0 error / 1 warning**。
  两者的安全性都做了核实：toast store 无 setup 副作用且 `ToastHost.vue` 自己会实例化；
  `PasswordField.vue` 全文无 `props.` 引用。
- ⚠️ **剩下那 1 条不是噪声，是真缺陷**：`UsersView.vue` 的 `canFreeze()`
  定义了、写了注释、却**从未被调用** —— 沉睡账号表的「冻结」按钮（模板 ~598 行）
  **没接权限门禁**，而「解除冻结」按钮（~641 行）有 `canUnfreeze(u)`。
  后端仍会拦（因此**不是越权漏洞**），但界面会给出一个必然被拒的按钮，
  与该函数自己的注释（"前端隐藏按钮只是提前告知"）相矛盾。
  **待决策**：接上门禁（1 行）或维持现状。

**2. tools/ 分类与证据归档**

新增 `tools/README.md`：把 46 个条目按用途分为 8 类（公共层 / 探针 / 端到端验收 /
界面检查 / 库管理 / 只读诊断 / 构建打包 / 进程诊断 / 一次性遗留），
逐条标注「是否走公共层」「是否打真实库」「门禁形式」「是否属回归套件」，并写明三条铁律。

- 18 张散落截图归入 `tools/evidence/`；4 个产出脚本的默认输出目录同步改为 `tools/evidence/`。
- **未搬迁脚本的物理位置** —— 移动目录会破坏脚本间的相对引用和既有文档链接，收益不抵风险；
  分类用索引而非目录来实现。

**3. 行尾与属性统一 —— 本报告 2026-10-05 的判断有误，在此更正**

原文写"建议加 `.gitattributes` 统一"，但 **`.gitattributes` 早已存在**（提交 `fc1eed7`
「chore(仓库卫生)…统一行尾符」），且内容正确：`* text=auto eol=lf` + bat/cmd 放行 + 二进制清单。
实测 `git ls-files --eol`：索引内 **146 个文件全部为 LF**，
29 个工作区 CRLF 文件**零 diff 噪声**（`git diff AuthServer/Program.cs` 为空）。
原判断是把"工作区字节是 CRLF"误当成"仓库没统一"。

真正缺的只有一处：**`.icns` 未显式声明为二进制**（git 靠启发式判对了，但行为不应依赖启发式），已补。
另补 `.dpapi` / `.pfx` / `.p12` 的二进制声明，作为"误 `git add` 凭据文件"时的护栏。改动后无任何文件被重判。

### 批次 1 待办 · P1 · God 文件（10 个超 500 行）

| 文件 | 行数 | 主要问题 |
|---|---|---|
| `AuthController.cs` | **1,818** | 16 路由 + 16 私有方法 + **78 处 `WriteAuditLogAsync`**；5 个方法 >100 行（`Login` 184 / `SetRole` 132 / `SendEmailCode` 129 / `ResetPassword` 113 / `Register` 107） |
| `UsersView.vue` | 1,119 | `template` 独占 567 行 |
| `session.js` | 941 | 40+ 函数挤一个 store（认证/用户/审计/分片/完整性/越权告警/沉睡/轮询） |
| `LoginView.vue` | 940 | `template` 439 行 |
| `AuditView.vue` | 854 | |
| `CertificateManager.cs` | 665 | |
| `AuditService.cs` | 600 | |
| `tools/audit_e2e_test.py` | 591 | |
| `DashboardView.vue` | 517 | |
| `tools/pepper_probe.py` | 504 | |

**建议的拆分方向**（按收益排序）：

1. `AuthController` 按**领域**拆：`AuthController`（登录/注册/登出/改密）、
   `AccountAdminController`（approve / unlock / freeze / delete / create / set-role）、
   `UserQueryController`（users / dormant-users）。78 处审计写入可收进一个
   `AuditScope` 辅助对象，把"权限校验 + 写审计 + 构造响应"这三件总是一起出现的事打包。
2. `session.js` 按**角色域**拆：`useAuthStore`（会话/票据/传输）、`useAdminStore`（用户管理）、
   `useAuditStore`（审计/完整性/越权）、`useDormantStore`。
3. `UsersView.vue` / `LoginView.vue` 的 `template` 抽子组件（用户表格行、待审核卡片、
   沉睡卡片、登录表单分组）。

### 批次 2 待办 · P2 · 工具链收口（分类已完成，收口待做）

分类已落地（`tools/README.md`）；**收口未做**：

- 仍未走 `_probe_common` 的活跃脚本：`cs_connect_check.py` / `cs_process_check.py` /
  `run_audit_e2e.py` / `email_e2e_test.py` / `verify_email.py`。
- 一次性遗留（`tools/README.md` H 组）：`verify_api.py` / `diag_api.py`。
  两者硬编码 `admin/Admin123` 且不接库名门禁 —— 若继续保留至少补门禁；
  若确认不再使用则归档（**归档前需先确认无人引用**）。
- ⚠️ **收口时必须守住的边界**：
  ① 两套库名规则（探针硬拒真实库 / 验收脚本显式确认）**不得合并**；
  ② 管理脚本的自有保护（备份核对、dry-run + `--apply`）**不得被通用门禁替换** —— 那会削弱保护；
  ③ 测 TLS 的脚本**不能**改用 `start_backend`（它硬编码 `http://` 且强制注入库名）。

### 批次 2 待办 · P3 · 零散整洁度

- **根目录 9 个 `.md` 平铺**（设计稿 + 报告 + README 混放）→ 归入 `docs/`，
  但**必须在 README 索引写完之后**，否则全文引用一起断。
- **`appsettings.Local.json` 12 份副本**（含 `publish/publish` 嵌套与 `src-tauri/target`）。
  实测 `git check-ignore`：**12 份全部被忽略**，被跟踪的只有 `AuthServer/appsettings.json`
  ⇒ 这是**磁盘占用与认知噪音，不是入库泄露风险**（原报告写"9 份"也已过时）。
  根因是构建输出布局乱了（出现了 `publish/publish/publish` 这种嵌套），**修布局比删副本有用**；
  且 `AuthServer/publish/AuthServer.exe` 是与安装版 md5 一致的**正品**，别误删。
- 后端「密码必须至少8位」与前端「至少 8 位」空格不统一（`AuthController.cs` 4 处）。
  属**用户可见文案**，改动会影响演示截图 ⇒ 先不动。

---

## 四、验证记录

| 检查项 | 结果 |
|---|---|
| C# 编译 | 0 警告 / 0 错误 |
| ESLint（全量 `src` + 配置） | **0 error / 1 warning**（该 1 条是 `canFreeze` 真缺陷，见 §三） |
| 前端构建（两套产物） | 一致，逐字节相同 |
| 守卫自测 | **37 / 37** |
| 轮询器语义 | **15 / 15** |
| 角色分离 | **79 / 79** |
| 锁定时钟 | **25 / 25** |
| 票据哈希 | **27 / 27** |
| pepper | **45 / 45** |
| 僵尸账号治理 | **37 / 37** |
| 生产态 HTTPS 接口回归 | 9 / 9 |
| 界面级 TLS 验证（CDP） | 10 / 10 |
| 独立复算哈希链 | 链完整（51 条），链尾 == 锚点 |
| 测试库残留 | 无 |
| 桌面端重装 md5 核验 | 一致 |

> 回归套件对**改后重打包**的产物执行，不是只测源码。

### 批次 0 改动文件（2026-10-06）

| 文件 | 性质 |
|---|---|
| `AuthClient/eslint.config.js` | 新增（ESLint 扁平配置，含规则取舍理由） |
| `AuthClient/package.json` | 加 `lint` 脚本与 3 个 devDependencies |
| `AuthClient/package-lock.json` | 依赖锁定更新 |
| `AuthClient/src/App.vue` | 删除未使用的 toast store 绑定与 import |
| `AuthClient/src/components/PasswordField.vue` | 删除未使用的 `props` 绑定 |
| `tools/README.md` | 新增（46 个条目的分类索引 + 三条铁律） |
| `tools/ui_tls_check.py`、`ui_audit_check.py`、`ui_readonly_check.py` | 截图目录 → `tools/evidence/` |
| `tools/ui_tls_events.mjs`、`ui_audit_events.mjs`、`ui_readonly_events.mjs` | 同上（默认值） |
| `tools/desktop_e2e.py`、`desktop_shot.py` | 截图默认路径 → `tools/evidence/` |
| `.gitattributes` | 补 `.icns` / `.dpapi` / `.pfx` / `.p12` 二进制声明 |
| `tools/evidence/`（不入库） | 18 张散落截图归入 |

⚠️ **桌面安装版的前端产物已落后于源码**：批次 0 改了 `App.vue` / `PasswordField.vue`
并重新构建（两套产物已同步），但安装目录里的 `wwwroot` 仍是上一版。
行为上无差异（动的都是死代码），要让安装版一致需重跑 `reinstall_desktop.py`。

---

## 五、P1 · 测试与 CI（2026-10-17）

P0 的两项（pepper 导入演练、SoD 绕过检测层）落地后，P1 剩下的三件事都是**质量与回归**。
它们的共同点是：**不改产品行为**，只在"改动会不会悄悄弄坏别的东西"这一层加护栏。

| 编号 | 内容 | 状态 |
|---|---|---|
| P1-4 | 后端纯逻辑单测（TimeGuard / PasswordHasher / FacePose） | ✅ **81 项**，1 秒跑完 |
| P1-3 | GitHub Actions 门禁（编译 / 单测 / lint / 脱敏 / 产物布局） | ✅ 4 个 job |
| P1-5 | 人脸动作挑战的帧录制与离线回放 | ✅ 通道打通 + **真实转头样本已录**（3/3 对账一致） |

### P1-4 · 纯逻辑单测（杠杆最高的一件）

**核心逻辑过去只能靠"起后端打 HTTP"来验**：`TimeGuard` 的 40 项断言、`PasswordHasher`
的 45 项、`FacePose` 的阈值行为，全挂在 `tools/` 的探针里。探针证明的是"整条链路在真实
后端上确实这样表现"，但它慢、要 Mongo、要 Windows，而且**造不出某些输入** ——
比如"墙钟恰好比单调线快 2 秒"这种精确落在容差边界上的场景，真实拨钟永远拨不出来。

新增 `AuthServer.Tests`（xUnit，**81 项**）把判定语义固化成单测：

| 文件 | 覆盖 | 关键断言 |
|---|---|---|
| `TimeGuardTests.cs`（25） | 锁定到期、失败计数窗口、窗口背离取证 | 前拨 600 秒仍锁定且剩余按单调线算；回拨不把锁定拖长；容差 2 秒的**确定性**边界；重启后锚点失效这条边界**也写成断言**（不靠注释承诺） |
| `PasswordHasherTests.cs`（26） | `v2$` 写入/验证、旧格式兼容、脏数据容错 | ★ `v2$` 且缺 pepper ⇒ 一律不通过（绝不回退旧格式）；★ 超过 72 字节仍能区分口令（HMAC 预处理的意义）；坏哈希返回 false 而不是 500 |
| `FacePoseTests.cs`（30） | 阈值边界、动作池、指标归一化、常量不变量 | ★ 动作池恰好 left/right（pitch 动作已下线的取舍记录在测试里）；★ 未知动作即便偏移巨大也判不满足；★ 画面放大 2 倍 yaw/pitch 不变；`HitNeeded ≤ HitWindow` 等常量不变量 |

**三个刻意的决定**：

1. **测试项目用 `net8.0-windows`，不用 `NoWarn` 压警告。**
   `AuthServer` 在 `Program.cs` 顶部整体声明了 `[assembly: SupportedOSPlatform("windows")]`
   （DPAPI / OpenCvSharp 都是 Windows 专属）。引用它的项目若写纯 `net8.0`，编译器会对每个
   类型引用喷 CA1416（实测 20+ 条）；`NoWarn` 掉会把真正的跨平台误用一起遮住。
   产品本来就只发 win-x64，测试也不该假装能跑在 Linux 上。
2. **只测不碰 IO 的东西。** 单测不连库、不碰摄像头、不需要证书。需要 IO 的那些
   （锁定链路、审计哈希链、人脸端到端）继续由 `tools/` 的探针负责 ——
   一旦掺进来，`dotnet test` 就会变成"起服务"的隐式前置。
3. **引用产品项目，不复制逻辑。** 测的必须是"将要发布的那份代码"，否则改产品时测试不会拦。

### P1-3 · CI 门禁

新增 `.github/workflows/ci.yml`，四个 job：

| job | 跑什么 | 为什么是它 |
|---|---|---|
| `backend` | `dotnet build AuthBaseline.sln -c Release` + `dotnet test` | 编译与单测是所有其它检查的前置 |
| `frontend` | `npm ci` + `eslint --max-warnings 0` + `vite build` | 用 `ci` 而不是 `install`：lock 与 package.json 不一致时直接失败 |
| `privacy` | `privacy_scan.py --no-history --gate` | 防"以后误提交本机路径/凭据" |
| `publish-layout` | `dotnet publish` + `verify_publish_layout.py` | 防"单文件打包器把 face-models 吞掉" |

**为什么不全搬进去**：仓库里 21 个探针大多需要 **MongoDB + 真实后端 + Windows 桌面壳**，
跑一次十几分钟且会写库。搬进 CI 只会得到一条常年超时抖动的流水线 ——
**红着的门禁等于没有门禁**，所有人都会学会忽略它。需要真库/真机的那部分，仍然是发布前手动跑。

**为了让它能当门禁，改了两处工具**：

- `privacy_scan.py` 原来**永远退出 0**（它是给人看的报告）。新增 `--gate`：只对
  `tools/privacy_baseline.json` 之外的新增命中失败。基线里 11 条都是逐条核实过的
  （上游协议署名邮箱、图标名被邮箱正则误判、Cargo.lock 的 checksum 里 11 位数字等），
  每条都写了 `reason`；**数字变大同样算新增**；条目不再命中只告警（stale）。
  要求"零命中"的话门禁会永久红着 —— 那是假装严格，实际是关掉门禁。
- 新增 `tools/verify_publish_layout.py`：CI 版的产物布局校验。
  判据是"face-models 目录齐全且非空 **且** exe 里找不到这些文件名"。
  这条守的是构建配置回归 —— 它坏掉时程序照常启动，只有已录人脸的账号全部 fail closed，
  症状离原因极远。完整的 14 项 + 内嵌 93 项仍由 `face_release_probe.py` 在发布前跑。

**刻意不做的一件事**：CI 里不扫 git 历史。CI 是浅克隆（`fetch-depth: 1`）扫不到；
而且历史内容不随本次 PR 变化，完整历史扫描留在发布前手动跑（它本身要几分钟）。

### P1-5 · 人脸动作挑战的帧回放

这是三件里唯一"过去完全做不到"的：动作挑战的判定（求基线 → 等转头 → 等回正 → 从回正帧提特征）
只有在真实画面上才有意义，于是**每次动阈值都要把人叫到摄像头前重看一遍**，
而且当时发生了什么只能靠一句 `Diagnostic` 字符串猜。

补了一条离线通道（**不增加任何对外路由**，接口仍是 28 条）：

| 入口 | 作用 |
|---|---|
| `authserver.exe --face-record <目录> <left\|right>` | 录一次：每帧写 JPEG + `manifest.json`（含期望结论） |
| `authserver.exe --face-replay <目录>` | 离线重放，输出 `FACE_REPLAY_RESULT={...}` |
| `python tools/face_fixture_check.py <exe>` | 批量回放并与期望值对账 |

**为什么回放可信**：它**只换采集源**（`ReadRaw` 里从摄像头换成图片目录），不换判定 ——
`RunChallenge` 的同一段代码照跑，YuNet 检测、SFace 特征、采样节奏、跳变与回正判定全都在。
两个实现细节各对应一个坑：

- **帧序按文件名 Ordinal 排序**：文件系统返回顺序不保证稳定，帧序一乱时序就毁了。
- **帧放完保持最后一帧**，而不是返回 null。真实摄像头不会"没有下一帧"，它只会一直送同一幅画面。
  若返回 null，上层会走"读不到帧"→10 次 miss→`FACE_NO_FACE`；而真实情形该报
  `FACE_LIVENESS_FAILED`。**这两者的区别正是"照片能不能过活体"这个结论本身**。

已跑通的样例（本地，fixture 不入库）：

| fixture | 输入 | 录制时结论 | 回放复现 |
|---|---|---|---|
| `_smoke` | 8 张界面截图（画面里没有人脸） | `FACE_NO_FACE`，samples 0 | ✓ 一致 |
| `_static` | 同一张人脸照片重复 12 帧（"拿照片对着摄像头"） | `FACE_LIVENESS_FAILED`，动作始终未成立 | ✓ 一致 |
| `left-ok` | **真人向左转头再回正**，46 帧（10-17 录制） | `passed=true`，yaw −0.06…+4.58、actionSeen | ✓ 一致（yaw −0.06…+4.70） |

`_static` 是可复现的**防照片重放**证据：不必每次拿张照片对着摄像头试。
`left-ok` 是**正向黄金样本**：真实动作必须过，而且回放要在同一份判定代码上复现同一个结论。

**顺带做的一次反向验证**（不改代码、只改要求的方向）：把 `left-ok` 的 46 帧原样喂给
`--face-replay`，但把 manifest 的 `action` 改成 `right` —— 结果 `FACE_LIVENESS_FAILED`、
`actionSeen False`，而 yaw 范围依旧是 −0.06…+4.70。

这条比"成功样本复现了成功"更有力：它说明判定看的是**方向**，不是"画面里有没有发生过位移"。
否则一个"动一下就放行"的判定也会让 `left-ok` 通过，那样这个 fixture 就什么都证明不了。

`left-ok` 那一次的真实数据也说明了阈值余量：`YawTurn=0.13` 是"明显转头"的门槛，
而这次实测 yaw 摆到 **+4.58**（基线 −0.01）—— 量级上差三十多倍，不是压在阈值边缘过的。
反过来说，如果哪次"人几乎没动"也判过，那就该回头查阈值了（本次没有出现）。

**口径**：它证明"同一段画面 → 同一结论"，不证明"当时坐在这儿的是本人"；
也不覆盖跨设备/跨光照的稳定性。

### 本次验证记录

| 检查项 | 结果 |
|---|---|
| `dotnet build AuthBaseline.sln -c Release` | 0 错误（仅 1 条 OpenCvSharp 自带分析器的 CS9057，与本仓库代码无关） |
| `dotnet test`（Release，CI 同参数） | **81 / 81**，1 秒 |
| `npm run lint` | 0 error / 0 warning |
| `privacy_scan.py --no-history --gate` | 通过（11 条基线命中，0 条新增）；另用一条假手机号验证过**会红** |
| `verify_publish_layout.py`（对现有 `AuthServer/publish`） | 7 / 7 通过 |
| `dotnet publish` + 布局校验（模拟 CI） | 7 / 7 通过 |
| `face_fixture_check.py` | 2 / 2 fixture 结论一致 |
| `face_second_factor_probe.py`（回归，stub 引擎） | **93 / 93**，无副作用（测试库已清理） |

### 本次新增/改动文件

| 文件 | 性质 |
|---|---|
| `AuthServer.Tests/`（csproj + 3 个测试文件） | 新增（81 项单测） |
| `.github/workflows/ci.yml` | 新增（4 个 job） |
| `tools/privacy_baseline.json` | 新增（11 条已核实的命中，逐条带 reason） |
| `tools/verify_publish_layout.py` | 新增（CI 版产物布局校验） |
| `tools/face_fixture_check.py` | 新增（帧回放对账） |
| `AuthServer/Services/Face/FaceFixtureCli.cs` | 新增（`--face-record` / `--face-replay`） |
| `AuthServer/Services/Face/FaceOptions.cs` | 加 `ReplayDir` / `RecordDir`（含环境变量覆盖） |
| `AuthServer/Services/Face/CvFaceEngine.cs` | 只改采集入口：回放读目录、录制落盘；**判定逻辑一行未动** |
| `AuthServer/Program.cs` | 子命令分支（早于 `CreateBuilder`，与 pepper 同位置） |
| `tools/privacy_scan.py` | 加 `--gate` 与基线机制；`main()` 改为返回退出码 |
| `.gitignore` | 加 `publish_ci/`、`tools/fixtures/` |
| `AuthBaseline.sln` | 加入测试项目 |
| `README.md`、`docs/design/FACE-AUTH-DESIGN.md`、`tools/README.md` | 文档同步 |
