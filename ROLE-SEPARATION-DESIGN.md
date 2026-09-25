# 角色分离（职责分离）改造方案

> 目标：把"管理员"这一个笼统身份，拆成**互斥**的三类角色，实现
> **管账号的人看不到日志、看日志的人管不了账号**。
>
> 状态：**已实现并部署**（2026-09-20）。本文档已按最终落地形态校正，
> 方案阶段的 `SuperAdmin` 命名在实际实现中统一为 `Admin`，
> 并新增 `UserAdmin` 一级，见文末「修订记录」。

---

## 一、需求（来自用户）

1. `admin` 管理员账号**不能查看日志**
2. `admin` 可以**创建和管理数个新的管理员账号**
3. `admin` 可以**指定几位管理员为审计管理员**
4. **只有审计管理员**可以查看日志
5. 由 `admin` 创建的管理员账号**不需要绑定邮箱**，只需口令

已确认的四个关键决策：

| 决策点 | 选择 |
|---|---|
| 审计管理员与普通管理员的关系 | **互斥** —— 审计管理员只能看日志，不能管理任何账号 |
| `admin` 能否被授予审计权限 | **永久禁止** —— 硬性限制 |
| `admin` 新建管理员的权限级别 | **低于 `admin`** —— 只能管普通用户 |
| "不能查看日志"的范围 | **全部审计接口** —— logs / verify / shards / stats 全部禁止 |

---

## 二、现状

| 项 | 现状 |
|---|---|
| 权限模型 | `User.IsAdmin` 单个布尔位，无角色层次 |
| 现有账号 | 库里**只有 `admin` 一条**（`IsAdmin=true`，本就无邮箱，`EmailVerified=false`） |
| 审计接口鉴权 | `AuditController` 的 `verify` / `shards` / `logs` / `stats`，加 `AuthController.GetLogs`，全部 `requireAdmin: true` |
| 创建账号能力 | **不存在**。管理员只能"审核待注册用户 / 解锁 / 删除 / 转让权限" |
| 注册流程 | `Email.Enabled=true`，邮箱+验证码必填，建号后 `Pending` 待审核 |
| 前端菜单 | `session.isAdmin` 同时决定「用户管理」与「审计日志」两个入口 |
| 定时器 | 20 秒管理数据轮询、30 秒完整性巡检、10 秒越权巡检，全部挂 `isAdmin` |

---

## 三、角色模型

### 3.1 用单一枚举，不用两个布尔位

```csharp
public enum UserRole
{
    User       = 0,  // 普通用户（自助注册，需邮箱验证，待审核）
    Admin      = 1,  // 管理员：管账号 + 任免角色，看不到审计日志
    UserAdmin  = 2,  // 用户管理员：由管理员创建，管账号但不能任免角色
    AuditAdmin = 3   // 审计管理员：只读审计，不碰账号
}
```

**为什么是枚举而不是 `IsAdmin + IsAuditAdmin` 两个布尔位**：

两个布尔位能表达 `IsAdmin=true 且 IsAuditAdmin=true` 这种"兼任"组合，
而需求明确要求互斥。用枚举后，**"管理员兼任审计员"在数据结构上就无法表达**，
不需要靠额外的校验去堵 —— 非法状态不可表示，比事后检查更可靠。

同时，"`admin` 不能被授予审计权"也因此获得了**结构性保证**：
看日志要求 `Role == AuditAdmin`，而 `admin` 的 `Role` 是 `Admin`。
除非把他的角色改成 `AuditAdmin`（他就丢掉了管理员身份），否则永远看不到日志。

### 3.2 权限矩阵

| 能力 | User | UserAdmin | Admin<br>`admin` | AuditAdmin |
|---|:---:|:---:|:---:|:---:|
| 登录 / 修改自己的口令 | ✅ | ✅ | ✅ | ✅ |
| 审核待注册用户 | ❌ | ✅ | ✅ | ❌ |
| 查看用户列表 | ❌ | ✅ | ✅ | ❌ |
| 解锁 | ❌ | ✅ | ✅ | ❌ |
| 注销**普通用户** | ❌ | ✅ | ✅ | ❌ |
| 创建管理员 / 审计管理员 | ❌ | ❌ | ✅ | ❌ |
| 变更他人角色（任命审计员） | ❌ | ❌ | ✅ | ❌ |
| 注销**用户管理员 / 审计管理员 / 其它管理员** | ❌ | ❌ | ✅ | ❌ |
| 查看审计日志 `logs` | ❌ | ❌ | **❌ 硬禁止** | ✅ |
| 完整性校验 `verify` | ❌ | ❌ | **❌ 硬禁止** | ✅ |
| 分片清单 `shards` / 统计 `stats` | ❌ | ❌ | **❌ 硬禁止** | ✅ |

一眼可见的职责分离：**Admin 那一列在审计区全是 ❌，AuditAdmin 那一列在管理区全是 ❌。**

**处置范围单独说**，它和"能不能管用户"不是一回事：

| 操作者 | 可处置（注销 / 变更角色）的目标范围 |
|---|---|
| `Admin` | 除**自己**以外的任意账号 —— 含用户管理员、审计管理员、其它管理员 |
| `UserAdmin` | 只有普通用户与用户管理员；够不到审计管理员与管理员 |
| 所有角色 | 一律**不能处置自己** |

自我豁免这条约束不只是惯例，它是安全性的支柱：
操作者必然是管理员，而"不能处置自己"保证他操作完仍然是管理员 ⇒
**系统里恒有至少一个能任命角色的账号**，永远不会有权力真空。

### 3.3 不可动摇的约束

1. **不能把自己设为任何其它角色** —— 防止"把自己改成 AuditAdmin 去看日志"，
   也防止系统失去能任免角色的账号。
2. **不能把任何账号设为 `Admin`** —— 管理员不可通过程序自我复制，
   杜绝"凭空多出一个管理员来稀释责任"。
3. **AuditAdmin 与 Admin 互斥** —— 由枚举保证。
4. **审计权限不由管理员持有** —— 判定条件是 `Role == AuditAdmin`，
   管理员在结构上就不满足，而不是被某处 if 拦下。

---

## 四、后端改动

### 4.1 数据模型

`User` 增加一个字段，`IsAdmin` 退化为派生值：

```csharp
[BsonElement("role")]
[BsonRepresentation(BsonType.String)]
public UserRole Role { get; set; } = UserRole.User;
```

原来的 `isAdmin` 字段**保留在库里不删**（审计要追溯历史状态），但代码侧不再读写它 ——
统一走 `Role`。启动时做一次性回填：

- 库里 `isAdmin == true` 且无 `role` 字段的账号 → `role = Admin`
- 其余无 `role` 字段的账号 → `role = User`

**判断"有无 role 字段"必须下沉到 BSON 层**（`Exists("role", false)`）：
MongoDB 驱动对**缺失的枚举字段**反序列化时会取默认值 `0`（即 `User`），
所以在 C# 侧根本分不清"这条记录真的是普通用户"和"这条记录压根没有 role 字段"，
照 C# 判断会把所有老管理员降级成普通用户。

**本机迁移风险为零**：库里只有 `admin` 一条记录，回填结果就是 `admin → Admin`。

### 4.2 鉴权层

`SessionService.ValidateAsync` 现在只有 `bool requireAdmin` 一个开关，无法表达四种门槛。
改为传访问级别：

```csharp
public enum AccessLevel
{
    Authenticated,  // 只要登录
    UserAdmin,      // Admin 或 UserAdmin
    Admin,          // 仅 Admin
    AuditRead       // 仅 AuditAdmin
}
```

`ValidateAsync(ticket, AccessLevel)` 依旧**每次实时查库**取当前角色（不信票据快照），
这样角色被变更后旧票据立刻失效。新增拒绝原因码：

- `NOT_ADMIN` —— 已有，非管理员
- `NOT_AUDIT_ADMIN` —— 新增，有管理员身份但无审计权（用于区分"完全没权限"和"权限不够看日志"）
- `FORBIDDEN_ROLE` —— 新增，试图把自己或他人提权到越界角色

### 4.3 接口清单

**新增 2 个**（`AuthController`，均仅 `Admin` 可调、均需二次口令校验、均写审计链）：

| 接口 | 入参 | 行为 |
|---|---|---|
| `POST /api/auth/create-account` | `username` `password` `role` `operatorPassword` | 创建 `UserAdmin` 或 `AuditAdmin`。**不绑邮箱**（`Email=null`），状态**直接 `Enabled`** 免审核，口令复杂度沿用现有规则，用户名查重 |
| `POST /api/auth/set-role` | `username` `role` `operatorPassword` | 变更他人角色（`User` / `UserAdmin` / `AuditAdmin` 三选一，**不接受 `Admin`**）。变更后**吊销目标账号全部票据**，强制重新登录 |

> `set-role` 同时覆盖了需求里"指定几位管理员为审计管理员"（`UserAdmin → AuditAdmin`）
> 和反向操作（`AuditAdmin → UserAdmin`、`→ User`），一个接口够用。

**改造 5 个**：

| 接口 | 原门槛 | 新门槛 |
|---|---|---|
| `GET /api/audit/logs` | `requireAdmin` | `AuditRead` |
| `GET /api/audit/verify` | `requireAdmin` | `AuditRead` |
| `GET /api/audit/shards` | `requireAdmin` | `AuditRead` |
| `GET /api/audit/stats` | `requireAdmin` | `AuditRead` |
| `GET /api/auth/logs`（遗留接口） | `requireAdmin` | `AuditRead` |

其余管理类接口（`approve` / `unlock` / `delete-user`）门槛从 `requireAdmin` 换成 `UserAdmin`，
可处置范围则按**操作者身份**区分（判定集中在 `UserRoles.CanBeManagedBy`）：

- `Admin` —— 除自己以外任意账号，含用户管理员、审计管理员、其它管理员；
- `UserAdmin` —— 只有普通用户与用户管理员，够不到审计管理员与管理员；
- 所有角色 —— 一律不能处置自己（`FORBIDDEN_TARGET`）。

> 审慎之处在于：**不能处置自己**这一条同时顶掉了"管理员互相删除导致权力真空"的担忧 ——
> 操作者必是管理员，且操作后仍是他自己，所以系统里恒有至少一个能任命角色的账号。
> 与其逐个限制目标角色，不如给操作者加一条自我豁免，规则更少、也更牢。

### 4.4 `transfer-admin` 的处理

现有 `POST /api/auth/transfer-admin` 的语义是：**现任管理员把权限转给别人，自己降为普通用户**。

这与新模型**根本冲突**：

- "把某人设为管理员"已经被 `set-role` 覆盖，且不需要操作者自降身份；
- 但 `set-role` 又明确禁止把账号设为 `Admin`（不可自我复制），
  于是"交出管理员身份"这条路径整体不再需要 —— 管理员可以处置除自己以外的任何账号，
  不需要靠转移身份来腾位置。

**已废弃 `transfer-admin`。** 前端入口移除，后端接口一并删除。

### 4.5 审计留痕

新增动作（全部走现有哈希链，不可篡改）：

| 动作 | 触发时机 |
|---|---|
| `CREATE_ACCOUNT` | 创建管理员 / 审计管理员（含目标角色） |
| `SET_ROLE` | 角色变更（`statusBefore` / `statusAfter` 记角色名） |
| `DELETE_USER` | 注销账号（成功与被拒都记；越级尝试带 `reasonCode=FORBIDDEN_TARGET`，可单独筛出） |

`AUDIT_ACCESS_DENIED` 沿用现有逻辑 —— Admin 或普通用户试图访问审计接口时，
既返回 403，也留下"谁在什么时候试图看过日志"的记录。

---

## 五、前端改动

### 5.1 状态与菜单

`session.js` 增加派生属性：

```js
const role         = computed(() => state.role)
const isAdmin      = computed(() => ['Admin','UserAdmin'].includes(role.value))  // 能管用户
const isRoleAdmin  = computed(() => role.value === 'Admin')                      // 能任免角色
const isAuditAdmin = computed(() => role.value === 'AuditAdmin')                 // 能看审计
const roleLabel    = computed(() => ROLE_LABELS[role.value])
```

`App.vue` 导航拆开：

| 菜单 | 显示条件 |
|---|---|
| 仪表盘 / 账号与口令 | 所有登录用户 |
| 用户管理 | `isAdmin` |
| 审计日志 | `isAuditAdmin` |

### 5.2 定时器必须重新挂载（重点）

这是**最容易漏掉、后果最脏**的一处。当前三个定时器全部挂在 `isAdmin` 上：

| 定时器 | 周期 | 调用的接口 | 应改为 |
|---|---|---|---|
| 管理数据轮询 | 20s | `users` + `logs` + `shards` + `stats` | **拆成两条**：用户轮询挂 `isAdmin`，审计轮询挂 `isAuditAdmin` |
| 完整性巡检 | 30s | `audit/verify` | `isAuditAdmin` |
| 越权巡检 | 10s | `audit/stats` | `isAuditAdmin` |

**若不改**：`admin` 登录后会每 30 秒拿着一张没有审计权的票据去撞 `verify`，
后端每次都返回 403、每次都写一条 `AUDIT_ACCESS_DENIED`。结果是
**审计链被自己的假告警灌满**，验收时打开日志会看到成百条"越权访问被拒"。

### 5.3 用户管理页

- 顶部加「新建账号」入口，弹窗内选角色（用户管理员 / 审计管理员）+ 用户名 + 初始口令
  + 操作者本人的口令（二次确认），并附带"无需邮箱、创建后即可登录"的说明
- 账号列表每行加**角色标签**与「变更角色」操作，**仅 `isRoleAdmin` 可见**
- 操作列按可处置范围显隐：「注销」对 `Admin` 是**除自己外全开**（含审计管理员），
  对 `UserAdmin` 只对普通用户 / 用户管理员显示；自己那一行显示「受保护」且无按钮
- 注销确认框对管理员 / 审计管理员给出**升级的风险提示**（会带走角色任免能力或审计独立性）

### 5.4 仪表盘与侧边栏

- 侧边栏显示当前角色徽章（`管理员` / `超管` / `审计`）
- `DashboardView` 对审计管理员降级显示：不展示用户统计与待审核数量
  （那些数据来自管理员接口，他拿不到）

---

## 六、验收要点

改造完成后可以现场演示的四条对比：

| 演示动作 | 期望结果 |
|---|---|
| 用 `admin` 登录，找「审计日志」菜单 | **找不到入口**；直接打 `GET /api/audit/logs` 返回 **403 `NOT_AUDIT_ADMIN`**，且该次尝试被写入审计链 |
| 用 `admin` 创建审计管理员 `auditor01` → 用 `auditor01` 登录 | 能看到审计日志、能校验哈希链；但**看不到「用户管理」菜单**，调 `approve` 返回 403 |
| 用 `admin` 创建用户管理员 `ops01` → 用 `ops01` 登录 | 能审核 / 解锁 / 注销**普通用户**；**没有**「新建账号」「变更角色」入口；看不到任何审计数据 |
| 回到 `admin` 的用户管理页，对 `auditor01` 点「注销」 | 按钮**存在**（`ops01` 登录时同一行没有这个按钮）；确认后账号从库中删除、其票据立即失效，审计链留下 `DELETE_USER` |

前三条构成"职责分离"的完整证明：**管账号的看不了日志，看日志的管不了账号。**
第四条证明"管理员对账号的处置权是完整的"——包括审计管理员在内。

---

## 七、修订记录

### 2026-09-20 实现期校正

1. **命名统一**：方案阶段的 `SuperAdmin` 在实际实现中改名为 `Admin`，
   并把"被创建的管理员"独立成 `UserAdmin` 一级。原因是方案里"Admin 只管普通用户"
   与"admin 才是超管"两种叫法在代码评审时反复混淆，改为
   `Admin`（管账号 + 任免角色）/ `UserAdmin`（只管账号）后一目了然。
2. **放开管理员的注销范围**：原方案规定"管理员只能动普通用户与用户管理员"，
   审计管理员与其它管理员一律 `FORBIDDEN_TARGET`。实现后按需求调整为
   **管理员可处置除自己以外的任意账号**，并把"自我豁免"确立为唯一恒定的约束。
   判定从"只看目标角色"改为"同时看操作者与目标角色"（`UserRoles.CanBeManagedBy`），
   因为同一个目标账号在管理员和用户管理员手里可处置范围本就不同。
3. **`set-role` 同步放开**：原先"不能变更管理员账号的角色"这条同级保护一并移除，
   否则会出现"能注销管理员却不能降级管理员"的不一致。
4. **验证**：`tools/role_separation_test.py` 从 47 项断言扩到 **59 项**，
   新增的 12 项全部覆盖注销范围（管理员自保护、用户管理员越级被拒、注销审计管理员成功、
   票据吊销、库记录删除、留痕与 `FORBIDDEN_TARGET` 计数）。

### 方案期遗留问题（已全部结清）

| 问题 | 结论 |
|---|---|
| `transfer-admin` 是否保留逃生通道 | **不保留**。管理员可处置除自己以外的一切账号，不需要靠转移身份腾位置 |
| 新建账号是否强制首次改密 | **不强制**，用初始口令直接登录 |
| 审计管理员能否看到操作者姓名 | **能**，审计链保留完整操作者信息（本来就要靠它追责） |
| `delete-user` 能否删除审计管理员 | **能**，本次修订的核心 |
