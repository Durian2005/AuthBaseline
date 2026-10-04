# AuthBaseline

**一套可本地部署、职责分离、全程可追责的口令认证基线系统。**

AuthBaseline 是一套完整的口令认证参考实现，覆盖认证系统的完整生命周期：注册审核、
登录、口令复杂度校验与哈希存储、失败锁定、会话票据、基于角色的访问控制（职责分离），
以及基于哈希链的审计日志。后端为 ASP.NET Core（.NET 8）+ MongoDB，前端是 Vue 3
的桌面形态应用，并可通过 Tauri v2 打包为 Windows 桌面软件。

它适合作为新系统的认证起点，也可作为认证与审计安全设计的参考实现：全部能力都可
在本机跑起来、可复算、可验证，不依赖任何外部服务。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)
![Vue](https://img.shields.io/badge/Vue-3-42B883)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6)

## 文档导航

各能力模块都有独立文档，本 README 覆盖整体架构、接口清单与运行方式：

| 文档 | 内容 |
|------|------|
| [`DESKTOP-README.md`](DESKTOP-README.md) | 桌面端使用与打包：Tauri v2 + Vue 3 + .NET sidecar，输出 Windows 安装包 |
| [`EMAIL-VERIFY-README.md`](EMAIL-VERIFY-README.md) | 邮箱验证码：注册邮箱绑定、忘记密码重置 |
| [`ROLE-SEPARATION-DESIGN.md`](ROLE-SEPARATION-DESIGN.md) | 角色分离（职责分离）：管理用户与读取审计互斥 |
| [`AUDIT-UPGRADE-DESIGN.md`](AUDIT-UPGRADE-DESIGN.md) | 审计追责设计：让所有安全事件可追溯 |
| [`AUDIT-VERIFY-REPORT.md`](AUDIT-VERIFY-REPORT.md) | 审计哈希链的独立复算与验证报告 |
| [`TRANSPORT-STORAGE-SECURITY-DESIGN.md`](TRANSPORT-STORAGE-SECURITY-DESIGN.md) | 传输与存储安全设计：TLS、票据哈希化、口令 pepper |

## 一、技术栈

- 后端：ASP.NET Core Web API（.NET 8）—— 可用 Visual Studio 2022 或 .NET CLI 开发
- 数据库：MongoDB（推荐搭配 MongoDB Compass 直接观察数据）
- 前端：Vue 3（Composition API + Pinia + Vite），Tauri 封装的桌面软件形态 UI
- 密码哈希：BCrypt

> 前端最初是原生 HTML + CSS + JavaScript 实现，后重构为 Vue 3 单文件组件应用，
> 呈现为**桌面软件形态**（标题栏 / 侧边栏 / 状态栏 / 可拖拽对话框 / 任务栏）。
> 后端接口与业务逻辑保持不变，旧版前端保留在 `AuthClient/legacy-wwwroot/` 以便对照。

## 二、项目结构

```
AuthBaseline/
├── AuthBaseline.sln              # 解决方案文件（Visual Studio 2022 / dotnet CLI）
├── AuthServer/                   # 后端（ASP.NET Core）
│   ├── AuthServer.csproj
│   ├── Program.cs                # 服务注册、中间件、CORS、静态文件
│   ├── appsettings.json          # MongoDB 连接字符串
│   ├── Controllers/
│   │   └── AuthController.cs     # 注册/审核/登录/改密/锁定/解锁/日志接口
│   ├── Models/
│   │   ├── User.cs               # 用户实体
│   │   ├── AuditLog.cs           # 审计日志实体
│   │   ├── ApiResponse.cs        # 统一响应
│   │   └── AuthDtos.cs           # 请求/响应 DTO
│   ├── Services/
│   │   └── MongoDbService.cs     # MongoDB 连接与管理员种子
│   └── wwwroot/                  # 前端构建产物（由 AuthClient 构建生成）
├── AuthClient/                   # 前端源码（Vue 3）
│   ├── package.json
│   ├── vite.config.js            # 开发代理 /api → 5007，构建输出 → ../AuthServer/wwwroot
│   ├── smoke_test.py             # 端到端接口冒烟测试（26 项）
│   ├── legacy-wwwroot/           # 旧版原生前端备份
│   └── src/
│       ├── main.js
│       ├── App.vue               # 桌面外壳：窗口/最小化/最大化/关闭/壁纸/任务栏
│       ├── styles/               # 设计令牌与基础样式
│       ├── api/client.js         # API 封装与错误分类
│       ├── stores/               # Pinia：会话状态 + 通知
│       ├── components/           # 外壳与通用组件（图标、窗口、表格、徽章…）
│       └── views/                # 登录、仪表盘、账号口令、用户管理、审计日志
└── README.md
```

## 三、环境准备

1. 安装并启动 MongoDB（默认端口 `27017`）。
2. 可选：安装 MongoDB Compass，连接 `mongodb://localhost:27017`，数据库名为 `AuthBaselineDb`。
3. 安装 .NET 8 SDK，然后任选一种方式打开工程：
   - Visual Studio 2022 打开 `AuthBaseline.sln`；
   - 或使用 .NET CLI（`dotnet build` / `dotnet run`）。
4. 首次打开后，NuGet 包会自动还原（MongoDB.Driver、BCrypt.Net-Next）。

## 四、运行步骤

1. 在 Visual Studio 2022 中，将 `AuthServer` 设为启动项目（或执行 `dotnet run --project AuthServer`）。
2. 按 `F5` 或 `Ctrl+F5` 运行。
3. 浏览器打开 `http://localhost:5007/`。

> 后端 API 地址：`http://localhost:5007/api/auth/...`
>
> 前端产物已构建并提交在 `AuthServer/wwwroot/`，**直接运行后端即可看到界面**，
> 无需启动前端开发服务器。
>
> ⚠️ VS 默认使用的 `http` 启动配置走**明文对照模式**（自动设 `AUTHBASELINE_REQUIRE_HTTPS=false`），
> 目的是让调试与既有脚本不受影响；要看加密形态请选 `https` 启动配置，或直接运行桌面端。
> **桌面端首次启动可能弹出一次 Windows 证书信任确认框，选「是」**（写 `CurrentUser\Root`，
> 不用管理员权限；产品化路径是安装期写 `LocalMachine\Root`）。

### 前端开发（可选）

只有需要修改界面时才需要走这一步：

```bash
cd AuthClient
npm install       # 首次
npm run dev       # 开发服务器 http://localhost:5173，/api 自动代理到 5007
npm run build     # 只出浏览器产物 → ../AuthServer/wwwroot
```

> **改完界面建议用 `python tools/build_all.py frontend` 统一构建。**
>
> 本项目有两条分发链路，靠 vite 的 mode 区分输出目录：
>
> | 链路 | 产物目录 | 构建命令 |
> |---|---|---|
> | 浏览器访问（后端静态托管，同源 `/api`） | `AuthServer/wwwroot` | `npm run build` |
> | 桌面端（Tauri 打包 / 热替换安装目录） | `AuthClient/dist` | `npm run build:desktop` |
>
> 只跑其中一条命令，另一条链路的产物就会停在旧版本 —— 本项目出过一次
> `wwwroot` 落后 `dist` 15 天、浏览器打开后端看到旧界面的事故。
> 上面的脚本会**两套都构建**，并逐字节比对两者是否一致，不一致直接报非零退出码。
>
> 单独做一致性检查（不构建）：`python tools/build_all.py check`

## 五、默认管理员账号

系统首次启动时会自动创建：

- 用户名：`admin`
- 密码：`Admin123`

> ⚠️ 这是**公开的默认种子口令**，仅用于首次进入系统。请在任何非本机环境部署前修改，
> 或通过 `set-role` / `create-account` 接口建立自己的管理员账号后停用默认账号。

## 六、功能说明

### 1. 用户注册（需管理员审核）

- 普通用户注册后状态为 **待审核（Pending）**，无法登录。
- 管理员在“管理员控制台”点击“通过”后，状态变为 **启用（Enabled）**。

### 2. 密码复杂度要求

- 至少 8 位
- 同时包含大写字母、小写字母、数字

示例合法密码：`Hello123`、`Admin123`、`Password1`

### 3. 密码哈希存储

- 用户密码通过 BCrypt 哈希后存入 MongoDB。
- 数据库中只保存 `passwordHash`，不保存明文。
- 当前实现为 pepper + BCrypt + 内嵌盐（`v2$` 前缀），旧格式哈希在登录时自动升级。
  详见 [TRANSPORT-STORAGE-SECURITY-DESIGN.md](TRANSPORT-STORAGE-SECURITY-DESIGN.md)。

### 4. 登录失败锁定

- 连续输错 **3 次** 密码，账号状态变为 **锁定（Locked）**。
- 锁定持续 **3 分钟**。
- **锁定期间即使输入正确密码，也拒绝登录**。
- 3 分钟后系统自动解锁；或管理员可手动解锁。
- 锁定期内同时记录墙钟与单调时钟，偏离超过容差以单调时钟为准，并写入 `CLOCK_ANOMALY`
  审计事件 —— 防止通过回拨系统时间绕过锁定。

### 5. 修改密码

- 登录后可在用户面板修改密码。
- 修改成功后，旧密码立即失效，旧会话票据同时吊销。

### 6. 注销用户

- 管理员可在用户列表点击“注销”删除普通用户账号，操作前会弹窗二次确认，防止误删。
- **管理员账号不可被注销**（包含注销自己），避免系统失去管理员而无法恢复。
- 注销会写入审计日志，`statusAfter` 记为 `Deleted`。

### 7. 审计日志

每个关键操作都会在 MongoDB `AuditLogs` 集合中记录：

- `operatorId` / `operatorName`：操作者
- `action`：动作（REGISTER / LOGIN / APPROVE / UNLOCK / DELETE_USER / CHANGE_PASSWORD）
- `statusBefore`：操作前状态
- `statusAfter`：操作后状态
- `request`：请求内容（已脱敏，不含密码）
- `response`：响应内容
- `timestamp`：UTC 时间

日志按 `AuditLogs_yyyyMM` 分片存储，每条带 `selfHash` / `prevHash` / `seq` 构成哈希链，
分片头部锚点记录在 `AuditChainHeads`，可通过 `GET /api/audit/verify` 校验完整性。

### 8. 桌面端界面（Vue 3）

前端以**桌面软件**的形态呈现，而不是普通网页：

| 元素 | 行为 |
|------|------|
| 标题栏 | 应用标识、主题切换（浅色/深色）、最小化 / 最大化 / 关闭 |
| 侧边栏 | 功能导航（仪表盘、账号与口令、用户管理、审计日志），待审核数量角标 |
| 状态栏 | 后端连通状态、传输加密指示、上次同步时间、锁定倒计时、当前用户、系统时钟 |
| 任务栏 | 最小化后可从任务栏恢复；关闭后桌面上保留图标，双击重新打开 |
| 子窗口 | 注销确认、日志详情为可拖拽对话框，`Esc` 关闭 |
| 通知 | 右上角应用内 Toast，按成功/错误/警告/信息分色 |

无障碍与规范：全矢量内联图标（无 emoji 充当图标）、表单均有标签与行内错误提示、
焦点可见、`prefers-reduced-motion` 下自动关闭动效、深浅双主题均满足文本 4.5:1 对比度。

## 七、测试用例

> 以下用例均已在开发机上实测验证，全部符合预期（实测记录见第十一章第 5 节）。

### 正常测试

| 步骤 | 操作 | 预期结果 |
|------|------|----------|
| 1 | 注册普通用户 `alice`，密码 `Hello123` | 注册成功，状态为 Pending |
| 2 | 用 `admin` / `Admin123` 登录 | 登录成功，进入管理员控制台 |
| 3 | 管理员审核通过 `alice` | alice 状态变为 Enabled |
| 4 | 用 `alice` / `Hello123` 登录 | 登录成功 |
| 5 | alice 修改密码为 `World456` | 修改成功 |
| 6 | 用 `alice` / `World456` 登录 | 登录成功 |
| 7 | 用 `alice` / `Hello123` 登录 | 旧密码失效，登录失败 |

### 异常测试

| 步骤 | 操作 | 预期结果 |
|------|------|----------|
| 1 | 注册重复用户名 `alice` | 拒绝，提示“用户名已存在” |
| 2 | 使用错误旧密码修改密码 | 拒绝，提示“旧密码错误” |
| 3 | 输入空用户名/空密码 | 拒绝，提示字段不能为空 |
| 4 | 注册密码 `123` | 拒绝，提示密码复杂度不足 |

### 攻击测试

| 步骤 | 操作 | 预期结果 |
|------|------|----------|
| 1 | 连续 3 次用 `alice` / 错误密码 登录 | 第 3 次后账号锁定 |
| 2 | 锁定期间用 `alice` / 正确密码 登录 | 拒绝，提示账号锁定 |
| 3 | 3 分钟后再次用正确密码登录 | 登录成功（自动解锁） |
| 4 | 或管理员手动点击“解锁” | 立即解锁，可用正确密码登录 |

> 更多自动化验证脚本见 `tools/`：角色分离（`role_separation_test.py`）、
> 时间回拨（`lockout_clock_probe.py`）、票据哈希化（`ticket_hash_probe.py`）、
> 口令 pepper（`pepper_probe.py`）、审计链独立复算（`verify_chain_independent.py`）。

## 八、数据库状态观察

打开 MongoDB Compass，查看 `AuthBaselineDb` 数据库：

- `Users` 集合：观察 `status`、`failedLoginAttempts`、`lockoutEnd` 字段变化。
- `AuditLogs` / `AuditLogs_yyyyMM` 集合：观察每次操作的状态流转证据。

典型的状态流转链：

```
待审核（Pending） → 启用（Enabled） → 锁定（Locked） → 启用（Enabled）
```

## 九、接口清单

> 下表为后端当前实际暴露的全部接口（共 **18** 个）。
> 鉴权自「角色分离」改造起改为**服务端签发的 Bearer 票据**（`Authorization: Bearer <ticket>`），
> 不再使用早期的 `?adminUsername=xxx` 由客户端自证身份的方式。
> 鉴权失败会写入一条 `AUDIT_ACCESS_DENIED` 事件，使越权尝试可追溯。

### 1. 认证与账号（`api/auth`）

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| POST | `/api/auth/register` | 匿名 | 用户注册（校验邮箱验证码，创建后状态为待审核） |
| POST | `/api/auth/login` | 匿名 | 用户登录，成功返回会话票据 |
| POST | `/api/auth/logout` | 需票据 | 注销当前会话（吊销票据） |
| POST | `/api/auth/send-email-code` | 匿名 | 发送邮箱验证码（注册与重置口令共用）；对不存在的邮箱返回与真实发信**逐字一致**的响应，防账号枚举 |
| POST | `/api/auth/reset-password` | 匿名（凭验证码） | 忘记密码：校验邮箱验证码后直接设置新口令 |
| POST | `/api/auth/change-password` | 需票据 | 修改自己的口令；新旧口令不得相同 |
| GET | `/api/auth/transport` | 匿名 | 传输层状态：当前链路是否加密（TLS）、证书主题与到期日。**刻意不做鉴权** —— 状态栏在登录页就要显示，且内容属于公钥信息 |

> ⚠️ **传输层**：桌面端（Tauri 壳 + sidecar）走 **HTTPS（TLS 1.3）**，
> 证书为本机私有 CA（`CN=AuthBaseline Local CA`）签发的 leaf，存于
> `%LOCALAPPDATA%\AuthBaselineData\certs\`，CA 公钥写入 `CurrentUser\Root`；
> 开发态 `dotnet run` 默认显式走明文对照模式。
> 详见 [TRANSPORT-STORAGE-SECURITY-DESIGN.md](TRANSPORT-STORAGE-SECURITY-DESIGN.md) 的 §6.2 / §6.3 实施记录。

### 2. 用户管理（`api/auth`）

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/api/auth/users` | 用户管理员 | 获取用户列表 |
| POST | `/api/auth/approve` | 用户管理员 | 审核通过待审核用户 |
| POST | `/api/auth/unlock` | 用户管理员 | 手动解锁被锁定的账号 |
| POST | `/api/auth/delete-user` | 用户管理员 | 注销普通用户（管理员账号不可被注销） |
| POST | `/api/auth/create-account` | 管理员 | 管理员直接创建账号，需二次校验操作者口令 |
| POST | `/api/auth/set-role` | 管理员 | 任免用户角色（含 AuditAdmin），需二次校验操作者口令 |

### 3. 审计日志

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/api/audit/logs` | 审计读 | 分页查询审计日志，支持按分片 / 关键词 / 动作 / 结果筛选 |
| GET | `/api/auth/logs` | 审计读 | 兼容旧路径，内部转调同一套分页逻辑 |
| GET | `/api/audit/verify` | 审计读 | 哈希链完整性校验，返回断点序号与所在分片 |
| GET | `/api/audit/shards` | 审计读 | 分片清单与各片规模 |
| GET | `/api/audit/stats` | 审计读 | 概览统计：总数、失败数、篡改告警数 |

### 4. 角色与权限模型

角色为**互斥枚举**，避免出现非法权限组合：

| 角色 | 管理用户 | 分配角色 | 读取审计 |
|------|:---:|:---:|:---:|
| `User` | — | — | — |
| `UserAdmin` | 仅普通用户 | — | — |
| `Admin` | ✓ | ✓（含 AuditAdmin） | — |
| `AuditAdmin` | — | — | ✓ |

**职责分离**：`Admin` 能管理用户与分配角色，但**不能读取审计日志**；`AuditAdmin`
能读取审计日志，但**不能管理用户**。两者权限互斥，任何单一角色都无法同时篡改数据与
掩盖痕迹。

## 十、鲁棒性设计

- 用户名统一转小写并去除首尾空格，避免大小写重复。
- 注册、登录、改密接口对密码字段做了复杂度校验。
- 所有写操作均记录审计日志，便于追溯攻击与异常。
- 锁定状态优先于密码校验，确保暴力破解期间即使撞对密码也无法进入。
- 密码哈希使用 BCrypt（自适应成本，抗彩虹表）。
- 响应使用统一格式 `{ success, code, message, data }`，前端易于处理。
- 审计日志写入做了异常兜底：日志记录失败不会阻断注册/登录等主流程。
- 数据库中的会话票据只保存哈希（无盐 SHA-256 + Base64Url），明文票据仅在签发时返回一次。

## 十一、常见问题排查

### 1. 注册总是提示“注册失败”，但看不出原因

第一步先确认**后端是否在运行**（最常见的原因）：

- 在 VS2022 中按 `F5` 启动 `AuthServer`，或命令行执行 `dotnet run`。
- 浏览器访问 `http://localhost:5007/`，打不开就说明后端没跑起来。
- 界面左下角状态栏会实时显示「后端已连接 / 后端未连接」。

前端已把错误分成三类，便于快速定位：

| 提示 | 含义 |
|------|------|
| “无法连接后端服务。请确认 MongoDB 已启动…” | 后端进程没运行，或端口不对 |
| “服务器返回 HTTP 500” | 后端内部异常，查看 VS 输出窗口的异常堆栈 |
| 具体中文提示（如“密码必须至少8位…”） | 业务逻辑正常拦截，按提示修改输入即可 |

### 2. MongoDB 里看不到任何数据

- **MongoDB Compass 只是客户端，不自带数据库服务**，必须另外启动 MongoDB Server，
  默认监听 `127.0.0.1:27017`。
- 数据库名为 `AuthBaselineDb`，集合为 `Users` 和 `AuditLogs`。
- 只有后端成功启动并收到请求后才会写入数据。首次启动会自动建唯一索引并预置管理员 `admin`。
- Compass 里看不到时，点一下刷新按钮。

### 3. 已知坑：审计日志字段必须是 string

`AuditLog` 的 `request` / `response` 字段若声明为 `object`，MongoDB 的
`ObjectSerializer` 会拒绝序列化 `ApiResponse<T>` 这类自定义类型，抛出
`BsonSerializationException`，导致**整个请求返回 500**。

典型症状：用户数据其实已经写进 `Users` 集合，但接口返回 500，前端只能显示兜底的“注册失败”。

本项目已改为 `string`（写入前用 `JsonSerializer.Serialize` 序列化成 JSON 字符串），
并对日志写入加了 try-catch —— 审计日志属于旁路记录，失败绝不能拖垮主流程。

### 4. 端口被占用

若 `5007` 被占用，修改 `AuthServer/Properties/launchSettings.json` 中的
`applicationUrl` 即可。

### 5. 实测记录

以下流程已用 curl 实测全部通过：

| 场景 | 结果 |
|------|------|
| 注册合规密码 | 200，状态 `Pending` |
| 注册弱密码 `123` | 400，`WEAK_PASSWORD` |
| 未审核账号登录 | 401，`PENDING_APPROVAL` |
| 管理员登录 / 审核通过 | 200，状态转 `Enabled` |
| 连续 3 次错误密码 | 401，锁定并写入 `lockoutEnd` |
| **锁定期间输入正确密码** | 401，`ACCOUNT_LOCKED`（核心要求达成） |
| 管理员解锁 | 200，`Locked → Enabled`，失败次数清零 |
| 修改密码 | 200，旧密码立即失效 |
| 审计日志落库 | 含 `statusBefore/After`、`operatorId`、时间戳 |

## 十二、贡献指南

欢迎 issue 与 pull request。

**报告问题**：请附上复现步骤、期望行为与实际行为，以及环境信息（.NET 版本、MongoDB
版本、是否桌面端）。与审计链、口令存储或传输层相关的现象，请一并给出对应的审计
`reasonCode` 或错误码。

**提交代码**：

1. Fork 本仓库并从 `main` 切出特性分支（如 `feat/session-rotation`）。
2. 一个提交聚焦一件事，提交信息使用 Conventional Commits 前缀
   （`feat` / `fix` / `docs` / `test` / `chore`），并在正文说明动机与影响面。
3. 改动涉及前端时，请用 `python tools/build_all.py frontend` 构建并确认两条产物链路
   逐字节一致；涉及接口或权限模型时，请跑一遍 `tools/` 下对应的验证脚本。
4. 发起 PR，描述变更内容、验证方式与已知限制。

**安全漏洞**：请勿通过公开 issue 披露。审计链、口令存储、传输层与权限模型均属于
安全敏感面，请私下联系维护者并给出一段可复现的说明。

## 十三、许可证

本项目基于 [MIT License](LICENSE) 发布，版权所有 (c) 2026 Ruiyan Diao。
