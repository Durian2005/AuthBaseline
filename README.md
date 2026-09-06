# 实验一：建立可运行的口令认证基线

## 一、技术栈

- 后端：ASP.NET Core Web API（.NET 8），Visual Studio 2022
- 数据库：MongoDB（建议使用 MongoDB Compass 可视化观察）
- 前端：Vue 3（Composition API + Pinia + Vite），桌面软件风格 UI
- 密码哈希：BCrypt

> 前端由最初的「原生 HTML + CSS + JavaScript」重构为 Vue 3 单文件组件应用，
> 呈现为**桌面软件形态**（标题栏 / 侧边栏 / 状态栏 / 可拖拽对话框 / 任务栏）。
> 后端接口与业务逻辑未做任何改动，旧版前端已备份在 `AuthClient/legacy-wwwroot/`。

## 二、项目结构

```
实验一 建立可运行的口令认证基线/
├── AuthBaseline.sln              # Visual Studio 2022 解决方案
├── AuthServer/                   # 后端（本轮重构未改动）
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
3. 使用 Visual Studio 2022 打开 `AuthBaseline.sln`。
4. 首次打开后，NuGet 包会自动还原（MongoDB.Driver、BCrypt.Net-Next）。

## 四、运行步骤

1. 在 Visual Studio 2022 中，将 `AuthServer` 设为启动项目。
2. 按 `F5` 或 `Ctrl+F5` 运行。
3. 浏览器打开 `http://localhost:5007/`。

> 后端 API 地址：`http://localhost:5007/api/auth/...`
>
> 前端产物已构建并提交在 `AuthServer/wwwroot/`，**直接运行后端即可看到界面**，
> 无需启动前端开发服务器。

### 前端开发（可选）

只有需要修改界面时才需要走这一步：

```bash
cd AuthClient
npm install       # 首次
npm run dev       # 开发服务器 http://localhost:5173，/api 自动代理到 5007
npm run build     # 构建产物输出到 ../AuthServer/wwwroot
```

修改完务必执行 `npm run build`，否则后端托管的仍是旧产物。

## 五、默认管理员账号

系统首次启动时会自动创建：

- 用户名：`admin`
- 密码：`Admin123`

> 建议首次登录后立即修改管理员密码。

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

### 4. 登录失败锁定

- 连续输错 **3 次** 密码，账号状态变为 **锁定（Locked）**。
- 锁定持续 **3 分钟**。
- **锁定期间即使输入正确密码，也拒绝登录**。
- 3 分钟后系统自动解锁；或管理员可手动解锁。

### 5. 修改密码

- 登录后可在用户面板修改密码。
- 修改成功后，旧密码立即失效。

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

### 8. 桌面端界面（Vue 3）

前端以**桌面软件**的形态呈现，而不是普通网页：

| 元素 | 行为 |
|------|------|
| 标题栏 | 应用标识、主题切换（浅色/深色）、最小化 / 最大化 / 关闭 |
| 侧边栏 | 功能导航（仪表盘、账号与口令、用户管理、审计日志），待审核数量角标 |
| 状态栏 | 后端连通状态、上次同步时间、锁定倒计时、当前用户、系统时钟 |
| 任务栏 | 最小化后可从任务栏恢复；关闭后桌面上保留图标，双击重新打开 |
| 子窗口 | 注销确认、日志详情为可拖拽对话框，`Esc` 关闭 |
| 通知 | 右上角应用内 Toast，按成功/错误/警告/信息分色 |

无障碍与规范：全矢量内联图标（无 emoji 充当图标）、表单均有标签与行内错误提示、
焦点可见、`prefers-reduced-motion` 下自动关闭动效、深浅双主题均满足文本 4.5:1 对比度。

## 七、验收测试用例

> 以下用例已在本机用 curl 实测验证，全部符合预期（实测记录见第十一章第 5 节）。

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

## 八、数据库状态观察

打开 MongoDB Compass，查看 `AuthBaselineDb` 数据库：

- `Users` 集合：观察 `status`、`failedLoginAttempts`、`lockoutEnd` 字段变化。
- `AuditLogs` 集合：观察每次操作的状态流转证据。

典型的状态流转链：

```
待审核（Pending） → 启用（Enabled） → 锁定（Locked） → 启用（Enabled）
```

## 九、接口清单

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/register` | 用户注册 |
| POST | `/api/auth/login` | 用户登录 |
| POST | `/api/auth/approve` | 管理员审核用户 |
| POST | `/api/auth/unlock` | 管理员解锁用户 |
| POST | `/api/auth/delete-user` | 管理员注销用户 |
| POST | `/api/auth/change-password` | 修改密码 |
| GET | `/api/auth/users?adminUsername=admin` | 获取用户列表 |
| GET | `/api/auth/logs?adminUsername=admin` | 获取审计日志 |

## 十、鲁棒性设计

- 用户名统一转小写并去除首尾空格，避免大小写重复。
- 注册、登录、改密接口对密码字段做了复杂度校验。
- 所有写操作均记录审计日志，便于追溯攻击与异常。
- 锁定状态优先于密码校验，确保暴力破解期间即使撞对密码也无法进入。
- 密码哈希使用 BCrypt（自适应成本，抗彩虹表）。
- 响应使用统一格式 `{ success, code, message, data }`，前端易于处理。
- 审计日志写入做了异常兜底：日志记录失败不会阻断注册/登录等主流程。

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

### 5. 实测记录（本次验收）

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
