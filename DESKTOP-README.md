# 桌面端使用教程（Tauri v2 + Vue 3 + .NET sidecar）

本项目前端已重构为 Vue 3，并通过 **Tauri v2** 打包成轻量级桌面应用。
后端（ASP.NET Core）在桌面端以 **sidecar（边车进程）** 形式随应用自动启动、随应用关闭自动终止。

> 注：为支持"审计日志增强"与"管理员权限转让"，后端新增了 `POST /api/auth/transfer-admin` 接口，
> 并给审计日志补充了 `result`（成功 / 失败）与 `target`（操作对象）字段，
> 登录动作由 `LOGIN` 拆分为 `LOGIN_SUCCESS` / `LOGIN_FAILED`。其余接口与既有行为保持不变。

---

## 一、目录结构（与本仓库相关部分）

```
实验一 建立可运行的口令认证基线/
├── AuthClient/                 # Vue 3 前端（desktop 模式产物输出到 AuthClient/dist）
├── AuthServer/                 # ASP.NET Core 后端（未改动）
│   └── publish/                # dotnet publish 的发布产物（单文件 exe）
├── src-tauri/                  # Tauri v2 桌面外壳（Rust）
│   ├── src/lib.rs              # sidecar 启动/终止逻辑 + get_backend_url IPC
│   ├── tauri.conf.json         # 窗口标题、CSP、externalBin(sidecar) 配置
│   ├── Cargo.toml
│   ├── capabilities/default.json
│   └── binaries/
│       └── authserver-x86_64-pc-windows-msvc.exe   # 后端 sidecar 二进制
├── scripts/sync-sidecar.mjs    # 把发布产物同步为 sidecar
└── package.json                # 根：tauri 脚本入口
```

---

## 二、前置依赖

| 依赖 | 用途 | 检查 |
|---|---|---|
| Rust（stable, MSVC） | 编译 Tauri 外壳 | `cargo --version` |
| Node.js ≥ 18 | 构建前端、运行 Tauri CLI | `node -v` |
| .NET 8 运行时 | 后端 sidecar 是**框架依赖**发布，需本机有 .NET 8 | `dotnet --list-runtimes` |
| MongoDB | 后端需要 | 服务在 `localhost:27017` 监听 |
| WebView2 | Windows 上 Tauri 的渲染内核（Win10/11 通常自带） | — |

> 说明：后端采用**框架依赖 + 单文件**发布（约 13MB），因此目标机器必须安装 .NET 8 运行时。
> 若要做到"无 .NET 也能跑"，改用 `--self-contained true` 重新发布（约 110MB），见第七节。

---

## 三、日常开发（热更新）

在**仓库根目录**执行：

```bash
npm install          # 仅首次：安装 @tauri-apps/cli 等
npm run dev          # = tauri dev
```

- 会启动 Vite 开发服务器（http://localhost:5173）作为界面；
- 同时通过 sidecar 拉起 .NET 后端（**自动分配空闲端口**，不与你手动 `dotnet run` 的 5007 冲突）；
- 修改 `AuthClient/src/**` 后界面即时刷新；修改 `src-tauri/**` 会触发 Rust 重新编译。

---

## 四、构建桌面安装包

```bash
npm run build        # = tauri build
```

产物在：

```
src-tauri/target/release/bundle/nsis/AuthBaseline-Setup-1.0.0.exe
```

这是一个标准 Windows 安装向导（NSIS）。安装后从开始菜单 / 桌面快捷方式启动即可。

> **本次已为你生成好安装包**，位于上述路径，可直接双击安装，无需自己跑构建。
>
> 安装包内含：`auth-baseline-desktop.exe`（主程序）、`authserver.exe`（.NET 后端 sidecar）、
> `appsettings.json`（后端配置）、`wwwroot/`（后端静态资源），以及卸载程序与开始菜单/桌面快捷方式。
> 安装目录即程序启动目录，因此后端能正确读到 `appsettings.json` 与 `wwwroot`，不会出现 "WebRootPath not found" 警告。
>
> ⚠️ **关于打包环境的说明**：在正常机器上，直接 `npm run build`（即 `tauri build`）即可自动下载 NSIS 并生成安装包。
> 但本次所处环境无法访问 GitHub Releases（Tauri 的 NSIS 及插件从 GitHub 下载），因此安装包是**手动用本地 NSIS 3.11 编译**的，
> 效果一致（同样包含主程序 + 后端 sidecar + 卸载程序 + 开始菜单/桌面快捷方式）。回到你自己的电脑后用 `npm run build` 可正常复现。

> 首次 `tauri build` 会编译大量 Rust 依赖（tauri、tauri-plugin-shell 等），耗时较长（数分钟到十几分钟），属正常。

---

## 五、后端 sidecar 的更新流程

当你修改了 `AuthServer/` 后端代码，需要重新发布并更新 sidecar 二进制：

```bash
npm run publish:backend   # dotnet publish -> AuthServer/publish/AuthServer.exe
npm run sync:sidecar      # 复制到 src-tauri/binaries/ 并按 Tauri 命名规范重命名
npm run build             # 重新打包（含新后端）
```

`scripts/sync-sidecar.mjs` 会把
`AuthServer/publish/AuthServer.exe`
复制为
`src-tauri/binaries/authserver-x86_64-pc-windows-msvc.exe`。

---

## 六、工作原理（FAQ）

**Q：后端地址是怎么来的？为什么 Vue 里写的是 `/api`？**
A：浏览器模式下页面与后端同源，`/api` 即可。桌面端页面源是 `tauri://localhost`，相对路径失效，
因此 `AuthClient/src/main.js` 启动时调用 `initApiRoot()`，通过 Tauri IPC 向 Rust 询问
`get_backend_url`（例如 `http://127.0.0.1:52341`），再把 API 基址切到该地址。
浏览器模式完全不受影响。

**Q：sidecar 为什么用动态端口？**
A：`src-tauri/src/lib.rs` 在启动时 `bind("127.0.0.1:0")` 申请一个空闲端口，
再用 `--urls http://127.0.0.1:<port>` 传给 .NET 后端。这样即使你本地手动跑着 5007 端口的调试实例，
桌面端也不会冲突。

**Q：关闭窗口后 .NET 进程会残留吗？**
A：不会。Rust 侧在窗口 `Destroyed` 事件和应用 `Exit` 事件中都调用 `child.kill()`，
确保进程随应用退出而终止。若异常退出导致残留，可在任务管理器结束 `AuthServer.exe`。

**Q：点右上角 X 按钮会怎样？**
A：直接退出整个程序（不会弹确认框，也不会把窗口"关闭"到桌面图标）。
Rust 侧 `WindowEvent::Destroyed` → `kill_backend` 自动终止后端 sidecar。
最小化/最大化按钮调用的是 Tauri 原生窗口 API，行为与系统标准窗口一致。

**Q：MongoDB 没启动会怎样？**
A：后端进程会启动，但接口调用会失败（连接数据库超时）。界面底部状态栏会显示"后端已连接"但操作报错，
此时请先启动 MongoDB 服务。

---

## 七、常见问题排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 编译报 `linker 'link.exe' not found` | 缺 MSVC 生成工具 | 安装 "Desktop development with C++"（VS2022 工作负载） |
| 界面提示"无法连接后端" | MongoDB 未启动 / 后端还没预热 | 启动 MongoDB；首次启动后端有数秒预热，状态栏会自动变绿 |
| 应用开始但白屏 | 前端未构建或 `frontendDist` 路径错 | 确认 `npm run build:frontend` 能生成 `AuthClient/dist` |
| 换机器运行提示缺 .NET | sidecar 是框架依赖发布 | 目标机装 .NET 8 运行时，或改用自包含发布（见下） |
| 端口被占用导致启动慢 | 动态端口也会偶发等待 | 一般会自动跳过；如卡死，结束残留 `AuthServer.exe` 重试 |

---

## 八、改为完全自包含（可选）

若希望目标机器**无需安装 .NET** 也能运行，把 `package.json` 里 `publish:backend` 改为：

```json
"publish:backend": "dotnet publish AuthServer/AuthServer.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -o AuthServer/publish"
```

然后重新 `npm run sync:sidecar && npm run build`。代价是 sidecar 体积从 ~13MB 增至 ~110MB。

---

## 九、本次功能变更记录

### 9.1 登录页移除"自动填充管理员账号"

原先登录页底部有一个「填充默认管理员账号（admin / Admin123）」按钮，会把管理员凭据直接写进输入框，
等同于把口令明文暴露在界面上。现已删除该按钮与相关代码，并对登录框的两个输入项设置 `autocomplete="off"`，
避免浏览器长期留存凭据后被一键登录。注册表单仍保留 `new-password`（便于口令管理器生成强口令）。

### 9.2 审计日志：覆盖一切操作，且能区分成败

- 新增 `result` 列：成功 / 失败。登录成功与登录失败是同一入口的两种结局，必须能一眼区分。
- 新增 `target` 列：记录被操作对象（注册 / 审核 / 解锁 / 注销 / 转让的目标账号）。
- 登录动作由 `LOGIN` 拆为 `LOGIN_SUCCESS` / `LOGIN_FAILED`；历史 `LOGIN` 记录仍兼容展示。
- **所有分支都会落日志**：参数校验失败、口令错误、账号锁定、待审核、越权操作、目标不存在……
  失败的操作不再从审计中"凭空消失"。
- 口令永远不进入日志（请求体只记录用户名）。
- 只读接口（用户列表 / 日志查询）刻意不写日志——它们由界面每 20 秒轮询一次，写进去只会淹没真正的操作记录。

已覆盖的动作：`REGISTER`（增）、`DELETE_USER`（删）、`CHANGE_PASSWORD` / `APPROVE` / `UNLOCK` / `TRANSFER_ADMIN`（改）、
`LOGIN_SUCCESS` / `LOGIN_FAILED`（登录成败）。

### 9.3 注册审核支持查找

"待审核用户"面板新增用户名查找与注册时间排序（最新在前 / 最早在前，后者适合先来先审），
并显示"共 N 条 · 匹配 M 条"，便于在大量注册请求中快速定位。

### 9.4 管理员权限转让

现任管理员可把权限转让给另一位**合法用户**（状态为"启用"的账号）：

1. 用户管理 → 目标用户行 → **转让权限**；
2. 弹窗要求输入**当前管理员的登录口令**做二次校验（防止会话被冒用后直接夺权）；
3. 后端先提升受让方、再撤销自己的管理员身份 —— 任何时刻系统内都至少有一名管理员；
4. 成功后本人降为普通用户，界面自动离开管理员页面；全过程（含每次失败）写入审计日志 `TRANSFER_ADMIN`。

后端校验顺序与返回码：空字段 `EMPTY_FIELDS` → 非管理员 `UNAUTHORIZED` → 口令错误 `INVALID_CREDENTIALS`
→ 转让给自己 `CANNOT_TRANSFER_SELF` → 目标不存在 `NOT_FOUND`
→ 目标非启用状态 `TARGET_NOT_ELIGIBLE` → 目标已是管理员 `TARGET_ALREADY_ADMIN`。
