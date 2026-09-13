# 邮箱验证码功能说明

本次在基线 90 分版本之上新增两项能力，未改动原有登录、锁定、审核、注销、改密、权限转让逻辑。

| 功能 | 说明 |
|---|---|
| 注册绑定邮箱 | 注册时填写邮箱，**先发验证码、验证通过才创建账号**（账号仍为待审核） |
| 忘记密码 | 用户名 + 邮箱 → 验证码 → **直接设置新密码** → 用新密码正常登录 |

刻意**不做**"验证码直接登录"：本系统内不存在"不凭口令即可建立会话"的路径。

---

## 一、发件配置（授权码只经过你自己的手）

系统里有**两个完全不同的"邮箱"角色**，先分清这一点：

- **发件邮箱**：整个系统只有 1 个，需要用授权码登录 SMTP 服务器把信发出去。
- **用户注册邮箱**：每个用户各填各的，可以是 QQ / 163 / Gmail / 学校邮箱等**任何能收信的邮箱**，
  不需要做任何设置。所以"只支持 QQ 邮箱"是误解，QQ 邮箱只是当前选用的发件通道。

默认配置见 `AuthServer/appsettings.json` 的 `Email` 节：

```json
"Email": {
  "Enabled": true,
  "Provider": "Smtp",
  "SmtpHost": "smtp.qq.com",
  "SmtpPort": 465,
  "UseSsl": true,
  "Account": "",
  "Password": "",
  "DisplayName": "口令认证基线系统",
  "TimeoutSeconds": 10
}
```

`Account` / `Password` 留空时，程序会在启动日志里提示并**自动降级为控制台发件器**，
因此断网也能完整演示，不会因为没配邮箱就跑不起来。

### 填授权码的方式（任选其一）

| 场景 | 方式 | 操作 | 覆盖安装后 |
|---|---|---|---|
| **桌面安装版（推荐）** | 安装目录的 `appsettings.Local.json` | 用记事本打开 `%LOCALAPPDATA%\Programs\AuthBaseline\appsettings.Local.json`，填 `Account` 与 `Password`，完全退出程序再打开 | **保留**（安装器检测到文件已存在就不覆盖） |
| 开发联调 | `AuthServer/appsettings.Local.json` | 同上（该文件已被 .gitignore 忽略，不会进版本库） | — |
| 任意场景 | 环境变量 | `setx AUTHBASELINE_EMAIL_ACCOUNT "你的邮箱@qq.com"`、`setx AUTHBASELINE_EMAIL_PASSWORD "16位授权码"` | 保留 |
| 临时演示 | 安装目录的 `appsettings.json` | 直接改 | **会被重置**，不推荐 |

读取优先级：**环境变量 > `appsettings.Local.json` > `appsettings.json`**。

> **桌面版为什么推荐改文件而不是环境变量**：`setx` 只写入注册表，
> 已经运行的资源管理器不会立刻看到它，双击桌面快捷方式启动的程序可能读不到新变量，
> 需要注销重新登录才生效。改 `appsettings.Local.json` 则完全退出程序再打开即可，最省事。

授权码不需要、也不应该发给任何人，包括助手——助手只写"去哪里读授权码"的代码，不接触授权码本身。

### 启动时如何确认通道

```
[Email] 发件通道：SMTP(smtp.qq.com:465)          ← 已配好，真实投递
[Email] 发件通道：控制台（验证码打印在日志中…）    ← 未配授权码，降级模式
```

### 没配授权码时，怎么看到验证码

| 运行方式 | 验证码在哪里 |
|---|---|
| `dotnet run`（开发） | 后端控制台，或重定向的日志文件 |
| **桌面安装版** | 安装目录下的 **`email-codes.log`**（GUI 程序没有控制台，因此专门落一份文件） |

```bash
# 桌面安装版查看方式
notepad "%LOCALAPPDATA%\Programs\AuthBaseline\email-codes.log"
```

---

## 二、验证码规则

| 项 | 取值 |
|---|---|
| 位数 | 6 位数字，取自密码学安全随机源 `RandomNumberGenerator` |
| 有效期 | 5 分钟 |
| 校验次数 | 最多 5 次，超出即作废 |
| 重发间隔 | 60 秒 |
| 存储 | 只存 BCrypt 散列，**绝不存明文**；校验通过立即置为已用（一次性） |
| 绑定 | 记录与 `(用户名, 用途)` 绑定，A 收到的码不能用于 B 的账号 |
| 清理 | `expiresAt` 上建 MongoDB TTL 索引，过期记录自动删除，无需定时任务 |

## 三、用途隔离与状态门禁

- `purpose` 只接受 `REGISTER` / `RESET`，**注册码不能用于重置、重置码也不能用于注册**。
- 找回密码链路复用现有账号状态判定，以下状态一律拒绝：
  - **待审核**（403 `PENDING_APPROVAL`）
  - **已禁用**（403 `ACCOUNT_DISABLED`）
  - **锁定中**（423 `ACCOUNT_LOCKED`，返回剩余秒数）
- 因此"发一条验证码就绕过 3 次失败锁定"这条路被堵死。
- 重置成功后会一并清除 `lockoutEnd` 与失败计数，避免"改完密码仍被锁在门外"。

## 四、防枚举

找回密码场景下，**账号不存在 / 未绑邮箱 / 邮箱不匹配**时，返回值与成功响应逐字一致
（同样的 `code`、同样的 `maskedEmail`），只是不真正发信；真实原因只写进审计日志。
这样攻击者无法通过接口探测"哪些用户名存在、绑了哪个邮箱"。

## 五、老账号兼容

- `User` 新增 `email` / `emailVerified` 两个字段，**老账号保持 null**，可继续用原口令登录，不强制补绑。
- 邮箱唯一索引使用**部分索引**（只约束 `$type: string` 的文档），
  否则大量 `email = null` 的老账号会让唯一索引直接建失败、服务起不来。
- `Email:Enabled = false` 时注册回退为"无需邮箱"的老流程。

## 六、接口与审计

| 接口 | 说明 |
|---|---|
| `POST /api/auth/send-email-code` | `{ purpose, username, email }`，发码 |
| `POST /api/auth/register` | 新增 `email` / `code` 字段，校验通过才建号 |
| `POST /api/auth/reset-password` | `{ username, email, code, newPassword }` |

审计动作新增 `SEND_EMAIL_CODE`（发送验证码）、`RESET_PASSWORD`（重置密码），
成功与失败都记；`target` 记用户名，邮箱一律脱敏（`s*****@example.com`）。

## 七、验证结果

| 层次 | 脚本 | 结果 |
|---|---|---|
| 后端接口 | `tools/email_e2e_test.py` | **34 / 34 通过**（含用途隔离、防枚举、锁定/待审核门禁、验证码一次性等失败分支） |
| 前端界面（浏览器） | `tools/ui_e2e.mjs`（Edge 无头 + CDP 真实点击） | **11 / 11 通过** |
| **桌面安装版** | 同一个 `tools/ui_e2e.mjs`，改指向安装后的 WebView2 | **11 / 11 通过**（注册绑邮箱 → 审核 → 找回密码 → 新密码登录进主界面） |

`ui_e2e.mjs` 通过环境变量适配两种运行目标，无需改代码：

```bash
# 浏览器联调模式
cd AuthServer && dotnet run --urls http://localhost:5007 > "$TEMP/be.log" 2>&1
python tools/email_e2e_test.py
node tools/ui_e2e.mjs ui_shot.png        # 需先启动 Edge：--remote-debugging-port=9222

# 桌面安装版模式（应用首页地址会自动识别，端口是动态的）
# 先带调试端口启动：set WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9333
set E2E_CDP=http://127.0.0.1:9333
set E2E_LOG=%LOCALAPPDATA%\Programs\AuthBaseline\email-codes.log
node tools/ui_e2e.mjs desktop_shot.png
```

## 八、桌面安装包

- 安装包：`AuthBaseline-Setup-1.0.0.exe`（静默安装参数 `/S`）
- 安装目录：`%LOCALAPPDATA%\Programs\AuthBaseline\`
- 安装内容：`auth-baseline-desktop.exe`（Tauri 壳）、`authserver.exe`（.NET 后端）、
  `wwwroot/`（前端静态资源）、`appsettings.json`、`appsettings.Local.json`

安装器的两条保护逻辑：

1. `appsettings.Local.json` **已存在则不覆盖**，用户填好的授权码不会因升级而丢失；
2. 覆盖安装前先清空旧 `wwwroot/`，避免前端带哈希的旧文件名越堆越多。

## 九、已知限制

1. 登录成功后仍**没有服务端会话票据**，管理员接口靠请求里的用户名判断身份——
   这是改造前就存在的设计，本次未改动。若后续老师要求"会话超时""并发登录控制"，
   需要补服务端 ticket，届时所有接口签名都要调整。
2. 单文件发布的后端（`authserver.exe`）依赖目标机已安装 **.NET 8 运行时**；
   打包机器上已具备，若换机演示需先装运行时。
3. QQ 邮箱对发信频率有限制（`550 Sender frequency limited`），
   全班集中注册可能触发限流；60 秒重发间隔本身已是一种限流，必要时可换 163 邮箱做发件箱。
