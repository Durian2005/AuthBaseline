# 邮箱验证码功能说明

本次在基线 90 分版本之上新增两项能力，未改动原有登录、锁定、审核、注销、改密、权限转让逻辑。

| 功能 | 说明 |
|---|---|
| 注册绑定邮箱 | 注册时填写邮箱，**先发验证码、验证通过才创建账号**（账号仍为待审核） |
| 忘记密码 | 用户名 + 邮箱 → 验证码 → **直接设置新密码** → 用新密码正常登录 |

刻意**不做**"验证码直接登录"：本系统内不存在"不凭口令即可建立会话"的路径。

---

## 一、发件配置（授权码只经过你自己的手）

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

`Account` / `Password` 留空时，程序会在启动日志里提示并**自动降级为控制台发件器**
（验证码打印到后端日志），因此断网也能完整演示，不会因为没配邮箱就跑不起来。

### 填授权码的三种方式（任选其一）

| 方式 | 操作 | 适用 |
|---|---|---|
| **环境变量（推荐）** | `setx AUTHBASELINE_EMAIL_PASSWORD "你的16位授权码"`，再 `setx AUTHBASELINE_EMAIL_ACCOUNT "你的邮箱@qq.com"` | 重新打包/覆盖安装都不会丢 |
| **本地覆盖文件** | 在 `AuthServer/` 下新建 `appsettings.Local.json`（已被 .gitignore 忽略），写入 `{ "Email": { "Account": "...", "Password": "..." } }` | 开发联调，不会进版本库 |
| **直接改配置** | 改安装目录下的 `appsettings.json` | 临时演示，**覆盖安装后会被重置** |

读取优先级：环境变量 > `appsettings.Local.json` > `appsettings.json`。
授权码不需要、也不应该发给任何人，包括助手。

### 启动时如何确认通道

```
[Email] 发件通道：SMTP(smtp.qq.com:465)          ← 已配好，真实投递
[Email] 发件通道：控制台（验证码打印在日志中…）    ← 未配授权码，降级模式
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
| 前端界面 | `tools/ui_e2e.mjs`（Edge 无头 + CDP 真实点击） | **11 / 11 通过**（注册绑邮箱 → 审核 → 找回密码 → 新密码登录进主界面） |

运行前提：后端以控制台发件器启动，stdout 重定向到 `%TEMP%\be.log`。

```bash
# 后端（控制台发件器，日志写入 %TEMP%\be.log）
cd AuthServer && dotnet run --urls http://localhost:5007 > "$TEMP/be.log" 2>&1

# 接口级验证
python tools/email_e2e_test.py

# 界面级验证（需先启动 Edge 调试实例：--remote-debugging-port=9222）
node tools/ui_e2e.mjs ui_shot.png
```

## 八、已知限制

登录成功后仍**没有服务端会话票据**，管理员接口靠请求里的用户名判断身份——
这是改造前就存在的设计，本次未改动。若后续老师要求"会话超时""并发登录控制"，
需要补服务端 ticket，届时所有接口签名都要调整。
