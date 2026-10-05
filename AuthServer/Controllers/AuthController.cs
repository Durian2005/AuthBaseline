using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthServer.Controllers;

/**
 * 认证与会话接口：传输层状态、登录、登出。
 *
 * 这三件事共同构成"一次会话从建立到结束"的完整闭环，
 * 与账号自助（AccountController）、用户管理（UserAdminController）分开。
 * 路由前缀仍是 api/auth —— 与拆分前逐一对应，前端契约不变。
 */
[ApiController]
[Route("api/auth")]
public class AuthController : AuthControllerBase
{
    private readonly TransportInfo _transport;

    public AuthController(MongoDbService db, AuditWriter auditWriter, SessionService sessions,
        PepperProvider pepper, TransportInfo transport, IConfiguration configuration)
        : base(db, auditWriter, sessions, pepper, configuration)
    {
        _transport = transport;
    }

    /// <summary>
    /// 传输层状态：供界面状态栏显示「加密 / 明文」。
    ///
    /// **刻意不做鉴权**：状态栏在登录页就要显示，而"这条链路到底有没有加密"
    /// 恰恰是用户最该在**输入口令之前**就知道的事。
    /// 该接口不含任何敏感信息 —— 证书主题与指纹属于公钥信息，本就是公开的。
    /// </summary>
    [HttpGet("transport")]
    public IActionResult Transport()
    {
        // 以**实际请求**的 scheme 为准，而不是配置项：
        // 配置说的是"打算怎么跑"，Request.IsHttps 说的是"这一跳到底有没有加密"，
        // 而验收要证明的是后者。两者不一致本身就是最该被暴露的信号。
        var https = Request.IsHttps;

        return Ok(new ApiResponse
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = https ? "链路已加密（TLS）" : "链路为明文 HTTP",
            Data = new
            {
                scheme = https ? "https" : "http",
                tls = https,
                requireHttps = _transport.RequireHttps,
                subject = _transport.Subject,
                notAfter = _transport.NotAfter?.ToUniversalTime().ToString("o"),
                thumbprint = _transport.Thumbprint,
                trustStore = _transport.TrustStore,
                // 配置要求加密、实际却是明文 ⇒ 界面必须显眼地报出来，而不是静静显示"明文"
                downgraded = _transport.RequireHttps && !https
            }
        });
    }

    /* ==================== 口令存储格式升级（pepper） ==================== */

    /**
     * 把一条**旧格式**（无 pepper）的口令哈希原地重写为新格式。
     * 仅由登录入口调用，且只在「口令已验证通过 + 库里是旧格式」时调用。
     *
     * 三条刻意的取舍：
     *
     * 1. **绝不影响本次登录。** 整段被 try/catch 包住，任何失败都只意味着
     *    "这个账号下次登录再升级"，用户照常登录成功。
     *    升级只是收紧存储形态，不该让用户因为"格式没换成功"而进不来 ——
     *    这与 AuditService 的旁路原则是同一条思路。
     *
     * 2. **用 UpdateOne 只改一个字段，不用 ReplaceOne 整篇覆盖。**
     *    user 对象是本次请求开头读出来的，中途可能已被并发修改
     *    （例如另一个请求刚更新了 failedLoginAttempts）。整篇替换会把这些改动抹掉。
     *
     * 3. **审计里绝不出现口令。** request 只记"从哪种格式变成哪种格式"这一事实 ——
     *    这条记录要留在哈希链里被反复翻看，不能因为"顺手升级"就把口令写进去。
     */
    private async Task TryUpgradePasswordHashAsync(User user, string password)
    {
        try
        {
            var newHash = PasswordHasher.Hash(password, _pepper.Pepper);

            await _db.Users.UpdateOneAsync(u => u.Id == user.Id,
                Builders<User>.Update.Set(u => u.PasswordHash, newHash));
            user.PasswordHash = newHash;

            // 此刻口令已验证通过，身份可信，所以操作者记该账号自己。
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.PasswordHashUpgraded,
                user.Status.ToString(),
                new { From = PasswordHasher.LegacyFormatName, To = PasswordHasher.PepperFormatName },
                new { Upgraded = true },
                user.Status.ToString(), user.Username, AuditResult.Success);
        }
        catch (Exception ex)
        {
            // 旁路失败不阻断：库里仍是旧格式，下次登录会再试一次。
            Console.WriteLine($"[Pepper] 口令哈希升级失败（不影响本次登录，下次登录会重试）: {ex.Message}");
        }
    }

    /* ==================== 登出 ==================== */

    /**
     * 主动登出：吊销当前票据。
     *
     * 有了服务端会话，登出才真正"登出"——
     * 改造前前端清掉本地状态即可，令牌本身仍有效；现在服务端一吊销，票据立刻作废。
     */
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var ticket = ReadTicket();
        var auth = await _sessions.ValidateAsync(ticket, AccessLevel.Authenticated);

        if (!auth.Success)
        {
            // 登出失败不值得打断用户，但仍留痕
            var quiet = new ApiResponse { Success = false, Code = auth.ReasonCode, Message = auth.Message };
            await _auditWriter.WriteAsync("anonymous", "anonymous", AuditAction.Logout, "N/A",
                new { Reason = auth.ReasonCode }, quiet, "N/A", "", AuditResult.Failed, auth.ReasonCode);
            return StatusCode(auth.HttpStatus, quiet);
        }

        await _sessions.RevokeAsync(ticket!, "用户主动登出");
        var resp = new ApiResponse { Success = true, Code = BusinessCode.Ok, Message = "已安全退出" };
        await _auditWriter.WriteAsync(auth.User!.Id, auth.User.Username, AuditAction.Logout,
            auth.User.Status.ToString(), new { }, resp, auth.User.Status.ToString(),
            auth.User.Username, AuditResult.Success);
        return Ok(resp);
    }

    /* ==================== 登录 ==================== */

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        var sanitizedUsername = Norm(req.Username);
        // 口令绝不进入日志，请求里只保留用户名
        var requestLog = new { req.Username };

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "用户名或密码不能为空" };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (user == null)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidCredentials, Message = "用户名或密码错误" };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        // 锁定期间，即使正确口令也拒绝登录。
        // 注意判定不再直接拿墙钟比：TimeGuard 会核对"墙钟"与"锁定时的墙钟 + 真实流逝的
        // 运行时长"这两条线，背离时以单调线为准 ——
        // 于是把电脑时间往前拨 3 分钟并不会让这里放行。
        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue)
        {
            var verdict = TimeGuard.Assess(user, TimeGuard.WallNow(), TimeGuard.UptimeMs());
            await LogClockDriftIfAnyAsync(user, verdict, "LOGIN", sanitizedUsername);

            if (verdict.Locked)
                return await LockoutRejectionAsync(user, verdict, AuditAction.LoginFailed, statusBefore,
                    requestLog, sanitizedUsername, "账号已锁定，请 ", 401);

            // 锁定时间已过（按可靠时刻判断），自动恢复为启用状态
            user.Status = UserStatus.Enabled;
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            ClearLockoutAnchor(user);
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            statusBefore = UserStatus.Enabled.ToString();
        }

        if (user.Status == UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.PendingApproval, Message = "账号待审核，请联系管理员" };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, user.Status.ToString(),
                sanitizedUsername, AuditResult.Failed, AuditReason.PendingApproval);
            return Unauthorized(resp);
        }

        // 冻结账号（沉睡治理的产物）：直接拒绝，且**放在口令校验之前**。
        //
        // 顺序很重要：若先验口令，冻结就只是"拦住知道口令的人"——
        // 攻击者仍可对冻结账号验证口令猜测是否命中（正确口令会走到下一步，
        // 于是错误码从"口令错"变成别的），等于给已停用的账号留了个口令探针。
        // 先判状态 ⇒ 不论口令对错一律 ACCOUNT_DISABLED，不透出任何口令信息。
        if (user.Status == UserStatus.Disabled)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.AccountDisabled,
                Message = "账号已被冻结，如需恢复请联系用户管理员"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp,
                user.Status.ToString(), sanitizedUsername, AuditResult.Failed, AuditReason.AccountDisabled);
            return Unauthorized(resp);
        }

        // 验证本身会顺带告诉我们要不要升级格式（旧格式无 pepper，通过后应当重写）。
        // 注意这里**只判 Valid**：是否升级由下面的登录成功分支决定，失败分支一概不改库。
        var passwordCheck = PasswordHasher.Verify(req.Password, user.PasswordHash, _pepper.Pepper);
        if (!passwordCheck.Valid)
        {
            user.FailedLoginAttempts++;
            string? message;
            string code;
            string reason;
            UserStatus newStatus = user.Status;
            DateTime? lockoutEnd = user.LockoutEnd;

            if (user.FailedLoginAttempts >= MaxFailedAttempts)
            {
                newStatus = UserStatus.Locked;
                // 锁定时同时记下**两个**时间锚点：墙钟 + 系统运行时长。
                // 只记墙钟的话，"现在到了没有"就还得再读一次墙钟，
                // 而墙钟恰恰是能被拨动的那一个（拨快 3 分钟即可解锁）；
                // 运行时长不受拨钟影响，两者一对比就知道这段时间真实过去了多久。
                var lockWallNow = TimeGuard.WallNow();
                lockoutEnd = lockWallNow.Add(LockoutDuration);
                user.Status = newStatus;
                user.LockoutEnd = lockoutEnd;
                user.LockoutWallAt = lockWallNow;
                user.LockoutUptimeAt = TimeGuard.UptimeMs();
                // 新的一轮锁定：把"已就时钟背离告警过"的标记归零，
                // 否则上一轮留下的 true 会让这一轮的拨钟不再留痕。
                user.LockoutDriftLogged = false;
                message = $"连续输错 {MaxFailedAttempts} 次密码，账号已锁定 {LockoutDuration.TotalMinutes} 分钟";
                code = BusinessCode.AccountLocked;
                // 本次尝试既"口令错"也"触发锁定"，审计语义上按更严重的锁定归类：
                // 审计员要能一条查询捞出"所有因口令错误而锁定的事件"。
                reason = AuditReason.AccountLocked;
            }
            else
            {
                message = $"密码错误，还剩 {MaxFailedAttempts - user.FailedLoginAttempts} 次机会";
                code = BusinessCode.InvalidCredentials;
                reason = AuditReason.InvalidCredentials;
            }

            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            var resp = new ApiResponse
            {
                Success = false,
                Code = code,
                Message = message,
                Data = new { FailedAttempts = user.FailedLoginAttempts, LockoutEnd = lockoutEnd }
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, user.Status.ToString(),
                sanitizedUsername, AuditResult.Failed, reason);
            return Unauthorized(resp);
        }

        // 登录成功，重置失败计数
        if (user.FailedLoginAttempts > 0)
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            ClearLockoutAnchor(user);
        }

        // ── 沉睡账号治理：记录最后一次成功登录 ──
        // 为什么记在"登录成功"这一处：它是全系统唯一入口（任何操作都要先拿票据），
        // 于是"在这写一次"就等于"覆盖全部真实使用"。沉睡判定以本字段为基准，
        // 漏写会让活跃账号被误判成沉睡 —— 这是本功能最不能出错的地方，
        // 所以它必须和"重置失败计数"一样，收在成功分支的必经之路上。
        user.LastLoginAt = DateTime.UtcNow;

        // 上面两条改动合并在一次写入里（而不是各写一次）：
        // 同一请求内对同一文档的两次 Replace 会白跑一次往返，也更容易在
        // 未来某次改动中漏掉其中一条。
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        // ── 旧格式口令哈希的顺手升级 ──
        // 为什么只做在这一处：登录是全系统唯一的入口 —— 任何操作都要先拿到票据，
        // 而票据只能由登录签发。于是"只在登录升级"就等于"全部账号迟早都会升级"，
        // 不必把"顺手写库"这件事复制到四个验证点里去（那样回滚面也更大）。
        // 为什么放在这里：此时口令刚刚验证通过，用它算新哈希是安全的；
        // 而验证失败的分支已经在上面 return 掉了，不会走到这里。
        if (passwordCheck.NeedsUpgrade)
            await TryUpgradePasswordHashAsync(user, req.Password);

        // 登录成功 → 签发服务端会话票据。
        // 票据是后续所有管理员接口的凭证，也是"普通用户无权查看审计日志"能成立的前提。
        // 注意明文只存在于 issued.Ticket（随响应发回客户端），**库里落的是它的哈希**。
        var issued = await _sessions.IssueAsync(user);

        var successResp = new ApiResponse<LoginResult>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = "登录成功",
            Data = new LoginResult
            {
                Username = user.Username,
                Status = user.Status.ToString(),
                Role = user.Role.ToString(),
                RoleLabel = UserRoles.Label(user.Role),
                IsAdmin = UserRoles.CanManageUsers(user.Role),
                Ticket = issued.Ticket,
                ExpiresAt = issued.Session.ExpiresAt
            }
        };
        // 审计里绝不记录票据本体，只记"已签发"这一事实
        await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginSuccess, statusBefore, requestLog,
            new { user.Username, user.Status, Role = user.Role.ToString(), TicketIssued = true },
            user.Status.ToString(), sanitizedUsername, AuditResult.Success);
        return Ok(successResp);
    }
}
