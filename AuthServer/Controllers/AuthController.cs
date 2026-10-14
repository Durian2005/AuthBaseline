using AuthServer.Models;
using AuthServer.Services;
using AuthServer.Services.Face;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthServer.Controllers;

/**
 * 认证与会话接口：传输层状态、登录（含可选的人脸第二因子）、登出。
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
    private readonly FaceLoginService _face;

    public AuthController(MongoDbService db, AuditWriter auditWriter, SessionService sessions,
        PepperProvider pepper, TransportInfo transport, IConfiguration configuration, FaceLoginService face)
        : base(db, auditWriter, sessions, pepper, configuration)
    {
        _transport = transport;
        _face = face;
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
            // 失败计数与窗口锚点一并清掉：解锁后应当从 0 重新数满 3 次。
            user.Status = UserStatus.Enabled;
            ResetFailedAttempts(user);
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
            // 两个时间读数只取一次，供"失败计数窗口的锚点"与"锁定锚点"共用：
            // 分两次读会拿到两个不同步的"现在"，让本应同起点的锚点对不上。
            var failWallNow = TimeGuard.WallNow();
            var failUptimeMs = TimeGuard.UptimeMs();

            // 计一次失败：只有落在同一个窗口（FailureWindow）内的才累加。
            // 窗口过期时由它把计数归零、本次成为新窗口的第 1 次 ——
            // 这里刻意不自己判"过期没有"，窗口语义只有基类那一份实现。
            // 它同时是"还没锁定就拨钟"的唯一留痕点：拨钟不改变本次尝试的结果
            // （不加罚、也不放过），只让"有人动过时钟"在审计里留下一条。
            var thresholdReached = await RegisterFailedAttemptAsync(user, failWallNow, failUptimeMs,
                sanitizedUsername);

            string? message;
            string code;
            string reason;
            UserStatus newStatus = user.Status;
            DateTime? lockoutEnd = user.LockoutEnd;

            if (thresholdReached)
            {
                newStatus = UserStatus.Locked;
                // 锁定时同时记下**两个**时间锚点：墙钟 + 系统运行时长。
                // 只记墙钟的话，"现在到了没有"就还得再读一次墙钟，
                // 而墙钟恰恰是能被拨动的那一个（拨快 3 分钟即可解锁）；
                // 运行时长不受拨钟影响，两者一对比就知道这段时间真实过去了多久。
                lockoutEnd = failWallNow.Add(LockoutDuration);
                user.Status = newStatus;
                user.LockoutEnd = lockoutEnd;
                user.LockoutWallAt = failWallNow;
                user.LockoutUptimeAt = failUptimeMs;
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

        // ── 旧格式口令哈希的顺手升级 ──
        // 为什么只做在这一处：登录是全系统唯一的入口 —— 任何操作都要先拿到票据，
        // 而票据只能由登录签发。于是"只在登录升级"就等于"全部账号迟早都会升级"，
        // 不必把"顺手写库"这件事复制到四个验证点里去（那样回滚面也更大）。
        // 为什么放在这里：此时口令刚刚验证通过，用它算新哈希是安全的；
        // 而验证失败的分支已经在上面 return 掉了，不会走到这里。
        // 放在第二因子之前：升级只依赖"口令已验过"这一个事实，与人脸无关；
        // 若放在人脸之后，一个长期不刷脸的账号就会一直停在旧格式。
        if (passwordCheck.NeedsUpgrade)
            await TryUpgradePasswordHashAsync(user, req.Password);

        // ── 第二因子闸门 ──
        //
        // ⚠️ 从这里往下，**还没有**清零失败计数、**还没有**更新 lastLoginAt、
        //    更没有签发任何票据。这三件事统一由 CompleteLoginAsync 在"整段认证全部通过"时
        //    一次做完 —— 理由见该方法注释（否则人脸这一因子会变成一条不会触发锁定的口令探针）。
        if (_face.Enabled)
        {
            var decision = await _face.AssessAsync(user);

            if (decision.Requirement == FaceLoginService.Requirement.EngineUnavailable)
            {
                // 该账号已录人脸（= 自愿启用了第二因子），但本机引擎不可用。
                // 这里**拒绝**而不是"跳过第二因子放行"：跳过等于给出一条
                // "把摄像头占用/弄坏就降回单因子"的静默通道（见 FaceLoginService.AssessAsync）。
                var resp = new ApiResponse
                {
                    Success = false,
                    Code = BusinessCode.FaceEngineUnavailable,
                    Message = $"该账号已启用刷脸验证，但本机人脸引擎不可用：{decision.Message}。"
                              + "请联系用户管理员重置你的人脸后重试。"
                };
                await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginFailed, statusBefore,
                    requestLog, resp, user.Status.ToString(), sanitizedUsername, AuditResult.Failed,
                    AuditReason.FaceEngineUnavailable);
                return StatusCode(503, resp);
            }

            if (decision.Requirement == FaceLoginService.Requirement.Challenge)
            {
                var (token, action) = _face.Issue(user.Username);
                var challengeResp = new ApiResponse<FaceChallengeResponse>
                {
                    // Success=true 表示"这一步本身成功":口令这一因子已经通过，
                    // 流程正确地进入第二阶段。它与"已登录"完全不同——
                    // 响应里没有票据，客户端拿不到任何可用于访问接口的凭据。
                    Success = true,
                    Code = BusinessCode.FaceRequired,
                    Message = "口令已通过，请完成人脸验证",
                    Data = new FaceChallengeResponse
                    {
                        ChallengeToken = token,
                        Action = action,
                        ActionText = FacePose.ActionText(action),
                        ActionHint = FacePose.ActionHint,
                        ExpiresInSeconds = _face.ChallengeTtlSeconds
                    }
                };
                await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginRequired, statusBefore,
                    requestLog,
                    new { user.Username, Step = "PASSWORD_OK", ChallengeIssued = true, Action = action },
                    user.Status.ToString(), sanitizedUsername, AuditResult.Success);
                return Ok(challengeResp);
            }
        }

        // 未录人脸（或模块关闭）⇒ 与改造前逐字一致的单因子登录。
        return await CompleteLoginAsync(user, statusBefore, requestLog, sanitizedUsername, secondFactor: false);
    }

    /* ==================== 登录第二阶段：人脸验证 ==================== */

    /**
     * 人脸验证通过后，提交一次性挑战，由服务端自己开摄像头完成动作挑战并比对模板。
     *
     * 这是**未鉴权**接口 —— 此时还没有任何票据可携带，唯一的凭据就是那张一次性挑战 token。
     * 它之所以安全，是因为 token 只可能来自"口令刚刚验证通过"那一步，且随机、新鲜、一次性：
     *   拿不到 token 的人，必须先有一个正确的口令。
     *
     * 接口上**只有 token 一个输入**，没有"画面"也没有"特征" ——
     * 采集与特征提取全在服务端进程内完成。这不是省事，是这条功能的立身之本：
     * 一旦允许前端上送特征，攻击者就能不碰摄像头、直接 POST 一个向量。详见设计文档 §四。
     */
    [HttpPost("login/face")]
    public async Task<IActionResult> LoginFace([FromBody] FaceVerifyRequest req)
    {
        var (user, action, error) = await _face.BeginVerifyAsync(req.ChallengeToken);

        if (error is not null || user is null || action is null)
        {
            // 认不出这张票属于谁 ⇒ 无法归属到某个账号，因此**不累加任何计数**
            // （计数是账号级的量，无主的失败没有累加对象）。
            // 这不构成绕过：要拿到 token 必须先过口令，重放一张已消费/过期的票并不推进攻击。
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.FaceChallengeInvalid,
                Message = FaceCodes.MessageFor("FACE_CHALLENGE_INVALID")
            };
            await _auditWriter.WriteAsync("anonymous", "anonymous", AuditAction.FaceLoginFailed, "N/A",
                new { Step = "FACE", ChallengePresent = !string.IsNullOrWhiteSpace(req.ChallengeToken) },
                resp, "N/A", "anonymous", AuditResult.Failed, AuditReason.FaceChallengeInvalid);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();
        var requestLog = new { user.Username };

        // 口令通过之后、人脸完成之前，账号状态仍可能被管理员改掉（冻结 / 锁定）。
        // 这里**重新判一次**：否则"口令通过那一刻还正常、之后被冻结"的账号
        // 仍会被人脸这一步放进来 —— 等于给处置动作留了一个时间窗。
        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue)
        {
            var verdict = TimeGuard.Assess(user, TimeGuard.WallNow(), TimeGuard.UptimeMs());
            await LogClockDriftIfAnyAsync(user, verdict, "LOGIN_FACE", user.Username);

            if (verdict.Locked)
                return await LockoutRejectionAsync(user, verdict, AuditAction.FaceLoginFailed, statusBefore,
                    requestLog, user.Username, "账号已锁定，请 ", 401);

            user.Status = UserStatus.Enabled;
            ResetFailedAttempts(user);
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            statusBefore = UserStatus.Enabled.ToString();
        }

        if (user.Status == UserStatus.Disabled)
        {
            var disabledResp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.AccountDisabled,
                Message = "账号已被冻结，如需恢复请联系用户管理员"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginFailed, statusBefore,
                requestLog, disabledResp, user.Status.ToString(), user.Username, AuditResult.Failed,
                AuditReason.AccountDisabled);
            return Unauthorized(disabledResp);
        }

        var result = await _face.EvaluateAsync(user, action);

        if (result.Passed)
        {
            // 人脸这一因子单独记一条：事后能一条查询捞出"哪些登录真的刷过脸"。
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginSuccess, statusBefore,
                requestLog,
                new
                {
                    user.Username,
                    Similarity = result.Similarity,
                    Threshold = _face.Threshold,
                    Diagnostic = result.Diagnostic
                },
                user.Status.ToString(), user.Username, AuditResult.Success);

            // 两个因子都过了 ⇒ 到这里才真正完成登录（清零计数 / 更新 lastLoginAt / 签票）。
            return await CompleteLoginAsync(user, statusBefore, requestLog, user.Username, secondFactor: true);
        }

        // ── 未通过：按 A/B 组决定要不要计入 3 分钟失败窗口 ──
        // A 组（欺骗信号 / 主动绕过）计次，B 组（质量问题 / 配合问题）不计 ——
        // 否则用户会被自己的摄像头误伤到锁号，而症状（"我明明是对的脸却登不上"）极难归因。
        string? lockMessage = null;
        if (result.Counted)
            lockMessage = await ApplyCountedFailureAsync(user);
        // 不计次的分支刻意**不写库**：质量问题不改变账号上的任何字段。
        // 多写一次除了浪费一次往返，还会让"这次到底动没动计数"变得难以从代码上一眼看清。

        var reason = result.AuditReason;
        var responseCode = result.BusinessCode;
        if (lockMessage is not null)
        {
            // 本次既"人脸没过"也"触发锁定"，审计按更严重的锁定归类 ——
            // 与口令失败那条路径的口径一致，好让"所有因验证失败而锁定"能被一条查询捞出。
            responseCode = BusinessCode.AccountLocked;
            reason = AuditReason.AccountLocked;
        }

        var failResp = new ApiResponse
        {
            Success = false,
            Code = responseCode,
            Message = lockMessage ?? result.Message,
            Data = new
            {
                FailedAttempts = user.FailedLoginAttempts,
                LockoutEnd = user.LockoutEnd,
                Similarity = result.Similarity,
                Threshold = _face.Threshold
            }
            // 刻意**不下发** Counted：那等于告诉攻击者"哪一类失败不会被计数"。
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginFailed, statusBefore, requestLog,
            new
            {
                user.Username,
                BusinessCode = responseCode,
                Similarity = result.Similarity,
                Threshold = _face.Threshold,
                Counted = result.Counted,
                Diagnostic = result.Diagnostic
            },
            user.Status.ToString(), user.Username, AuditResult.Failed, reason);
        return Unauthorized(failResp);
    }

    /* ==================== 登录完成的唯一出口 ==================== */

    /**
     * 一次登录**真正完成**的唯一出口。
     *
     * 为什么"清零失败计数 + 更新 lastLoginAt + 签发票据 + 写 LOGIN_SUCCESS"必须收在一处：
     *   引入第二因子后，登录从"一步"变成"口令 + 人脸"两步。
     *   如果在口令那一步就把失败计数清零，那么一个**已经知道口令**的攻击者
     *   只要反复"口令正确 → 人脸随便过两下 → 失败 → 重新登录"，
     *   就能让计数在每次口令通过时归零，**永远刷不满 3 次** ——
     *   人脸这一因子反而被自己变成了一个不会被锁定的口令探针。
     *   所以清零只发生在"两个因子都过"的那一刻，与 lastLoginAt、票据同生共死。
     *
     * secondFactor 只进审计的 JSON 袋（**不加列**，见 AuditLog 的字段约束）：
     *   事后必须能回答"这次 LOGIN_SUCCESS 到底有没有过第二因子"，
     *   因为它直接决定这条成功记录代表多强的认证。
     */
    private async Task<IActionResult> CompleteLoginAsync(User user, string statusBefore, object requestLog,
        string target, bool secondFactor)
    {
        // 失败计数与窗口一起归零（下次要从 0 重新数满 3 次）。
        // 走统一出口 —— 清零牵动 5 个字段，散着写迟早漏掉一个。
        if (user.FailedLoginAttempts > 0)
            ResetFailedAttempts(user);

        // ── 沉睡账号治理：记录最后一次成功登录 ──
        // 为什么记在"登录成功"这一处：它是全系统唯一入口（任何操作都要先拿票据），
        // 于是"在这写一次"就等于"覆盖全部真实使用"。沉睡判定以本字段为基准，
        // 漏写会让活跃账号被误判成沉睡 —— 这是本功能最不能出错的地方。
        // 注意：人脸没过的那次**不算**成功登录，因此不会走到这里，
        // lastLoginAt 也就不会被一次失败的尝试刷新。
        user.LastLoginAt = DateTime.UtcNow;

        // 上面两条改动合并在一次写入里（而不是各写一次）：
        // 同一请求内对同一文档的两次 Replace 会白跑一次往返，也更容易在
        // 未来某次改动中漏掉其中一条。
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

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
            new
            {
                user.Username,
                user.Status,
                Role = user.Role.ToString(),
                TicketIssued = true,
                SecondFactor = secondFactor ? "FACE" : "NONE"
            },
            user.Status.ToString(), target, AuditResult.Success);
        return Ok(successResp);
    }
}
