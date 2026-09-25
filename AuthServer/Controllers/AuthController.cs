using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly MongoDbService _db;
    private readonly VerificationService _codes;
    private readonly EmailOptions _emailOptions;
    private readonly AuditService _audit;
    private readonly SessionService _sessions;
    private const int MaxFailedAttempts = 3;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(3);

    public AuthController(MongoDbService db, VerificationService codes, EmailOptions emailOptions,
        AuditService audit, SessionService sessions)
    {
        _db = db;
        _codes = codes;
        _emailOptions = emailOptions;
        _audit = audit;
        _sessions = sessions;
    }

    // 密码复杂度校验：至少8位，包含大小写字母和数字
    private static bool IsPasswordComplex(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
            return false;
        if (!Regex.IsMatch(password, @"[A-Z]"))
            return false;
        if (!Regex.IsMatch(password, @"[a-z]"))
            return false;
        if (!Regex.IsMatch(password, @"[0-9]"))
            return false;
        return true;
    }

    private static string Norm(string? username) => username?.Trim().ToLowerInvariant() ?? string.Empty;

    private static UserResponse ToUserResponse(User u) => new()
    {
        Id = u.Id,
        Username = u.Username,
        Status = u.Status.ToString(),
        Role = u.Role.ToString(),
        RoleLabel = UserRoles.Label(u.Role),
        // 邮箱一律脱敏后返回，管理员能看到"有没有绑、绑没绑好"，但拿不到完整地址
        Email = EmailUtil.Mask(u.Email),
        EmailVerified = u.EmailVerified,
        FailedLoginAttempts = u.FailedLoginAttempts,
        LockoutEnd = u.LockoutEnd,
        CreatedAt = u.CreatedAt,
        // 由角色派生：只有能管用户的两种角色才为 true。
        // 审计管理员在此为 false —— 他看日志，但管不了任何账号。
        IsAdmin = UserRoles.CanManageUsers(u.Role)
    };

    /**
     * 写入审计日志。
     *
     * 设计要点：
     *   - 审计是旁路记录，任何异常都不能影响主业务流程（鲁棒性要求）。
     *   - result 独立成列：登录成功与登录失败是同一个业务入口的两种结局，
     *     必须能被审计人员一眼区分。
     *   - target 记录被操作对象（注册/审核/解锁/注销/转让），便于按用户检索。
     *   - 任何分支（含越权、参数校验失败、目标不存在）都要落日志，
     *     否则"失败的操作"会在审计中凭空消失，形成盲区。
     *   - reasonCode 说明"为什么失败"，让越权尝试与口令错误可被分开检索。
     *   - 来源信息（IP / UA）由本方法自动补齐，调用方不必关心。
     *
     * 实际写入委托给 AuditService：由它串行化计算哈希链并选择分片集合，
     * 从而保证并发写入不破坏链的完整性。
     */
    private Task WriteAuditLogAsync(string operatorId, string operatorName, string action,
        string statusBefore, object request, object response, string statusAfter,
        string target = "", string result = AuditResult.Success, string reasonCode = "",
        string actorType = "")
    {
        return _audit.WriteAsync(new AuditEntry
        {
            OperatorId = operatorId,
            OperatorName = operatorName,
            Action = action,
            StatusBefore = statusBefore,
            Request = request,
            Response = response,
            StatusAfter = statusAfter,
            Target = target,
            Result = result,
            ReasonCode = reasonCode,
            ActorType = actorType,
            SourceIp = ClientIp(),
            SourceUserAgent = Request.Headers.UserAgent.ToString()
        });
    }

    /** 取调用方 IP。桌面端与浏览器都经本机回环，因此优先读 X-Forwarded-For（若有代理）。 */
    private string ClientIp()
    {
        var forwarded = Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(forwarded))
            return forwarded.Split(',')[0].Trim();
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    /* ==================== 时钟护栏的调用侧 ==================== */

    /**
     * 锁定拒绝的统一出口。
     *
     * 为什么要把这段抽出来：三个入口（登录 / 改密 / 重置口令）的锁定拒绝必须**逐字一致**。
     * 一旦各写各的，剩余秒数就可能有的按墙钟算、有的按单调线算，
     * 界面会出现"显示还剩 0 秒却仍然拒绝"这种自相矛盾 —— 而那恰好是
     * 一个正在被拨动的时钟最典型的表现。
     * 统一出口后，"判定用哪条时间线"这件事只有 TimeGuard 一个地方说了算。
     */
    private async Task<IActionResult> LockoutRejectionAsync(User user, LockoutVerdict verdict,
        string action, string statusBefore, object requestLog, string target,
        string messagePrefix, int httpStatus)
    {
        var resp = new ApiResponse
        {
            Success = false,
            Code = "ACCOUNT_LOCKED",
            Message = $"{messagePrefix}{verdict.RemainingSeconds} 秒后再试",
            Data = new { LockoutEnd = user.LockoutEnd, RemainingSeconds = verdict.RemainingSeconds }
        };
        await WriteAuditLogAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
            target, AuditResult.Failed, AuditReason.AccountLocked);
        return StatusCode(httpStatus, resp);
    }

    /**
     * 发现时钟背离时留一条审计。
     *
     * 加固前，靠拨钟解开锁定是**完全静默**的：锁定到期走登录里的"自动恢复"分支，
     * 而那个分支不写任何日志。于是事后翻审计，看不出这个账号曾被"用改时间的方式"放进去过。
     * 有了这条记录，"有人动过时钟"本身成为可检索的事件。
     *
     * 两个刻意的取舍：
     *   1. 同一次锁定只记一条（靠 lockoutDriftLogged 收敛）。时钟被拨动后不会自己回来，
     *      否则之后每一次尝试都会被判为背离，把审计刷成一屏重复告警 ——
     *      真正的事件反而被淹掉。
     *   2. 只翻标志位用 UpdateOne，不整篇 ReplaceOne：本分支不改动用户文档的其它内容，
     *      没必要多写一遍。
     */
    private async Task LogClockDriftIfAnyAsync(User user, LockoutVerdict verdict, string trigger, string target)
    {
        if (verdict.Drift == ClockDrift.None || user.LockoutDriftLogged) return;

        var forward = verdict.Drift == ClockDrift.Forward;
        await WriteAuditLogAsync(user.Id, user.Username, AuditAction.ClockAnomaly, user.Status.ToString(),
            new
            {
                Trigger = trigger,
                WallNow = TimeGuard.WallNow(),
                // 单调线推算出的"现在"：与墙钟的差就是被拨动的量
                UptimeImpliedNow = verdict.ReliableNow,
                DriftSeconds = verdict.DriftSeconds,
                // 演示开关若开着，记录里留个痕，事后能区分"演示模拟"与"真实拨钟"
                DemoSkewSeconds = TimeGuard.DemoSkewActive ? TimeGuard.DemoSkewSeconds : 0
            },
            new { Code = "CLOCK_ANOMALY", Drift = verdict.Drift.ToString(), RemainingSeconds = verdict.RemainingSeconds },
            user.Status.ToString(), target, AuditResult.Failed,
            forward ? AuditReason.ClockRolledForward : AuditReason.ClockRolledBackward);

        user.LockoutDriftLogged = true;
        await _db.Users.UpdateOneAsync(u => u.Id == user.Id,
            Builders<User>.Update.Set(u => u.LockoutDriftLogged, true));
    }

    /**
     * 清除锁定时钟锚点。
     *
     * 与 lockoutEnd 的清除**必须同步**（凡置 null 处都要调一次）：
     * 锚点若留在文档里而锁定已结束，下一次锁定虽然会覆盖它们，
     * 但"锁定已解除却仍带着锁定锚点"这个中间状态会让任何按字段排查的人把结论带偏。
     * 让 lockoutEnd 为 null 与三个锚点为 null 保持等价，是最省心的不变式。
     */
    private static void ClearLockoutAnchor(User user)
    {
        user.LockoutWallAt = null;
        user.LockoutUptimeAt = null;
        user.LockoutDriftLogged = false;
    }

    /* ==================== 会话票据鉴权 ==================== */

    /** 从 Authorization: Bearer <ticket> 中取出票据。 */
    private string? ReadTicket()
    {
        var raw = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(raw)) return null;
        const string prefix = "Bearer ";
        return raw.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? raw[prefix.Length..].Trim()
            : null;
    }

    /**
     * 受保护接口的统一入口守卫，按所需访问级别分三个入口。
     *
     * 为什么拆成三个而不是一个带 bool 的：
     *   "是不是管理员"这种二元判断已经不足以描述本系统的权限边界 ——
     *   用户管理员能管用户但不能任免角色，审计管理员能看日志但管不了账号。
     *   每个接口显式声明自己要哪一级，声明错了在验收时会立刻暴露。
     *
     * 鉴权失败时**本身也要留下审计记录** —— 这是实验二「02 看不到」的关键证据：
     * 光有拒绝响应不够，必须证明系统把这次越权尝试也记下来了。
     */

    /// <summary>需要用户管理能力（Admin / UserAdmin）：审核、解锁、删除普通用户。</summary>
    private Task<(User? Admin, IActionResult? Deny)> RequireUserAdminAsync(string action, string target = "")
        => RequireAsync(AccessLevel.UserAdmin, action, target);

    /// <summary>需要角色任免能力（仅 Admin）：创建账号、变更他人角色。</summary>
    private Task<(User? Admin, IActionResult? Deny)> RequireAdminAsync(string action, string target = "")
        => RequireAsync(AccessLevel.Admin, action, target);

    /// <summary>需要审计读取能力（仅 AuditAdmin）。管理员的票据到这里会被拒。</summary>
    private Task<(User? Auditor, IActionResult? Deny)> RequireAuditAsync(string action, string target = "")
        => RequireAsync(AccessLevel.AuditRead, action, target);

    private async Task<(User? Operator, IActionResult? Deny)> RequireAsync(
        AccessLevel level, string action, string target)
    {
        var ticket = ReadTicket();
        var auth = await _sessions.ValidateAsync(ticket, level);

        if (!auth.Success)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = auth.ReasonCode,
                Message = auth.Message
            };
            var statusBefore = auth.User?.Status.ToString() ?? "N/A";
            await WriteAuditLogAsync(
                auth.User?.Id ?? "anonymous",
                auth.User?.Username ?? "anonymous",
                action, statusBefore,
                // 保留被尝试访问的接口与原始查询串：越权尝试最常见的形态就是
                // "在 URL 里声明自己是管理员"（如 ?adminUsername=admin），
                // 留住原始请求形态，才能证明拦截的究竟是哪一类伪冒手法。
                // Role 一并记下，"管理员来够审计数据"这类越界才能被单独筛出来。
                new
                {
                    AttemptedTarget = target,
                    Reason = auth.ReasonCode,
                    Role = auth.User is null ? "anonymous" : auth.User.Role.ToString(),
                    Path = Request.Path.Value,
                    Query = Request.QueryString.Value
                },
                resp, statusBefore, target, AuditResult.Failed, auth.ReasonCode);
            return (null, StatusCode(auth.HttpStatus, resp));
        }

        return (auth.User, null);
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
            await WriteAuditLogAsync("anonymous", "anonymous", AuditAction.Logout, "N/A",
                new { Reason = auth.ReasonCode }, quiet, "N/A", "", AuditResult.Failed, auth.ReasonCode);
            return StatusCode(auth.HttpStatus, quiet);
        }

        await _sessions.RevokeAsync(ticket!, "用户主动登出");
        var resp = new ApiResponse { Success = true, Code = "OK", Message = "已安全退出" };
        await WriteAuditLogAsync(auth.User!.Id, auth.User.Username, AuditAction.Logout,
            auth.User.Status.ToString(), new { }, resp, auth.User.Status.ToString(),
            auth.User.Username, AuditResult.Success);
        return Ok(resp);
    }

    /* ==================== 注册（绑定邮箱） ==================== */

    /**
     * 注册流程改为"先验证邮箱、后落库"：
     *   1. 前端先调用 send-email-code（purpose=REGISTER）拿到验证码；
     *   2. 本接口校验通过后才创建账号（状态仍为待审核）。
     *
     * 这样库里不会出现"邮箱是乱填的"垃圾账号，也不必再维护未验证账号的清理逻辑。
     * 注意：发码与校验之间存在几分钟空档，用户名/邮箱可能在此期间被他人占用，
     *       因此建号前会再查一次重。
     */
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req)
    {
        var sanitizedUsername = Norm(req.Username);
        var email = EmailUtil.Normalize(req.Email);
        // 口令与验证码都不入日志，邮箱脱敏
        var requestLog = new { req.Username, Email = EmailUtil.Mask(req.Email) };
        var emailRequired = _emailOptions.Enabled;

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "用户名或密码不能为空" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.Password))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "WEAK_PASSWORD",
                Message = "密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.WeakPassword);
            return BadRequest(resp);
        }

        if (emailRequired && !EmailUtil.IsValid(email))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_EMAIL", Message = "请输入有效的邮箱地址" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.InvalidEmail);
            return BadRequest(resp);
        }

        var existing = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (existing != null)
        {
            var resp = new ApiResponse { Success = false, Code = "DUPLICATE_USERNAME", Message = "用户名已存在" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, existing.Status.ToString(),
                sanitizedUsername, AuditResult.Failed, AuditReason.DuplicateUsername);
            return Conflict(resp);
        }

        if (emailRequired)
        {
            var boundUser = await _db.Users.Find(u => u.Email == email).FirstOrDefaultAsync();
            if (boundUser != null)
            {
                var resp = new ApiResponse { Success = false, Code = "EMAIL_ALREADY_BOUND", Message = "该邮箱已被其它账号绑定" };
                await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, boundUser.Status.ToString(),
                    sanitizedUsername, AuditResult.Failed, AuditReason.EmailAlreadyBound);
                return Conflict(resp);
            }

            // 用途隔离：只接受 purpose=REGISTER 的验证码；
            // 并把所填邮箱一并传入比对，防止"用 A 邮箱的码去绑 B 邮箱"。
            // 该比对发生在消耗验证码之前，用户只是填错邮箱时不会白白烧掉一次验证码。
            var verify = await _codes.VerifyAsync(sanitizedUsername, EmailCodePurpose.Register, req.Code, email);
            if (!verify.Success)
            {
                var resp = new ApiResponse { Success = false, Code = verify.Code, Message = verify.Message };
                await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                    sanitizedUsername, AuditResult.Failed, VerifyCodeReason.From(verify.Code));
                return BadRequest(resp);
            }

            // 建号前再查一次重（发码/校验期间可能已被抢注）
            existing = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
            if (existing != null)
            {
                var resp = new ApiResponse { Success = false, Code = "DUPLICATE_USERNAME", Message = "用户名已存在" };
                await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, existing.Status.ToString(),
                    sanitizedUsername, AuditResult.Failed, AuditReason.DuplicateUsername);
                return Conflict(resp);
            }
        }

        var user = new User
        {
            Username = sanitizedUsername,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password),
            Status = UserStatus.Pending,
            // 邮件功能关闭时回退为"无邮箱的老流程"，避免外部依赖不可用就完全无法注册
            Email = emailRequired ? email : null,
            EmailVerified = emailRequired,
            FailedLoginAttempts = 0,
            CreatedAt = DateTime.UtcNow
        };

        await _db.Users.InsertOneAsync(user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = emailRequired
                ? "注册成功，邮箱已验证，等待管理员审核"
                : "注册成功，等待管理员审核",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, response, user.Status.ToString(),
            sanitizedUsername, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 发送邮箱验证码 ==================== */

    /**
     * 发送邮箱验证码，支持两种用途：
     *   REGISTER —— 注册绑定邮箱；
     *   RESET    —— 忘记密码（用户名 + 邮箱必须与库中已绑定且已验证的邮箱一致）。
     *
     * 安全要点：
     *   - 用途隔离：REGISTER 与 RESET 的验证码互不通用；
     *   - 防枚举：RESET 场景下账号不存在或邮箱不匹配时，返回与成功**完全相同**的响应，
     *     只是不真正发信，避免把"哪些用户名存在、绑了哪个邮箱"暴露出去；
     *   - 状态门禁：待审核 / 已禁用 / 锁定中一律拒绝（能走到这一步说明用户名+邮箱已对得上）。
     */
    [HttpPost("send-email-code")]
    public async Task<IActionResult> SendEmailCode([FromBody] SendEmailCodeRequest req)
    {
        const string action = AuditAction.SendEmailCode;
        // 发码被拒同样是安全事件（有人在批量试探邮箱、或撞限流），单独动作便于检索
        const string failedAction = AuditAction.SendEmailCodeFailed;
        var username = Norm(req.Username);
        var email = EmailUtil.Normalize(req.Email);
        var purpose = (req.Purpose ?? string.Empty).Trim().ToUpperInvariant();
        var requestLog = new { Purpose = purpose, req.Username, Email = EmailUtil.Mask(req.Email) };

        if (!_emailOptions.Enabled)
        {
            var resp = new ApiResponse { Success = false, Code = "EMAIL_DISABLED", Message = "邮件服务当前未启用，请联系管理员" };
            await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.EmailDisabled);
            return StatusCode(503, resp);
        }

        if (!EmailCodePurpose.IsValid(purpose))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_PURPOSE", Message = "验证码用途不合法" };
            await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.InvalidPurpose);
            return BadRequest(resp);
        }

        if (string.IsNullOrWhiteSpace(username) || !EmailUtil.IsValid(email))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_EMAIL", Message = "请填写用户名和有效的邮箱地址" };
            await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.InvalidEmail);
            return BadRequest(resp);
        }

        if (purpose == EmailCodePurpose.Register)
        {
            var taken = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
            if (taken != null)
            {
                var resp = new ApiResponse { Success = false, Code = "DUPLICATE_USERNAME", Message = "用户名已存在" };
                await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, resp, taken.Status.ToString(),
                    username, AuditResult.Failed, AuditReason.DuplicateUsername);
                return Conflict(resp);
            }

            var boundUser = await _db.Users.Find(u => u.Email == email).FirstOrDefaultAsync();
            if (boundUser != null)
            {
                var resp = new ApiResponse { Success = false, Code = "EMAIL_ALREADY_BOUND", Message = "该邮箱已被其它账号绑定" };
                await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, resp, boundUser.Status.ToString(),
                    username, AuditResult.Failed, AuditReason.EmailAlreadyBound);
                return Conflict(resp);
            }
        }
        else
        {
            var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
            var matched = user != null
                && !string.IsNullOrEmpty(user.Email)
                && string.Equals(user.Email, email, StringComparison.Ordinal)
                && user.EmailVerified;

            if (!matched)
            {
                // 防枚举：与成功响应逐字一致，仅不发信。
                //
                // 注意这里的记录形态：对外是"成功"（返回 200 且报文与真实发信完全一致），
                // 对内必须记成**失败** —— 因为审计要回答的是"信到底发没发出去"。
                // 若跟着响应记成成功，这条线索就彻底消失了。
                var generic = BuildSendCodeSuccess(email);
                await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, generic,
                    user?.Status.ToString() ?? "N/A", username, AuditResult.Failed, AuditReason.InvalidCredentials);
                return Ok(generic);
            }

            var statusBefore = user!.Status.ToString();

            if (user.Status == UserStatus.Pending)
            {
                var resp = new ApiResponse { Success = false, Code = "PENDING_APPROVAL", Message = "账号待审核，暂不能重置密码" };
                await WriteAuditLogAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
                    username, AuditResult.Failed, AuditReason.PendingApproval);
                return StatusCode(403, resp);
            }

            if (user.Status == UserStatus.Disabled)
            {
                var resp = new ApiResponse { Success = false, Code = "ACCOUNT_DISABLED", Message = "账号已被禁用，无法重置密码" };
                await WriteAuditLogAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
                    username, AuditResult.Failed, AuditReason.AccountDisabled);
                return StatusCode(403, resp);
            }

            if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue)
            {
                var verdict = TimeGuard.Assess(user, TimeGuard.WallNow(), TimeGuard.UptimeMs());
                await LogClockDriftIfAnyAsync(user, verdict, "SEND_EMAIL_CODE", username);

                if (verdict.Locked)
                    return await LockoutRejectionAsync(user, verdict, failedAction, statusBefore,
                        requestLog, username, "账号处于锁定状态，请 ", 423);
            }

            // 锁定已到期：顺手恢复启用态，避免"锁定期已过但仍被拒"的错觉
            if (user.Status == UserStatus.Locked)
            {
                user.Status = UserStatus.Enabled;
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;
                ClearLockoutAnchor(user);
                await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            }
        }

        var send = await _codes.SendAsync(username, email, purpose);
        if (!send.Success)
        {
            var failure = new ApiResponse { Success = false, Code = send.Code, Message = send.Message };
            var httpCode = send.Code == "RESEND_TOO_SOON" ? 429 : 502;
            await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, failure, "N/A",
                username, AuditResult.Failed, SendCodeReason.From(send.Code));
            return StatusCode(httpCode, failure);
        }

        var success = BuildSendCodeSuccess(email);
        await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, success, "N/A",
            username, AuditResult.Success);
        return Ok(success);
    }

    /**
     * 发送成功响应：注册与找回密码共用，保证外形一致（防枚举）。
     * 同时告知当前发件通道，界面据此提示"验证码在后端日志里"还是"请查收邮件"。
     */
    private ApiResponse BuildSendCodeSuccess(string email) => new()
    {
        Success = true,
        Code = "OK",
        Message = "若该账号与邮箱匹配，验证码已发送，5 分钟内有效",
        Data = new
        {
            MaskedEmail = EmailUtil.Mask(email),
            ExpiresIn = 300,
            ResendAfter = 60,
            Channel = _codes.SenderName,
            DeliversRealMail = _codes.DeliversRealMail
        }
    };

    /* ==================== 忘记密码：重置密码 ==================== */

    /**
     * 通过邮箱验证码重置口令。
     *
     * 刻意不提供"验证码直接登录"：本接口只改密码，不签发任何会话，
     * 系统里因此不存在"不凭口令就能建立会话"的通道。
     * 锁定 / 待审核 / 已禁用状态一律拒绝，防止用验证码绕过 3 次锁定策略。
     */
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest req)
    {
        // 动作名随结果切换：失败改用 RESET_PASSWORD_FAILED。
        //
        // "重置口令失败"与"重置口令成功"在审计上是两件程度完全不同的事 ——
        // 前者意味着有人正在用验证码入口试探账号，后者只是一次正常的找回。
        // 拆开之后，审计员一条查询就能列出全部失败尝试，不必再叠加 result 条件。
        const string action = AuditAction.ResetPassword;
        const string failedAction = AuditAction.ResetPasswordFailed;
        var username = Norm(req.Username);
        var email = EmailUtil.Normalize(req.Email);
        // 新旧口令、验证码都不入日志
        var requestLog = new { req.Username, Email = EmailUtil.Mask(req.Email) };

        if (!_emailOptions.Enabled)
        {
            var resp = new ApiResponse { Success = false, Code = "EMAIL_DISABLED", Message = "邮件服务当前未启用，请联系管理员" };
            await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.EmailDisabled);
            return StatusCode(503, resp);
        }

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(req.NewPassword))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "用户名与新密码不能为空" };
            await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.NewPassword))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "WEAK_PASSWORD",
                Message = "新密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.WeakPassword);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();

        // 账号不存在 / 未绑邮箱 / 邮箱不匹配：统一话术，不透露具体是哪一种
        if (user == null
            || string.IsNullOrEmpty(user.Email)
            || !string.Equals(user.Email, email, StringComparison.Ordinal)
            || !user.EmailVerified)
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "用户名与邮箱不匹配" };
            await WriteAuditLogAsync("anonymous", username, failedAction, "N/A", requestLog, resp,
                user?.Status.ToString() ?? "N/A", username, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        if (user.Status == UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = "PENDING_APPROVAL", Message = "账号待审核，暂不能重置密码" };
            await WriteAuditLogAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
                username, AuditResult.Failed, AuditReason.PendingApproval);
            return StatusCode(403, resp);
        }

        if (user.Status == UserStatus.Disabled)
        {
            var resp = new ApiResponse { Success = false, Code = "ACCOUNT_DISABLED", Message = "账号已被禁用，无法重置密码" };
            await WriteAuditLogAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
                username, AuditResult.Failed, AuditReason.AccountDisabled);
            return StatusCode(403, resp);
        }

        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue)
        {
            var verdict = TimeGuard.Assess(user, TimeGuard.WallNow(), TimeGuard.UptimeMs());
            await LogClockDriftIfAnyAsync(user, verdict, "RESET_PASSWORD", username);

            if (verdict.Locked)
                return await LockoutRejectionAsync(user, verdict, failedAction, statusBefore,
                    requestLog, username, "账号处于锁定状态，请 ", 423);
        }

        var verify = await _codes.VerifyAsync(username, EmailCodePurpose.Reset, req.Code, email);
        if (!verify.Success)
        {
            var resp = new ApiResponse { Success = false, Code = verify.Code, Message = verify.Message };
            await WriteAuditLogAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
                username, AuditResult.Failed, VerifyCodeReason.From(verify.Code));
            return BadRequest(resp);
        }

        // 重置成功：换口令，并一并清掉锁定与失败计数（否则改完密码仍被锁在门外）
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword);
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        ClearLockoutAnchor(user);
        if (user.Status == UserStatus.Locked) user.Status = UserStatus.Enabled;
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = "密码已重置，请使用新密码登录",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync(user.Id, user.Username, action, statusBefore, requestLog, response, user.Status.ToString(),
            username, AuditResult.Success);
        return Ok(response);
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
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "用户名或密码不能为空" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (user == null)
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "用户名或密码错误" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
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
            var resp = new ApiResponse { Success = false, Code = "PENDING_APPROVAL", Message = "账号待审核，请联系管理员" };
            await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, user.Status.ToString(),
                sanitizedUsername, AuditResult.Failed, AuditReason.PendingApproval);
            return Unauthorized(resp);
        }

        var passwordValid = BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash);
        if (!passwordValid)
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
                code = "ACCOUNT_LOCKED";
                // 本次尝试既"口令错"也"触发锁定"，审计语义上按更严重的锁定归类：
                // 审计员要能一条查询捞出"所有因口令错误而锁定的事件"。
                reason = AuditReason.AccountLocked;
            }
            else
            {
                message = $"密码错误，还剩 {MaxFailedAttempts - user.FailedLoginAttempts} 次机会";
                code = "INVALID_CREDENTIALS";
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
            await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, user.Status.ToString(),
                sanitizedUsername, AuditResult.Failed, reason);
            return Unauthorized(resp);
        }

        // 登录成功，重置失败计数
        if (user.FailedLoginAttempts > 0)
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            ClearLockoutAnchor(user);
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
        }

        // 登录成功 → 签发服务端会话票据。
        // 票据是后续所有管理员接口的凭证，也是"普通用户无权查看审计日志"能成立的前提。
        var session = await _sessions.IssueAsync(user);

        var successResp = new ApiResponse<LoginResult>
        {
            Success = true,
            Code = "OK",
            Message = "登录成功",
            Data = new LoginResult
            {
                Username = user.Username,
                Status = user.Status.ToString(),
                Role = user.Role.ToString(),
                RoleLabel = UserRoles.Label(user.Role),
                IsAdmin = UserRoles.CanManageUsers(user.Role),
                Ticket = session.Ticket,
                ExpiresAt = session.ExpiresAt
            }
        };
        // 审计里绝不记录票据本体，只记"已签发"这一事实
        await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginSuccess, statusBefore, requestLog,
            new { user.Username, user.Status, Role = user.Role.ToString(), TicketIssued = true },
            user.Status.ToString(), sanitizedUsername, AuditResult.Success);
        return Ok(successResp);
    }

    /* ==================== 管理员：审核 ==================== */

    [HttpPost("approve")]
    public async Task<IActionResult> Approve([FromBody] ApproveRequest req)
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.Approve, Norm(req.Username));
        if (deny != null) return deny;
        var requestLog = new { req.Username };

        var user = await _db.Users.Find(u => u.Username == Norm(req.Username)).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = "NOT_FOUND", Message = "用户不存在" };
            await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.Approve, "N/A", requestLog, missing, "N/A",
                Norm(req.Username), AuditResult.Failed, AuditReason.NotFound);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();
        if (user.Status != UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = "NOT_PENDING", Message = "该用户不处于待审核状态" };
            await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.Approve, statusBefore, requestLog, resp, user.Status.ToString(),
                user.Username, AuditResult.Failed, AuditReason.NotPending);
            return BadRequest(resp);
        }

        user.Status = UserStatus.Enabled;
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = "审核通过",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.Approve, statusBefore, requestLog, response, user.Status.ToString(),
            user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：解锁 ==================== */

    [HttpPost("unlock")]
    public async Task<IActionResult> Unlock([FromBody] UnlockRequest req)
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.Unlock, Norm(req.Username));
        if (deny != null) return deny;
        var requestLog = new { req.Username };

        var user = await _db.Users.Find(u => u.Username == Norm(req.Username)).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = "NOT_FOUND", Message = "用户不存在" };
            await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.Unlock, "N/A", requestLog, missing, "N/A",
                Norm(req.Username), AuditResult.Failed, AuditReason.NotFound);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();
        if (user.Status != UserStatus.Locked)
        {
            var resp = new ApiResponse { Success = false, Code = "NOT_LOCKED", Message = "该用户未被锁定" };
            await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.Unlock, statusBefore, requestLog, resp, user.Status.ToString(),
                user.Username, AuditResult.Failed, AuditReason.NotLocked);
            return BadRequest(resp);
        }

        user.Status = UserStatus.Enabled;
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        ClearLockoutAnchor(user);
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = "账号已解锁",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.Unlock, statusBefore, requestLog, response, user.Status.ToString(),
            user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：注销用户 ==================== */

    [HttpPost("delete-user")]
    public async Task<IActionResult> DeleteUser([FromBody] DeleteUserRequest req)
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.DeleteUser, Norm(req.Username));
        if (deny != null) return deny;
        var requestLog = new { req.Username };

        var username = Norm(req.Username);
        var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = "NOT_FOUND", Message = "用户不存在" };
            await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.DeleteUser, "N/A", requestLog, missing, "N/A",
                username, AuditResult.Failed, AuditReason.NotFound);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();

        // 处置范围随操作者身份而定（判定集中在 UserRoles.CanBeManagedBy）：
        //   · 管理员（Admin）—— 除自己以外任何账号都能注销，含审计管理员与其它管理员；
        //   · 用户管理员（UserAdmin）—— 只能注销普通用户与用户管理员，够不到上级。
        //
        // 唯一不随身份变化、也不随目标角色变化的例外是"自己"：
        // 若允许自我注销，操作者就可能把系统里最后一个管理员删掉，
        // 从而再没有人能任命角色。自我豁免同时保证了"操作者操作完仍是管理员"。
        if (!UserRoles.CanBeManagedBy(admin!, user))
        {
            var isSelf = UserRoles.IsSameAccount(admin!, user);
            var denied = new ApiResponse
            {
                Success = false,
                Code = "FORBIDDEN_TARGET",
                Message = isSelf
                    ? "不能注销自己的账号。如需转让职责，请先创建另一位管理员。"
                    : $"当前身份「{UserRoles.Label(admin!.Role)}」不能注销"
                        + $"「{UserRoles.Label(user.Role)}」账号。"
            };
            await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.DeleteUser, statusBefore, requestLog, denied, statusBefore,
                user.Username, AuditResult.Failed, AuditReason.ForbiddenTarget);
            return BadRequest(denied);
        }

        await _db.Users.DeleteOneAsync(u => u.Id == user.Id);

        // 账号已被注销，其名下所有票据必须立即失效 ——
        // 否则被注销的人手里若还留着票据，仍能继续调用接口。
        await _sessions.RevokeAllForUserAsync(user.Username, "账号被管理员注销");

        var response = new ApiResponse
        {
            Success = true,
            Code = "OK",
            Message = $"已注销用户「{user.Username}」",
            Data = new { Username = user.Username }
        };
        await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.DeleteUser, statusBefore, requestLog, response, "Deleted",
            user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：创建账号 ==================== */

    /// <summary>
    /// 允许被创建的两种角色。
    ///
    /// 刻意**不含 Admin**：Admin 是角色任免权的持有者，若能凭空再造一个 Admin，
    /// 就存在"管理员自我复制、稀释责任"的路径。需要有人分担任免权时，
    /// 应当由人来决定并明确留痕，而不是让程序放开这个口子。
    /// </summary>
    private static bool CanBeCreatedRole(UserRole role) =>
        role is UserRole.UserAdmin or UserRole.AuditAdmin;

    /**
     * 由管理员创建「用户管理员」或「审计管理员」账号。
     *
     * 与自助注册的本质区别：
     *   - **不绑邮箱、不发验证码**（需求明确要求）；
     *   - **建号即启用**，不走待审核；
     *   - 因此这个接口本身就是一条高权限通道 —— 一旦被冒用就能凭空造出管理员，
     *     所以必须**二次校验操作者本人的登录口令**：
     *     仅凭会话票据不足以证明是本人操作，票据被盗时攻击者不该能直接造账号。
     *
     * 校验顺序上把口令校验放在"用户名查重"之前：
     * 查重会回答"这个用户名是否存在"，属于可被利用的信息；
     * 先证明是本人，再去查库。
     */
    [HttpPost("create-account")]
    public async Task<IActionResult> CreateAccount([FromBody] CreateAccountRequest req)
    {
        const string action = AuditAction.CreateAccount;
        var targetName = Norm(req.Username);
        // 初始口令与操作者口令都不入日志
        var requestLog = new { req.Username, req.Role };

        if (string.IsNullOrWhiteSpace(targetName) || string.IsNullOrWhiteSpace(req.Password)
            || string.IsNullOrWhiteSpace(req.Role))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "用户名、初始口令与角色不能为空" };
            await WriteAuditLogAsync("anonymous", "anonymous", action, "N/A", requestLog, resp, "N/A",
                targetName, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        var (admin, deny) = await RequireAdminAsync(action, targetName);
        if (deny != null) return deny;
        var operatorLabel = $"{admin!.Username}·{UserRoles.Label(admin.Role)}";

        if (!UserRoles.TryParse(req.Role, out var newRole) || !CanBeCreatedRole(newRole))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "FORBIDDEN_ROLE",
                Message = "只能创建「用户管理员」或「审计管理员」账号"
            };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.ForbiddenRole);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.Password))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "WEAK_PASSWORD",
                Message = "初始密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.WeakPassword);
            return BadRequest(resp);
        }

        // 二次口令：创建管理员是特权变更，仅凭会话不足以证明是本人操作
        if (!BCrypt.Net.BCrypt.Verify(req.OperatorPassword, admin.PasswordHash))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "管理员口令校验失败，已拒绝创建" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        var existing = await _db.Users.Find(u => u.Username == targetName).FirstOrDefaultAsync();
        if (existing != null)
        {
            var resp = new ApiResponse { Success = false, Code = "DUPLICATE_USERNAME", Message = "用户名已存在" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.DuplicateUsername);
            return Conflict(resp);
        }

        var user = new User
        {
            Username = targetName,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password),
            Status = UserStatus.Enabled,
            Role = newRole,
            // 管理员创建的账号一律不绑邮箱，只凭口令登录（需求明确要求）
            Email = null,
            EmailVerified = false,
            FailedLoginAttempts = 0,
            CreatedAt = DateTime.UtcNow
        };
        await _db.Users.InsertOneAsync(user);

        var newLabel = $"{user.Username}·{UserRoles.Label(newRole)}";
        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = $"已创建{UserRoles.Label(newRole)}账号「{user.Username}」，该账号无需邮箱、可直接登录",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, response,
            newLabel, user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：变更他人角色 ==================== */

    /**
     * 变更他人角色 —— "指定某位管理员为审计管理员"就是走这里。
     *
     * 三条硬约束：
     *   1. 只能由 Admin 发起（AccessLevel.Admin），用户管理员无权任免角色；
     *   2. 不能把任何人设为 Admin，与 create-account 同理，杜绝管理员自我复制；
     *   3. **不能变更自己** —— 若管理员能改自己的角色，他就能把自己降成审计管理员
     *      去读日志，职责分离当场失效。自我提权必须是死路。
     *
     * 除此之外，处置范围随操作者身份而定（见 UserRoles.CanBeManagedBy）：
     * 管理员可变更除自己以外任意账号的角色，含审计管理员与其它管理员。
     * SetRole 的门槛是 AccessLevel.Admin，所以实际能走到这里的操作者只有管理员，
     * 该判定当前恒真 —— 保留它是为了让规则只写一处：日后若有更低的角色
     * 获得任免权，无需回头再补目标侧的校验。
     *
     * 变更成功后立刻吊销目标账号的全部票据：
     * 旧票据虽然因"每次实时查库"而立刻失去（或获得）对应权限，
     * 但让对方重新登录、亲眼看到自己的新身份，比"权限悄悄变了"更清楚。
     */
    [HttpPost("set-role")]
    public async Task<IActionResult> SetRole([FromBody] SetRoleRequest req)
    {
        const string action = AuditAction.SetRole;
        var targetName = Norm(req.Username);
        var requestLog = new { req.Username, req.Role };

        if (string.IsNullOrWhiteSpace(targetName) || string.IsNullOrWhiteSpace(req.Role))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "目标用户名与目标角色不能为空" };
            await WriteAuditLogAsync("anonymous", "anonymous", action, "N/A", requestLog, resp, "N/A",
                targetName, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        var (admin, deny) = await RequireAdminAsync(action, targetName);
        if (deny != null) return deny;
        var operatorLabel = $"{admin!.Username}·{UserRoles.Label(admin.Role)}";

        if (!UserRoles.TryParse(req.Role, out var newRole))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_ROLE", Message = "无法识别的角色标识" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.ForbiddenRole);
            return BadRequest(resp);
        }

        // 约束 2：不能把任何人（包括自己）设为管理员
        if (newRole == UserRole.Admin)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "FORBIDDEN_ROLE",
                Message = "不能把账号设为「管理员」。如需分担用户管理，请创建「用户管理员」。"
            };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.ForbiddenRole);
            return BadRequest(resp);
        }

        // 约束 3：不能变更自己
        if (targetName == admin.Username)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "CANNOT_SET_OWN_ROLE",
                Message = "不能变更自己的角色。如需调整职责，请由另一位管理员操作。"
            };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.ForbiddenRole);
            return BadRequest(resp);
        }

        // 二次口令：角色任免是系统内权限最高的操作
        if (!BCrypt.Net.BCrypt.Verify(req.OperatorPassword, admin.PasswordHash))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "管理员口令校验失败，已拒绝变更" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        var target = await _db.Users.Find(u => u.Username == targetName).FirstOrDefaultAsync();
        if (target == null)
        {
            var resp = new ApiResponse { Success = false, Code = "NOT_FOUND", Message = "目标用户不存在" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.NotFound);
            return NotFound(resp);
        }

        var statusBefore = $"{target.Username}·{UserRoles.Label(target.Role)}";

        // 目标侧的统一判定：管理员除自己外皆可处置（含审计管理员与其它管理员）。
        // 自己已被上面的约束 3 提前拦下，这里兜住的是"更低身份的操作者"。
        if (!UserRoles.CanBeManagedBy(admin, target))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "FORBIDDEN_TARGET",
                Message = $"当前身份「{UserRoles.Label(admin.Role)}」不能变更"
                    + $"「{UserRoles.Label(target.Role)}」账号的角色"
            };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, statusBefore, requestLog, resp, statusBefore,
                target.Username, AuditResult.Failed, AuditReason.ForbiddenTarget);
            return BadRequest(resp);
        }

        if (target.Role == newRole)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "ROLE_UNCHANGED",
                Message = $"该账号的角色已经是「{UserRoles.Label(newRole)}」"
            };
            // 这里原先误用了 AuditReason.EmptyFields（"字段为空"），与事实不符。
            // 语义上属于"目标状态与请求状态一致，无需变更"，单独给一条码，
            // 免得审计员按 EMPTY_FIELDS 检索时捞出一堆压根没缺字段的记录。
            await WriteAuditLogAsync(admin.Id, admin.Username, action, statusBefore, requestLog, resp, statusBefore,
                target.Username, AuditResult.Failed, AuditReason.RoleUnchanged);
            return BadRequest(resp);
        }

        target.Role = newRole;
        await _db.Users.ReplaceOneAsync(u => u.Id == target.Id, target);

        // 角色变了，旧票据必须作废：让当事人重新登录、以新身份建立会话。
        // 虽然实时查库已让旧票据立刻失去旧权限，但明确吊销能避免
        // "界面还停留在旧身份"带来的困惑。
        await _sessions.RevokeAllForUserAsync(target.Username, "角色已变更，需重新登录");

        var statusAfter = $"{target.Username}·{UserRoles.Label(newRole)}";
        var response = new ApiResponse
        {
            Success = true,
            Code = "OK",
            Message = $"已将「{target.Username}」的角色变更为「{UserRoles.Label(newRole)}」，该账号需重新登录",
            Data = new
            {
                Username = target.Username,
                Role = newRole.ToString(),
                RoleLabel = UserRoles.Label(newRole),
                ReLoginRequired = true
            }
        };
        await WriteAuditLogAsync(admin.Id, admin.Username, action, statusBefore, requestLog, response,
            statusAfter, target.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 修改密码 ==================== */

    /**
     * 修改自己的登录口令。
     *
     * 审计要点（本方法是从"改了没留痕"补回来的重点）：
     *   失败一律走 CHANGE_PASSWORD_FAILED，并带上具体原因码，
     *   使下面三类事件都能被一条查询单独捞出：
     *     · WEAK_PASSWORD      —— 反复提交不合规口令（口令策略被试探 / 有人想设弱口令）
     *     · WRONG_OLD_PASSWORD —— 账号存在但旧口令不符（口令猜测的直接指纹）
     *     · INVALID_CREDENTIALS—— 账号根本不存在（撞库 / 枚举）
     *   成功仍走 CHANGE_PASSWORD，与失败在动作层面就分开，
     *   审计员不需要叠加 result 条件就能把安全事件整类拉出来。
     */
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req)
    {
        const string okAction = AuditAction.ChangePassword;
        const string failAction = AuditAction.ChangePasswordFailed;
        var sanitizedUsername = Norm(req.Username);
        // 新旧口令都不入日志
        var requestLog = new { req.Username };

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(req.OldPassword) || string.IsNullOrWhiteSpace(req.NewPassword))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "字段不能为空" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, failAction, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.NewPassword))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "WEAK_PASSWORD",
                Message = "新密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, failAction, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.WeakPassword);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (user == null)
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "用户名或旧密码错误" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, failAction, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        if (!BCrypt.Net.BCrypt.Verify(req.OldPassword, user.PasswordHash))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "旧密码错误" };
            await WriteAuditLogAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp, statusBefore,
                sanitizedUsername, AuditResult.Failed, AuditReason.WrongOldPassword);
            return Unauthorized(resp);
        }

        // 新旧口令相同：改密等于没改，按策略拒绝。
        // 这条校验必须放在**旧口令验过之后** —— 否则攻击者能拿它当"口令是否正确"的探针。
        if (string.Equals(req.NewPassword, req.OldPassword, StringComparison.Ordinal))
        {
            var resp = new ApiResponse { Success = false, Code = "PASSWORD_REUSED", Message = "新密码不能与当前密码相同" };
            await WriteAuditLogAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp, statusBefore,
                sanitizedUsername, AuditResult.Failed, AuditReason.PasswordReused);
            return BadRequest(resp);
        }

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword);
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        // 口令已换，旧票据不应再能用。
        // 吊销失败不阻断主流程（AuditService 同思路）：口令已经改成功，
        // 吊销只是收紧，退回失败反而让用户以为没改成功、反复重试。
        await _sessions.RevokeAllForUserAsync(user.Username, "口令已变更，需重新登录");

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = "密码修改成功，旧口令立即失效",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync(user.Id, user.Username, okAction, statusBefore, requestLog, response, user.Status.ToString(),
            sanitizedUsername, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 查询 ==================== */

    /**
     * 用户列表。
     *
     * 改造前：靠 `?adminUsername=xxx` 判断身份 —— 客户端在 URL 里声明自己是管理员即可通过。
     * 改造后：必须持有服务端签发的有效票据，且该账号**当前**仍是管理员。
     * 鉴权失败会写入一条 AUDIT_ACCESS_DENIED 事件，使越权尝试可追溯。
     */
    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.AuditAccessDenied, "users");
        if (deny != null) return deny;

        var users = await _db.Users.Find(_ => true).ToListAsync();
        return Ok(new ApiResponse<List<UserResponse>>
        {
            Success = true,
            Code = "OK",
            Data = users.Select(ToUserResponse).ToList()
        });
    }

    /**
     * 审计日志查询（兼容旧路径）。
     *
     * 旧版是 `Limit(200)` 硬编码 —— 写多少都只看得到最近 200 条，"撑得住"无从谈起。
     * 现在改为分页 + 跨分片，完整实现见 AuditController.Query。
     * 此路径保留以兼容既有前端，内部转调同一套分页逻辑。
     *
     * 鉴权失败时写入的是 AUDIT_ACCESS_DENIED 而不是 AUDIT_QUERY：
     * 这里记录的是"有人试图看审计数据但被拒绝"这件事本身。
     * 若沿用 AuditQuery，拒绝事件就会和正常查询混在同一个动作下，
     * 只能靠 result=失败 间接区分，验收时无法一条查询列出全部越权尝试
     * —— 用 curl / PowerShell 直接打这个地址的被拒记录也会因此漏掉。
     */
    [HttpGet("logs")]
    public async Task<IActionResult> GetLogs([FromQuery] string? shard,
        [FromQuery] string? keyword, [FromQuery] string? action, [FromQuery] string? result,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50,
        [FromQuery] bool includeArchived = true)
    {
        var (auditor, deny) = await RequireAuditAsync(AuditAction.AuditAccessDenied, "logs");
        if (deny != null) return deny;

        var (items, total) = await _audit.QueryAsync(shard, keyword, action, result, page, pageSize, includeArchived);

        await WriteAuditLogAsync(auditor!.Id, auditor.Username, AuditAction.AuditQuery, "N/A",
            new { shard, keyword, action, result, page, pageSize },
            new { Returned = items.Count, Total = total },
            "N/A", "logs", AuditResult.Success);

        return Ok(new ApiResponse<object>
        {
            Success = true,
            Code = "OK",
            Data = new { Items = items, Total = total, Page = page, PageSize = pageSize }
        });
    }
}
