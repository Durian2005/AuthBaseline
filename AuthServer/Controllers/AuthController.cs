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
        // 邮箱一律脱敏后返回，管理员能看到"有没有绑、绑没绑好"，但拿不到完整地址
        Email = EmailUtil.Mask(u.Email),
        EmailVerified = u.EmailVerified,
        FailedLoginAttempts = u.FailedLoginAttempts,
        LockoutEnd = u.LockoutEnd,
        CreatedAt = u.CreatedAt,
        IsAdmin = u.IsAdmin
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
     * 管理员接口的统一入口守卫。
     *
     * 与改造前的本质区别：
     *   改造前 = 读请求里的 adminUsername 字符串，客户端说什么就是什么；
     *   改造后 = 校验服务端签发的票据，并**实时查库**确认该账号当前仍是管理员。
     *
     * 鉴权失败时**本身也要留下审计记录** —— 这是实验二「02 看不到」的关键证据：
     * 光有拒绝响应不够，必须证明系统把这次越权尝试也记下来了。
     */
    private async Task<(User? Admin, IActionResult? Deny)> RequireAdminAsync(string action, string target = "")
    {
        var ticket = ReadTicket();
        var auth = await _sessions.ValidateAsync(ticket, requireAdmin: true);

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
                new { AttemptedTarget = target, Reason = auth.ReasonCode },
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
        var auth = await _sessions.ValidateAsync(ticket, requireAdmin: false);

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
                sanitizedUsername, AuditResult.Failed);
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
                sanitizedUsername, AuditResult.Failed);
            return BadRequest(resp);
        }

        if (emailRequired && !EmailUtil.IsValid(email))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_EMAIL", Message = "请输入有效的邮箱地址" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return BadRequest(resp);
        }

        var existing = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (existing != null)
        {
            var resp = new ApiResponse { Success = false, Code = "DUPLICATE_USERNAME", Message = "用户名已存在" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, existing.Status.ToString(),
                sanitizedUsername, AuditResult.Failed);
            return Conflict(resp);
        }

        if (emailRequired)
        {
            var boundUser = await _db.Users.Find(u => u.Email == email).FirstOrDefaultAsync();
            if (boundUser != null)
            {
                var resp = new ApiResponse { Success = false, Code = "EMAIL_ALREADY_BOUND", Message = "该邮箱已被其它账号绑定" };
                await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, boundUser.Status.ToString(),
                    sanitizedUsername, AuditResult.Failed);
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
                    sanitizedUsername, AuditResult.Failed);
                return BadRequest(resp);
            }

            // 建号前再查一次重（发码/校验期间可能已被抢注）
            existing = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
            if (existing != null)
            {
                var resp = new ApiResponse { Success = false, Code = "DUPLICATE_USERNAME", Message = "用户名已存在" };
                await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, existing.Status.ToString(),
                    sanitizedUsername, AuditResult.Failed);
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
        var username = Norm(req.Username);
        var email = EmailUtil.Normalize(req.Email);
        var purpose = (req.Purpose ?? string.Empty).Trim().ToUpperInvariant();
        var requestLog = new { Purpose = purpose, req.Username, Email = EmailUtil.Mask(req.Email) };

        if (!_emailOptions.Enabled)
        {
            var resp = new ApiResponse { Success = false, Code = "EMAIL_DISABLED", Message = "邮件服务当前未启用，请联系管理员" };
            await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed);
            return StatusCode(503, resp);
        }

        if (!EmailCodePurpose.IsValid(purpose))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_PURPOSE", Message = "验证码用途不合法" };
            await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed);
            return BadRequest(resp);
        }

        if (string.IsNullOrWhiteSpace(username) || !EmailUtil.IsValid(email))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_EMAIL", Message = "请填写用户名和有效的邮箱地址" };
            await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed);
            return BadRequest(resp);
        }

        if (purpose == EmailCodePurpose.Register)
        {
            var taken = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
            if (taken != null)
            {
                var resp = new ApiResponse { Success = false, Code = "DUPLICATE_USERNAME", Message = "用户名已存在" };
                await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, resp, taken.Status.ToString(),
                    username, AuditResult.Failed);
                return Conflict(resp);
            }

            var boundUser = await _db.Users.Find(u => u.Email == email).FirstOrDefaultAsync();
            if (boundUser != null)
            {
                var resp = new ApiResponse { Success = false, Code = "EMAIL_ALREADY_BOUND", Message = "该邮箱已被其它账号绑定" };
                await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, resp, boundUser.Status.ToString(),
                    username, AuditResult.Failed);
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
                // 防枚举：与成功响应逐字一致，仅不发信
                var generic = BuildSendCodeSuccess(email);
                await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, generic,
                    user?.Status.ToString() ?? "N/A", username, AuditResult.Failed);
                return Ok(generic);
            }

            var statusBefore = user!.Status.ToString();

            if (user.Status == UserStatus.Pending)
            {
                var resp = new ApiResponse { Success = false, Code = "PENDING_APPROVAL", Message = "账号待审核，暂不能重置密码" };
                await WriteAuditLogAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
                    username, AuditResult.Failed);
                return StatusCode(403, resp);
            }

            if (user.Status == UserStatus.Disabled)
            {
                var resp = new ApiResponse { Success = false, Code = "ACCOUNT_DISABLED", Message = "账号已被禁用，无法重置密码" };
                await WriteAuditLogAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
                    username, AuditResult.Failed);
                return StatusCode(403, resp);
            }

            if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
            {
                var remaining = (int)(user.LockoutEnd.Value - DateTime.UtcNow).TotalSeconds;
                var resp = new ApiResponse
                {
                    Success = false,
                    Code = "ACCOUNT_LOCKED",
                    Message = $"账号处于锁定状态，请 {remaining} 秒后再试",
                    Data = new { LockoutEnd = user.LockoutEnd, RemainingSeconds = remaining }
                };
                await WriteAuditLogAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
                    username, AuditResult.Failed);
                return StatusCode(423, resp);
            }

            // 锁定已到期：顺手恢复启用态，避免"锁定期已过但仍被拒"的错觉
            if (user.Status == UserStatus.Locked)
            {
                user.Status = UserStatus.Enabled;
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;
                await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            }
        }

        var send = await _codes.SendAsync(username, email, purpose);
        if (!send.Success)
        {
            var failure = new ApiResponse { Success = false, Code = send.Code, Message = send.Message };
            var httpCode = send.Code == "RESEND_TOO_SOON" ? 429 : 502;
            await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, failure, "N/A",
                username, AuditResult.Failed);
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
        const string action = AuditAction.ResetPassword;
        var username = Norm(req.Username);
        var email = EmailUtil.Normalize(req.Email);
        // 新旧口令、验证码都不入日志
        var requestLog = new { req.Username, Email = EmailUtil.Mask(req.Email) };

        if (!_emailOptions.Enabled)
        {
            var resp = new ApiResponse { Success = false, Code = "EMAIL_DISABLED", Message = "邮件服务当前未启用，请联系管理员" };
            await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed);
            return StatusCode(503, resp);
        }

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(req.NewPassword))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "用户名与新密码不能为空" };
            await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed);
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
            await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed);
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
            await WriteAuditLogAsync("anonymous", username, action, "N/A", requestLog, resp,
                user?.Status.ToString() ?? "N/A", username, AuditResult.Failed);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        if (user.Status == UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = "PENDING_APPROVAL", Message = "账号待审核，暂不能重置密码" };
            await WriteAuditLogAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
                username, AuditResult.Failed);
            return StatusCode(403, resp);
        }

        if (user.Status == UserStatus.Disabled)
        {
            var resp = new ApiResponse { Success = false, Code = "ACCOUNT_DISABLED", Message = "账号已被禁用，无法重置密码" };
            await WriteAuditLogAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
                username, AuditResult.Failed);
            return StatusCode(403, resp);
        }

        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
        {
            var remaining = (int)(user.LockoutEnd.Value - DateTime.UtcNow).TotalSeconds;
            var resp = new ApiResponse
            {
                Success = false,
                Code = "ACCOUNT_LOCKED",
                Message = $"账号处于锁定状态，请 {remaining} 秒后再试",
                Data = new { LockoutEnd = user.LockoutEnd, RemainingSeconds = remaining }
            };
            await WriteAuditLogAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
                username, AuditResult.Failed);
            return StatusCode(423, resp);
        }

        var verify = await _codes.VerifyAsync(username, EmailCodePurpose.Reset, req.Code, email);
        if (!verify.Success)
        {
            var resp = new ApiResponse { Success = false, Code = verify.Code, Message = verify.Message };
            await WriteAuditLogAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
                username, AuditResult.Failed);
            return BadRequest(resp);
        }

        // 重置成功：换口令，并一并清掉锁定与失败计数（否则改完密码仍被锁在门外）
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword);
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
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
                sanitizedUsername, AuditResult.Failed);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (user == null)
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "用户名或密码错误" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        // 锁定期间，即使正确口令也拒绝登录
        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
        {
            var remaining = (int)(user.LockoutEnd.Value - DateTime.UtcNow).TotalSeconds;
            var resp = new ApiResponse
            {
                Success = false,
                Code = "ACCOUNT_LOCKED",
                Message = $"账号已锁定，请 {remaining} 秒后再试",
                Data = new { LockoutEnd = user.LockoutEnd, RemainingSeconds = remaining }
            };
            await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, statusBefore,
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        // 如果锁定时间已过，自动恢复为启用状态
        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue && user.LockoutEnd.Value <= DateTime.UtcNow)
        {
            user.Status = UserStatus.Enabled;
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            statusBefore = UserStatus.Enabled.ToString();
        }

        if (user.Status == UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = "PENDING_APPROVAL", Message = "账号待审核，请联系管理员" };
            await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, user.Status.ToString(),
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        var passwordValid = BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash);
        if (!passwordValid)
        {
            user.FailedLoginAttempts++;
            string? message;
            string code;
            UserStatus newStatus = user.Status;
            DateTime? lockoutEnd = user.LockoutEnd;

            if (user.FailedLoginAttempts >= MaxFailedAttempts)
            {
                newStatus = UserStatus.Locked;
                lockoutEnd = DateTime.UtcNow.Add(LockoutDuration);
                user.Status = newStatus;
                user.LockoutEnd = lockoutEnd;
                message = $"连续输错 {MaxFailedAttempts} 次密码，账号已锁定 {LockoutDuration.TotalMinutes} 分钟";
                code = "ACCOUNT_LOCKED";
            }
            else
            {
                message = $"密码错误，还剩 {MaxFailedAttempts - user.FailedLoginAttempts} 次机会";
                code = "INVALID_CREDENTIALS";
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
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        // 登录成功，重置失败计数
        if (user.FailedLoginAttempts > 0)
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
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
                IsAdmin = user.IsAdmin,
                Ticket = session.Ticket,
                ExpiresAt = session.ExpiresAt
            }
        };
        // 审计里绝不记录票据本体，只记"已签发"这一事实
        await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginSuccess, statusBefore, requestLog,
            new { user.Username, user.Status, user.IsAdmin, TicketIssued = true },
            user.Status.ToString(), sanitizedUsername, AuditResult.Success);
        return Ok(successResp);
    }

    /* ==================== 管理员：审核 ==================== */

    [HttpPost("approve")]
    public async Task<IActionResult> Approve([FromBody] ApproveRequest req)
    {
        var (admin, deny) = await RequireAdminAsync(AuditAction.Approve, Norm(req.Username));
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
        var (admin, deny) = await RequireAdminAsync(AuditAction.Unlock, Norm(req.Username));
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
        var (admin, deny) = await RequireAdminAsync(AuditAction.DeleteUser, Norm(req.Username));
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

        // 禁止注销管理员账号（含注销自己），避免系统失去管理员导致无法恢复
        if (user.IsAdmin)
        {
            var denied = new ApiResponse { Success = false, Code = "CANNOT_DELETE_ADMIN", Message = "不能注销管理员账号" };
            await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.DeleteUser, statusBefore, requestLog, denied, statusBefore,
                user.Username, AuditResult.Failed, AuditReason.NotAdmin);
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

    /* ==================== 管理员：权限转让 ==================== */

    /**
     * 将管理员权限转让给另一位合法用户。
     *
     * 安全约束：
     *   1. 操作者必须是现任管理员，且需二次校验其登录口令（防止会话被冒用后直接夺权）。
     *   2. 受让方必须是"合法用户"：账号已启用（非待审核 / 锁定 / 禁用），且当前不是管理员。
     *   3. 先提升受让方、再降级自己 —— 任何一步中断都不会让系统陷入无管理员状态。
     *   4. 全过程（含每次失败）写入审计日志；请求日志中绝不记录口令。
     */
    [HttpPost("transfer-admin")]
    public async Task<IActionResult> TransferAdmin([FromBody] TransferAdminRequest req)
    {
        const string action = AuditAction.TransferAdmin;
        var targetName = Norm(req.TargetUsername);
        // 口令不入日志
        var requestLog = new { req.TargetUsername };

        if (string.IsNullOrWhiteSpace(targetName) || string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "目标用户名与管理员口令不能为空" };
            await WriteAuditLogAsync("anonymous", "anonymous", action, "N/A", requestLog, resp, "N/A",
                targetName, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        var (admin, deny) = await RequireAdminAsync(action, targetName);
        if (deny != null) return deny;

        // 二次口令校验：转让属于特权变更，仅凭会话不足以证明是本人操作
        if (!BCrypt.Net.BCrypt.Verify(req.Password, admin!.PasswordHash))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "管理员口令校验失败，已拒绝转让" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, $"{admin.Username}·管理员", requestLog, resp, $"{admin.Username}·管理员",
                targetName, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        if (targetName == admin.Username)
        {
            var resp = new ApiResponse { Success = false, Code = "CANNOT_TRANSFER_SELF", Message = "不能把权限转让给自己" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, $"{admin.Username}·管理员", requestLog, resp, $"{admin.Username}·管理员",
                targetName, AuditResult.Failed, AuditReason.NotAdmin);
            return BadRequest(resp);
        }

        var target = await _db.Users.Find(u => u.Username == targetName).FirstOrDefaultAsync();
        if (target == null)
        {
            var resp = new ApiResponse { Success = false, Code = "NOT_FOUND", Message = "目标用户不存在" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, $"{admin.Username}·管理员", requestLog, resp, $"{admin.Username}·管理员",
                targetName, AuditResult.Failed, AuditReason.NotFound);
            return NotFound(resp);
        }

        var statusBefore = target.IsAdmin ? $"{target.Username}·管理员" : target.Status.ToString();

        // 合法用户判定：只有处于启用状态的账号才具备接管管理员权限的资格
        if (target.Status != UserStatus.Enabled)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "TARGET_NOT_ELIGIBLE",
                Message = $"目标账号当前状态为「{target.Status}」，只有已启用的账号才能接管管理员权限"
            };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, statusBefore, requestLog, resp, statusBefore,
                target.Username, AuditResult.Failed, AuditReason.AccountNotEnabled);
            return BadRequest(resp);
        }

        if (target.IsAdmin)
        {
            var resp = new ApiResponse { Success = false, Code = "TARGET_ALREADY_ADMIN", Message = "该用户已经是管理员" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, statusBefore, requestLog, resp, statusBefore,
                target.Username, AuditResult.Failed, AuditReason.NotAdmin);
            return BadRequest(resp);
        }

        // 先提升受让方，再撤销自己的管理员身份：任何时刻都保证系统内至少有一名管理员
        target.IsAdmin = true;
        await _db.Users.ReplaceOneAsync(u => u.Id == target.Id, target);

        admin.IsAdmin = false;
        await _db.Users.ReplaceOneAsync(u => u.Id == admin.Id, admin);

        // 权限变更后立刻吊销双方既有票据：
        // 原管理员的票据可能仍带着管理员快照，受让方也需要用新身份重新登录，
        // 否则会出现"权限已转出但旧会话还能操作"的授权残留。
        await _sessions.RevokeAllForUserAsync(admin.Username, "管理员权限已转出，需重新登录");
        await _sessions.RevokeAllForUserAsync(target.Username, "已获得管理员权限，需重新登录以生效");

        var response = new ApiResponse
        {
            Success = true,
            Code = "OK",
            Message = $"已将管理员权限转让给「{target.Username}」，您已变为普通用户，请重新登录",
            Data = new { Username = target.Username, PreviousAdmin = admin.Username, ReLoginRequired = true }
        };
        await WriteAuditLogAsync(admin.Id, admin.Username, action, $"{admin.Username}·管理员", requestLog, response, $"{target.Username}·管理员",
            target.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 修改密码 ==================== */

    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req)
    {
        var sanitizedUsername = Norm(req.Username);
        // 新旧口令都不入日志
        var requestLog = new { req.Username };

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(req.OldPassword) || string.IsNullOrWhiteSpace(req.NewPassword))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "字段不能为空" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.ChangePassword, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
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
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.ChangePassword, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (user == null)
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "用户名或旧密码错误" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.ChangePassword, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        if (!BCrypt.Net.BCrypt.Verify(req.OldPassword, user.PasswordHash))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "旧密码错误" };
            await WriteAuditLogAsync(user.Id, user.Username, AuditAction.ChangePassword, statusBefore, requestLog, resp, statusBefore,
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword);
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = "密码修改成功，旧口令立即失效",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync(user.Id, user.Username, AuditAction.ChangePassword, statusBefore, requestLog, response, user.Status.ToString(),
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
        var (admin, deny) = await RequireAdminAsync(AuditAction.AuditAccessDenied, "users");
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
     */
    [HttpGet("logs")]
    public async Task<IActionResult> GetLogs([FromQuery] string? shard,
        [FromQuery] string? keyword, [FromQuery] string? action, [FromQuery] string? result,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50,
        [FromQuery] bool includeArchived = true)
    {
        var (admin, deny) = await RequireAdminAsync(AuditAction.AuditQuery, "logs");
        if (deny != null) return deny;

        var (items, total) = await _audit.QueryAsync(shard, keyword, action, result, page, pageSize, includeArchived);

        await WriteAuditLogAsync(admin!.Id, admin.Username, AuditAction.AuditQuery, "N/A",
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
