using AuthServer.Models;
using AuthServer.Services;
using AuthServer.Services.Face;
using AuthServer.Services.Otp;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthServer.Controllers;

/**
 * 账号自助接口：注册、邮箱验证码、忘记口令（重置）、修改口令、人脸模板自助。
 *
 * 共同点：操作者**处理的是自己的账号**，或尚未成为账号的注册申请。
 * 因此这里没有"角色"守卫 —— 身份由"知道旧口令 / 收到邮箱验证码"证明，
 * 或由票据代表的"本人"确定。角色相关的操作全在 UserAdminController。
 * 路由前缀仍是 api/auth，与拆分前逐一对应。
 */
[ApiController]
[Route("api/auth")]
public class AccountController : AuthControllerBase
{
    private readonly VerificationService _codes;

    /// <summary>哈希链存储。本控制器只在两处用到它：改密/重置后重建链。</summary>
    private readonly OtpChainStore _chains;

    /// <summary>一次性挑战。改密走链值分支时要校验它（与登录同一套顺序）。</summary>
    private readonly OtpChallengeStore _challenges;

    private readonly EmailOptions _emailOptions;
    private readonly FaceLoginService _face;
    private readonly FaceTemplateStore _faceTemplates;
    private readonly FacePreviewService _preview;

    public AccountController(MongoDbService db, AuditWriter auditWriter, SessionService sessions,
        VerificationService codes, EmailOptions emailOptions,
        FaceLoginService face, FaceTemplateStore faceTemplates, FacePreviewService preview,
        IConfiguration configuration, OtpConfirmStore confirms,
        OtpChainStore chains, OtpChallengeStore challenges)
        : base(db, auditWriter, sessions, configuration, confirms)
    {
        _codes = codes;
        _emailOptions = emailOptions;
        _face = face;
        _chains = chains;
        _challenges = challenges;
        _faceTemplates = faceTemplates;
        _preview = preview;
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
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "用户名或密码不能为空" };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.Password))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.WeakPassword,
                Message = "密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.WeakPassword);
            return BadRequest(resp);
        }

        if (emailRequired && !EmailUtil.IsValid(email))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidEmail, Message = "请输入有效的邮箱地址" };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.InvalidEmail);
            return BadRequest(resp);
        }

        var existing = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (existing != null)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.DuplicateUsername, Message = "用户名已存在" };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, existing.Status.ToString(),
                sanitizedUsername, AuditResult.Failed, AuditReason.DuplicateUsername);
            return Conflict(resp);
        }

        if (emailRequired)
        {
            var boundUser = await _db.Users.Find(u => u.Email == email).FirstOrDefaultAsync();
            if (boundUser != null)
            {
                var resp = new ApiResponse { Success = false, Code = BusinessCode.EmailAlreadyBound, Message = "该邮箱已被其它账号绑定" };
                await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, boundUser.Status.ToString(),
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
                await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                    sanitizedUsername, AuditResult.Failed, VerifyCodeReason.From(verify.Code));
                return BadRequest(resp);
            }

            // 建号前再查一次重（发码/校验期间可能已被抢注）
            existing = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
            if (existing != null)
            {
                var resp = new ApiResponse { Success = false, Code = BusinessCode.DuplicateUsername, Message = "用户名已存在" };
                await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, existing.Status.ToString(),
                    sanitizedUsername, AuditResult.Failed, AuditReason.DuplicateUsername);
                return Conflict(resp);
            }
        }

        // Id 由**客户端生成**：账号与它的链必须一起成立，而链需要 userId。
        // 先插账号再建链的话，中间失败就会留下一个「看起来正常、其实永远登不进去」的账号 ——
        // 它还会照常出现在管理员的待审核列表里，谁都不知道它坏了。
        // Mongo 允许客户端提供 ObjectId，于是这条顺序可以反过来：先定 Id、插账号、再建链，
        // 建链失败就把账号删掉（此时它还没有任何关联数据）。
        var user = new User
        {
            Id = ObjectId.GenerateNewId().ToString(),
            Username = sanitizedUsername,
            // 口令不落库：注册这一刻拿到的是**明文**，正好用它把链建出来（见下）。
            Status = UserStatus.Pending,
            // 邮件功能关闭时回退为"无邮箱的老流程"，避免外部依赖不可用就完全无法注册
            Email = emailRequired ? email : null,
            EmailVerified = emailRequired,
            FailedLoginAttempts = 0,
            CreatedAt = DateTime.UtcNow
        };

        await _db.Users.InsertOneAsync(user);

        try
        {
            // 建链 = 把明文口令折叠成 x_N。明文只在本次调用内存在，用完即弃。
            await _chains.CreateAsync(user.Id, user.Username, req.Password);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Otp] 账号「{user.Username}」建链失败，回滚注册: {ex.Message}");

            // 回滚：删掉刚插的账号，让这次注册"什么都没发生"。
            // 反过来（留着账号、只报错）会造出一个永远登不进去的账号，
            // 而用户重试注册只会撞上"用户名已存在"。
            try
            {
                await _db.Users.DeleteOneAsync(u => u.Id == user.Id);
            }
            catch (Exception rollbackEx)
            {
                Console.WriteLine($"[Otp] ⚠️ 注册回滚失败，账号「{user.Username}」已成为无链账号: {rollbackEx.Message}");
            }

            var failed = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.OtpRebuildFailed,
                Message = "注册失败：认证链未能建立，请稍后重试"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.Register, "N/A", requestLog, failed,
                user.Status.ToString(), sanitizedUsername, AuditResult.Failed, AuditReason.OtpRebuildFailed);
            return StatusCode(500, failed);
        }

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = emailRequired
                ? "注册成功，邮箱已验证，等待管理员审核"
                : "注册成功，等待管理员审核",
            Data = ToUserResponse(user)
        };
        await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, response, user.Status.ToString(),
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
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmailDisabled, Message = "邮件服务当前未启用，请联系管理员" };
            await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.EmailDisabled);
            return StatusCode(503, resp);
        }

        if (!EmailCodePurpose.IsValid(purpose))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidPurpose, Message = "验证码用途不合法" };
            await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.InvalidPurpose);
            return BadRequest(resp);
        }

        if (string.IsNullOrWhiteSpace(username) || !EmailUtil.IsValid(email))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidEmail, Message = "请填写用户名和有效的邮箱地址" };
            await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.InvalidEmail);
            return BadRequest(resp);
        }

        if (purpose == EmailCodePurpose.Register)
        {
            var taken = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
            if (taken != null)
            {
                var resp = new ApiResponse { Success = false, Code = BusinessCode.DuplicateUsername, Message = "用户名已存在" };
                await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, resp, taken.Status.ToString(),
                    username, AuditResult.Failed, AuditReason.DuplicateUsername);
                return Conflict(resp);
            }

            var boundUser = await _db.Users.Find(u => u.Email == email).FirstOrDefaultAsync();
            if (boundUser != null)
            {
                var resp = new ApiResponse { Success = false, Code = BusinessCode.EmailAlreadyBound, Message = "该邮箱已被其它账号绑定" };
                await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, resp, boundUser.Status.ToString(),
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
                await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, generic,
                    user?.Status.ToString() ?? "N/A", username, AuditResult.Failed, AuditReason.InvalidCredentials);
                return Ok(generic);
            }

            var statusBefore = user!.Status.ToString();

            if (user.Status == UserStatus.Pending)
            {
                var resp = new ApiResponse { Success = false, Code = BusinessCode.PendingApproval, Message = "账号待审核，暂不能重置密码" };
                await _auditWriter.WriteAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
                    username, AuditResult.Failed, AuditReason.PendingApproval);
                return StatusCode(403, resp);
            }

            if (user.Status == UserStatus.Disabled)
            {
                var resp = new ApiResponse { Success = false, Code = BusinessCode.AccountDisabled, Message = "账号已被禁用，无法重置密码" };
                await _auditWriter.WriteAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
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
                ResetFailedAttempts(user);
                await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            }
        }

        var send = await _codes.SendAsync(username, email, purpose);
        if (!send.Success)
        {
            var failure = new ApiResponse { Success = false, Code = send.Code, Message = send.Message };
            var httpCode = send.Code == "RESEND_TOO_SOON" ? 429 : 502;
            await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, failure, "N/A",
                username, AuditResult.Failed, SendCodeReason.From(send.Code));
            return StatusCode(httpCode, failure);
        }

        var success = BuildSendCodeSuccess(email);
        await _auditWriter.WriteAsync("anonymous", username, action, "N/A", requestLog, success, "N/A",
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
        Code = BusinessCode.Ok,
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
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmailDisabled, Message = "邮件服务当前未启用，请联系管理员" };
            await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.EmailDisabled);
            return StatusCode(503, resp);
        }

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(req.NewPassword))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "用户名与新密码不能为空" };
            await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.NewPassword))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.WeakPassword,
                Message = "新密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, resp, "N/A",
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
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidCredentials, Message = "用户名与邮箱不匹配" };
            await _auditWriter.WriteAsync("anonymous", username, failedAction, "N/A", requestLog, resp,
                user?.Status.ToString() ?? "N/A", username, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        if (user.Status == UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.PendingApproval, Message = "账号待审核，暂不能重置密码" };
            await _auditWriter.WriteAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
                username, AuditResult.Failed, AuditReason.PendingApproval);
            return StatusCode(403, resp);
        }

        if (user.Status == UserStatus.Disabled)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.AccountDisabled, Message = "账号已被禁用，无法重置密码" };
            await _auditWriter.WriteAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
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
            await _auditWriter.WriteAsync(user.Id, user.Username, failedAction, statusBefore, requestLog, resp, statusBefore,
                username, AuditResult.Failed, VerifyCodeReason.From(verify.Code));
            return BadRequest(resp);
        }

        // ── 重置口令 = 重建链（P6/P8）──
        // 口令不再单独存一份，它**只存在于链里**（链根由它派生）。
        // 于是"改口令"这个动作的全部内容就是"用新明文重算一条链、换掉旧的"，
        // 没有第二个记录需要同步，也就不存在"改了一半"的中间态 ——
        // 重建失败 = 什么都没变，用户拿旧口令照样能登进来说明这次重置没生效。
        if (!await TryRebuildChainAsync(user, req.NewPassword, "RESET_PASSWORD", requestLog, username))
        {
            var rebuildFailed = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.OtpRebuildFailed,
                Message = "重置失败：认证链未能重建，口令未变更，请稍后重试"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failedAction, statusBefore, requestLog,
                rebuildFailed, user.Status.ToString(), username, AuditResult.Failed, AuditReason.OtpRebuildFailed);
            return StatusCode(500, rebuildFailed);
        }

        // 链已换新 ⇒ 顺带清掉锁定与失败计数（否则改完口令仍被锁在门外）。
        // 放在重建**之后**：重建失败时"什么都没改"是最容易解释的失败形态。
        ResetFailedAttempts(user);
        if (user.Status == UserStatus.Locked) user.Status = UserStatus.Enabled;
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = "密码已重置，请使用新密码登录",
            Data = ToUserResponse(user)
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog, response, user.Status.ToString(),
            username, AuditResult.Success);
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

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(req.NewPassword)
            || string.IsNullOrWhiteSpace(req.OldOtpCode) || string.IsNullOrWhiteSpace(req.OldChallengeToken))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "字段不能为空" };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, failAction, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.NewPassword))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.WeakPassword,
                Message = "新密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, failAction, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.WeakPassword);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (user == null)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidCredentials, Message = "用户名或旧密码错误" };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, failAction, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        // 本端点**匿名**（没有票据可依）：唯一的身份证明就是"能算出一格仍然有效的链值"。
        // 旧口令明文早已不上网 —— 客户端在本机把它折叠成 x_k 再提交。

        // ① 先消费挑战：一次性、绑用户名、有 TTL。顺序与登录一致 ——
        //    放在最前面是为了"无论后面成败，这张票都不能再用"。
        var (challengeUsername, challengeError) = _challenges.Consume(req.OldChallengeToken);
        if (challengeError is not null
            || !string.Equals(challengeUsername, user.Username, StringComparison.Ordinal))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.OtpChallengeInvalid,
                Message = "改密请求已失效，请重新发起"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                statusBefore, sanitizedUsername, AuditResult.Failed, AuditReason.OtpChallengeInvalid);
            return Unauthorized(resp);
        }

        // ② 核销一格
        var consumed = await _chains.ConsumeAsync(user.Id, req.OldOtpCode);

        // 未建链 / 链畸形：对外与"旧密码错误"**逐字一致**。
        // 这个端点是匿名的，承认"这个账号有链 / 链坏了"就是一条比"账号存在"更细的枚举信息。
        if (consumed.Outcome is OtpConsumeOutcome.NotEnrolled or OtpConsumeOutcome.Malformed)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidCredentials, Message = "旧密码错误" };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                statusBefore, sanitizedUsername, AuditResult.Failed,
                consumed.Outcome == OtpConsumeOutcome.Malformed
                    ? AuditReason.OtpChainMalformed
                    : AuditReason.OtpNotEnrolled);
            return Unauthorized(resp);
        }

        if (consumed.Outcome == OtpConsumeOutcome.Exhausted)
        {
            // 凭据是真的、链没了。必须回"需重建"，否则用户会反复重输旧口令。
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.OtpChainExhausted,
                Message = "本账号的一次性口令已用尽，请用邮箱验证码重置口令"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                statusBefore, sanitizedUsername, AuditResult.Failed, AuditReason.OtpChainExhausted);
            return Unauthorized(resp);
        }

        if (consumed.Outcome == OtpConsumeOutcome.Conflict)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.OtpChainConflict,
                Message = "改密请求发生并发冲突，请重试"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                statusBefore, sanitizedUsername, AuditResult.Failed, AuditReason.OtpChainConflict);
            return Conflict(resp);
        }

        if (consumed.Outcome == OtpConsumeOutcome.Mismatch)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidCredentials, Message = "旧密码错误" };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                statusBefore, sanitizedUsername, AuditResult.Failed, AuditReason.WrongOldPassword);
            return Unauthorized(resp);
        }

        // ── ③「新旧口令相同」这一条 P8 起由**客户端**判定 ──
        // 服务端已经没有"当前口令"可比：库里的链是一串哈希迭代的结果，
        // 拿新明文去比它需要先知道 k 与盐，而那正是登录/改密刚刚消耗掉的东西。
        // 这不是"放弃校验"而是"校验挪位"：客户端同时持有新旧两个明文，比较是一行的事；
        // 服务端要做同样的判定，就必须为每个账号留一份可离线比对的口令派生物 ——
        // 那正是这个项目从 P0 起就在拆掉的东西。
        // 代价是绕过客户端（直接打接口）可以把口令改成同一个值：**改密等于没改**，
        // 不产生任何权限变化，因此不构成安全边界（见设计稿 §7.6 边界）。

        // ── ④ 重建链 = 换口令 ──
        // 口令只存在于链里，所以改密的全部内容就是"用新明文重算一条链"。
        // 这一步失败 = 什么都没变，旧口令照样能登进来。
        if (!await TryRebuildChainAsync(user, req.NewPassword, "CHANGE_PASSWORD", requestLog, sanitizedUsername))
        {
            var rebuildFailed = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.OtpRebuildFailed,
                Message = "改密失败：认证链未能重建，口令未变更，请稍后重试"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog,
                rebuildFailed, user.Status.ToString(), sanitizedUsername, AuditResult.Failed, AuditReason.OtpRebuildFailed);
            return StatusCode(500, rebuildFailed);
        }

        // 口令已换，旧票据不应再能用。
        // 吊销失败不阻断主流程（AuditService 同思路）：口令已经改成功，
        // 吊销只是收紧，退回失败反而让用户以为没改成功、反复重试。
        await _sessions.RevokeAllForUserAsync(user.Username, "口令已变更，需重新登录");

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = "密码修改成功，旧口令立即失效",
            Data = ToUserResponse(user)
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, okAction, statusBefore, requestLog, response, user.Status.ToString(),
            sanitizedUsername, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 口令变更后的链重建（P6） ==================== */

    /**
     * 用新口令整条重建链。返回 false ⇒ 调用方**必须整体失败**（口令未变）。
     *
     * ── 为什么不走"下次登录再补"的懒路径 ────────────────────────
     * 那条路看起来更温和（改密永不会失败），但它把问题推到了下一次登录：
     * 那时客户端手里已经是新口令、链却绑着旧口令，得到的是"口令明明对却登不上"。
     * 这类故障的归因成本极高 —— 而在 P8 之前它一直是**隐形的**：`passwordHash` 还在，
     * 口令登录是通的，用户不会意识到 OTP 那条路已经死了。P8 删掉口令路径之后，
     * 半截状态就是"谁都进不来"，所以这条约束反而更硬：
     * 宁可让改密这一次显式失败，也不要留下半个口令。
     *
     * ── 为什么失败也不抛 ────────────────────────────────────────
     * 返回值而不是异常：调用方还要写自己的失败审计、决定状态码，并保证
     * "失败 ⇒ 什么都没改"（P8 之后重建链就是换口令本身，没有第二个记录要回滚）。
     * 这里只负责"把 OTP 域的事实记清楚"。
     */
    private async Task<bool> TryRebuildChainAsync(User user, string newPassword, string trigger,
        object requestLog, string target)
    {
        var statusBefore = user.Status.ToString();

        try
        {
            var chain = await _chains.RebuildAsync(user.Id, user.Username, newPassword);

            // 审计里**绝不含口令、绝不含链值**：只记这条新链的公开参数与"由谁触发"。
            // Trigger 必须记 —— 同一个动作码要能回答"这次换链是改密、是重置、还是人工恢复"。
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.OtpRebuilt, statusBefore,
                requestLog,
                new
                {
                    Trigger = trigger,
                    user.Username,
                    ChainLength = chain.Length,
                    KdfIterations = chain.KdfIterations,
                    Generation = chain.Generation
                },
                statusBefore, target, AuditResult.Success, AuditReason.OtpRebuilt);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Otp] 账号「{user.Username}」重建链失败（{trigger} 将整体失败并回滚口令）: {ex.Message}");

            try
            {
                await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.OtpRebuildFailed, statusBefore,
                    requestLog,
                    new { Trigger = trigger, user.Username, ErrorType = ex.GetType().Name },
                    statusBefore, target, AuditResult.Failed, AuditReason.OtpRebuildFailed);
            }
            catch (Exception auditEx)
            {
                // 审计是旁路，任何情况下都不该把"重建失败"升级成"连响应都发不出去"。
                Console.WriteLine($"[Otp] 重建失败的审计也未能写入: {auditEx.Message}");
            }

            return false;
        }
    }

    /* ==================== 人脸模板自助（可选第二因子） ==================== */

    /**
     * 本人的人脸状态：有没有录、录了几张、什么时候录的、本机引擎是否可用。
     *
     * 为什么走票据而不是"报用户名"：人头上的模板属于**本人**，
     * 而"我是谁"只能由票据回答（见 AuthControllerBase.RequireAuthenticatedAsync）。
     *
     * 为什么**不写审计**：账号页每次打开都会拉一次，逐次留痕只会把审计链刷成噪声
     * —— 与 /dormant-users 同一条理由。需要留痕的是"录入 / 删除"这类**改变状态**的动作。
     */
    [HttpGet("face")]
    public async Task<IActionResult> FaceStatus()
    {
        var (user, deny) = await RequireAuthenticatedAsync(AuditAction.AuditAccessDenied, "self-face");
        if (deny != null) return deny;

        return Ok(new ApiResponse<FaceStatusResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = "查询成功",
            Data = await BuildFaceStatusAsync(user!)
        });
    }

    private async Task<FaceStatusResponse> BuildFaceStatusAsync(User user)
    {
        var engine = _face.EngineStatus;
        return new FaceStatusResponse
        {
            Enrolled = await _faceTemplates.HasAnyAsync(user.Id),
            TemplateCount = (int)await _faceTemplates.CountAsync(user.Id),
            EnrolledAt = await _faceTemplates.LastEnrolledAtAsync(user.Id),
            // 阈值与引擎状态一并下发：界面上要能显示"本机当前按 0.50 判定"、
            // "本机检测不到摄像头"，而不是让用户对着一个沉默的按钮猜。
            Threshold = _face.Threshold,
            EngineReady = engine.Ready,
            EngineMessage = engine.Ready ? string.Empty : engine.Message
        };
    }

    /**
     * 录入 / 更换人脸 · 第一步：验口令、下发动作挑战。
     *
     * 为什么必须拆成两步：动作由**服务端随机决定**（让客户端指定等于把活体挑战作废），
     * 而用户必须知道要做什么才能做 —— 所以动作必须先送到客户端，
     * 客户端准备好后再回来采一帧。两步之间靠一张一次性 token 连接，并绑定用途（enroll）。
     *
     * 口令校验放在这一步、而不是采集之后：免得用户对着镜头把动作做完，
     * 才被告知"口令不对"——那既浪费一次采集，也让失败原因变得含糊。
     */
    [HttpPost("face/enroll")]
    public async Task<IActionResult> FaceEnrollStart([FromBody] FaceEnrollRequest req)
    {
        const string action = AuditAction.FaceEnroll;
        var (user, deny) = await RequireAuthenticatedAsync(action, "self-face");
        if (deny != null) return deny;
        var requestLog = new { user = user!.Username };
        var statusBefore = user.Status.ToString();

        // 模块关闭 / 引擎不可用 ⇒ 明确拒绝并留痕，而不是给一个"看起来能用"的按钮
        if (!_face.Enabled || !_face.EngineStatus.Ready)
        {
            var message = !_face.Enabled ? "本系统的人脸模块当前未启用" : $"本机人脸引擎不可用：{_face.EngineStatus.Message}";
            var resp = new ApiResponse { Success = false, Code = BusinessCode.FaceEngineUnavailable, Message = message };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceEnrollFailed, statusBefore,
                requestLog, resp, statusBefore, user.Username, AuditResult.Failed, AuditReason.FaceEngineUnavailable);
            return StatusCode(503, resp);
        }

        // 二次确认（P8）：只认一次性确认凭据，没有"再输一次口令"这条路了。
        // 缺凭据时 <see cref="DenyUnlessConfirmedAsync"/> 一律回 401 OTP_CONFIRM_REQUIRED，
        // 客户端据此去 <c>POST /api/auth/reconfirm</c> 换一张 —— 与旧路径"口令不对"同一个状态码，
        // 于是界面上的错误处理不必按新旧分叉（那段分叉正是回滚期最容易错位的地方）。
        var confirmDeny = await DenyUnlessConfirmedAsync(req.ConfirmToken, user, OtpConfirmPurpose.FaceEnroll,
            user.Username, AuditAction.FaceEnrollFailed, requestLog);
        if (confirmDeny != null) return confirmDeny;

        var (token, pose) = _face.IssueForEnroll(user.Username);

        // 与登录那条路径同源：录入挑战同样是一张"能换到识别画面"的凭据，
        // 而它成立的前提是——本人刚刚重新输过当前口令。
        _preview.Open(token, _face.ChallengeTtlSeconds);

        var challenge = new ApiResponse<FaceChallengeResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = "口令已验证，请按提示完成动作",
            Data = new FaceChallengeResponse
            {
                ChallengeToken = token,
                Action = pose,
                ActionText = FacePose.ActionText(pose),
                ActionHint = FacePose.ActionHint,
                ExpiresInSeconds = _face.ChallengeTtlSeconds,
                Threshold = _face.Threshold
            }
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog,
            new { user.Username, Step = "ENROLL_CHALLENGE", Action = pose }, statusBefore, user.Username,
            AuditResult.Success);
        return Ok(challenge);
    }

    /**
     * 录入 / 更换人脸 · 第二步：提交挑战，由服务端采集一帧并写入模板。
     *
     * 采集、检测、特征提取全部在服务端进程内完成 —— 请求体里只有 token，
     * 没有任何画面或特征（理由同登录第二因子）。
     *
     * 录入失败**不计次**：用户已经登录，一次录不上人脸没有任何安全含义，
     * 不该混进"本账号被连续判失败"的统计（见 AuditReason.FaceEnrollRejected）。
     */
    [HttpPost("face/enroll/complete")]
    public async Task<IActionResult> FaceEnrollComplete([FromBody] FaceEnrollCompleteRequest req)
    {
        const string action = AuditAction.FaceEnroll;
        const string failAction = AuditAction.FaceEnrollFailed;
        var (user, deny) = await RequireAuthenticatedAsync(action, "self-face");
        if (deny != null) return deny;
        var requestLog = new { user = user!.Username };
        var statusBefore = user.Status.ToString();

        // 采集期间画面改由采集循环推，并在这之后收回预览权（见 FacePreviewService.BeginCapture）。
        (string? challengeUser, ChallengeOutcome? outcome, string? error) captured;
        using (var _ = _preview.BeginCapture())
        {
            try
            {
                captured = _face.CaptureForEnroll(req.ChallengeToken);
            }
            finally
            {
                _preview.Close(req.ChallengeToken);
            }
        }
        var (challengeUser, outcome, error) = captured;

        // 挑战无效 / 用途不是 enroll / 属于别人 ⇒ 一律按无主处理，不归属、不计次。
        // "属于别人"这一条虽然靠 token 不可猜已经兜住，但仍显式比一次 ——
        // 让"随机不可猜"成为纵深手段而不是唯一防线。
        if (error is not null || outcome is null || challengeUser is null
            || !string.Equals(challengeUser, user.Username, StringComparison.Ordinal))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.FaceChallengeInvalid,
                Message = FaceCodes.MessageFor("FACE_CHALLENGE_INVALID")
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore,
                new { user.Username, ChallengePresent = !string.IsNullOrWhiteSpace(req.ChallengeToken) },
                resp, statusBefore, user.Username, AuditResult.Failed, AuditReason.FaceChallengeInvalid);
            return BadRequest(resp);
        }

        if (!outcome.Passed || outcome.Feature is null)
        {
            // 引擎问题（环境）与"没通过"（配合/质量）在审计里分开：
            // 前者不是用户的问题，后者才是。
            var reason = string.Equals(outcome.BusinessCode, "FACE_ENGINE_UNAVAILABLE", StringComparison.Ordinal)
                ? AuditReason.FaceEngineUnavailable
                : AuditReason.FaceEnrollRejected;
            var resp = new ApiResponse
            {
                Success = false,
                Code = outcome.BusinessCode,
                Message = FaceCodes.MessageFor(outcome.BusinessCode),
                // 诊断量只入审计（下面），不进响应体：它是排障用的，对用户没有意义
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog,
                new { user.Username, BusinessCode = outcome.BusinessCode, Diagnostic = outcome.Diagnostic },
                statusBefore, user.Username, AuditResult.Failed, reason);
            return BadRequest(resp);
        }

        var count = await _faceTemplates.AddAsync(user.Id, user.Username, outcome.Feature);
        var response = new ApiResponse
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = count > 1
                ? $"已录入第 {count} 张人脸模板（上限 {_face.MaxTemplates} 张，超出后自动淘汰最早的）"
                : "已录入人脸模板，该账号登录时需要刷脸",
            Data = new { TemplateCount = count, EnrolledAt = DateTime.UtcNow, Threshold = _face.Threshold }
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog,
            new { user.Username, TemplateCount = count, Diagnostic = outcome.Diagnostic },
            statusBefore, user.Username, AuditResult.Success);
        return Ok(response);
    }

    /**
     * 删除本人的全部人脸模板。**必须重新输入口令**。
     *
     * 这是"可选启用"这条设计自带的**降级通道**上唯一的闸门：
     * 拿到一个有效会话的人，若能顺手把模板删掉，该账号就永久退回单因子 ——
     * 而脸不像口令那样"改了就能撤销"，删掉之后攻击者留下的唯一凭据就是口令。
     * 所以这一步的门槛刻意与"修改口令"同级（都要当前口令）。
     *
     * 口令错误按 A 组计次（同 face/enroll）。
     */
    [HttpPost("face/delete")]
    public async Task<IActionResult> FaceDelete([FromBody] FaceDeleteRequest req)
    {
        const string action = AuditAction.FaceTemplateDeleted;
        var (user, deny) = await RequireAuthenticatedAsync(action, "self-face");
        if (deny != null) return deny;
        var requestLog = new { user = user!.Username };
        var statusBefore = user.Status.ToString();

        // 二次确认（P8）：只认一次性确认凭据，没有"再输一次口令"这条路了。
        // 缺凭据时 <see cref="DenyUnlessConfirmedAsync"/> 一律回 401 OTP_CONFIRM_REQUIRED，
        // 客户端据此去 <c>POST /api/auth/reconfirm</c> 换一张 —— 与旧路径"口令不对"同一个状态码，
        // 于是界面上的错误处理不必按新旧分叉（那段分叉正是回滚期最容易错位的地方）。
        var confirmDeny = await DenyUnlessConfirmedAsync(req.ConfirmToken, user, OtpConfirmPurpose.FaceDelete,
            user.Username, action, requestLog);
        if (confirmDeny != null) return confirmDeny;

        var removed = await _faceTemplates.DeleteByUserIdAsync(user.Id);
        var response = new ApiResponse
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = removed > 0
                ? $"已删除 {removed} 张人脸模板，该账号不再需要刷脸登录"
                : "该账号原本就没有录入人脸",
            Data = new { Removed = removed, Enrolled = false }
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog, response,
            statusBefore, user.Username, AuditResult.Success);
        return Ok(response);
    }
}
