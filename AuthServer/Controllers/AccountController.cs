using AuthServer.Models;
using AuthServer.Services;
using AuthServer.Services.Face;
using Microsoft.AspNetCore.Mvc;
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
    private readonly EmailOptions _emailOptions;
    private readonly FaceLoginService _face;
    private readonly FaceTemplateStore _faceTemplates;
    private readonly FacePreviewService _preview;

    public AccountController(MongoDbService db, AuditWriter auditWriter, SessionService sessions,
        PepperProvider pepper, VerificationService codes, EmailOptions emailOptions,
        FaceLoginService face, FaceTemplateStore faceTemplates, FacePreviewService preview,
        IConfiguration configuration)
        : base(db, auditWriter, sessions, pepper, configuration)
    {
        _codes = codes;
        _emailOptions = emailOptions;
        _face = face;
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

        var user = new User
        {
            Username = sanitizedUsername,
            PasswordHash = PasswordHasher.Hash(req.Password, _pepper.Pepper),
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

        // 重置成功：换口令，并一并清掉锁定与失败计数（否则改完密码仍被锁在门外）
        user.PasswordHash = PasswordHasher.Hash(req.NewPassword, _pepper.Pepper);
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

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(req.OldPassword) || string.IsNullOrWhiteSpace(req.NewPassword))
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

        if (!PasswordHasher.Verify(req.OldPassword, user.PasswordHash, _pepper.Pepper).Valid)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidCredentials, Message = "旧密码错误" };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp, statusBefore,
                sanitizedUsername, AuditResult.Failed, AuditReason.WrongOldPassword);
            return Unauthorized(resp);
        }

        // 新旧口令相同：改密等于没改，按策略拒绝。
        // 这条校验必须放在**旧口令验过之后** —— 否则攻击者能拿它当"口令是否正确"的探针。
        if (string.Equals(req.NewPassword, req.OldPassword, StringComparison.Ordinal))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.PasswordReused, Message = "新密码不能与当前密码相同" };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp, statusBefore,
                sanitizedUsername, AuditResult.Failed, AuditReason.PasswordReused);
            return BadRequest(resp);
        }

        user.PasswordHash = PasswordHasher.Hash(req.NewPassword, _pepper.Pepper);
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

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

        if (string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "请先输入当前登录口令" };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceEnrollFailed, statusBefore,
                requestLog, resp, statusBefore, user.Username, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        if (!PasswordHasher.Verify(req.Password, user.PasswordHash, _pepper.Pepper).Valid)
        {
            // 这次失败的语义就是"有人在猜这个账号的口令"，与登录时的口令错误同类，
            // 因此**计次**（走 A 组语义，见 FaceCodes.IsCounted）。
            // 它与 create-account 的二次口令不同：那里的操作者本身就是管理员、
            // 且目标是他人的账号；这里猜的是**自己的**登录口令，
            // 而这条路径若不计次就是一条无节流的在线口令猜测通道。
            var lockMessage = await ApplyCountedFailureAsync(user);
            var resp = new ApiResponse
            {
                Success = false,
                Code = lockMessage is null ? BusinessCode.InvalidCredentials : BusinessCode.AccountLocked,
                Message = lockMessage ?? "口令校验失败，已拒绝录入",
                Data = new { FailedAttempts = user.FailedLoginAttempts, LockoutEnd = user.LockoutEnd }
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceEnrollFailed, statusBefore,
                requestLog, resp, user.Status.ToString(), user.Username, AuditResult.Failed,
                lockMessage is null ? AuditReason.FaceWrongPassword : AuditReason.AccountLocked);
            return Unauthorized(resp);
        }

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

        if (string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "删除人脸需要重新输入当前口令" };
            await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
                user.Username, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        if (!PasswordHasher.Verify(req.Password, user.PasswordHash, _pepper.Pepper).Valid)
        {
            var lockMessage = await ApplyCountedFailureAsync(user);
            var resp = new ApiResponse
            {
                Success = false,
                Code = lockMessage is null ? BusinessCode.InvalidCredentials : BusinessCode.AccountLocked,
                Message = lockMessage ?? "口令校验失败，已拒绝删除人脸",
                Data = new { FailedAttempts = user.FailedLoginAttempts, LockoutEnd = user.LockoutEnd }
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog, resp,
                user.Status.ToString(), user.Username, AuditResult.Failed,
                lockMessage is null ? AuditReason.FaceWrongPassword : AuditReason.AccountLocked);
            return Unauthorized(resp);
        }

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
