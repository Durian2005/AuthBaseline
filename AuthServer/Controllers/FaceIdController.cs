using AuthServer.Models;
using AuthServer.Services;
using AuthServer.Services.FaceId;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;

namespace AuthServer.Controllers;

/**
 * 纯人脸登录（FaceId）的自助接口：状态 / 录入 / 删除。
 *
 * 路由独立于 `/api/auth`（2FA 的人脸接口在那里）：
 *   两个模块**互不引用**，路由也分开，删掉任一模块时不需要动另一边的控制器。
 *
 * 鉴权：三条接口都只要求"本人已登录"（票据判定"我是谁"）。
 *   请求体里连用户名都没有 —— 人脸自助操作的对象只能是票据代表的那个人，
 *   若允许从请求体读用户名，就必须再额外证明"你就是那个人"，而首次录入时
 *   没有旧模板可比，等于把入口敞开（同 2FA 的理由）。
 *
 * 二次口令：录入与删除**都必须重输当前口令**，且口令错误**计次**。
 *   这一条是本模块唯一可能被用来爆破口令的地方：不重输口令的话，
 *   "拿到会话就能给自己录脸"，从此只需刷脸登录，且改口令甩不掉。
 *
 * 审计：状态查询**不写**（每次打开页面都会拉，写了只会把链刷成噪声）；
 *   录入 / 删除 / 一切失败都写，且诊断量只进审计、不进响应体。
 */
[ApiController]
[Route("api/faceid")]
public class FaceIdController : AuthControllerBase
{
    private readonly FaceIdEnrollService _enroll;
    private readonly FaceIdLoginService _login;
    private readonly FaceIdTemplateStore _templates;

    public FaceIdController(MongoDbService db, AuditWriter auditWriter, SessionService sessions,
        PepperProvider pepper, IConfiguration configuration,
        FaceIdEnrollService enroll, FaceIdLoginService login, FaceIdTemplateStore templates)
        : base(db, auditWriter, sessions, pepper, configuration)
    {
        _enroll = enroll;
        _login = login;
        _templates = templates;
    }

    /// <summary>
    /// 本人 FaceId 状态。enrolled / usable / modelMismatch 三个数一起下发，
    /// 界面才能区分"没录过"与"录过但模型换了"（后者要让用户重新录，而不是反复刷脸）。
    /// </summary>
    [HttpGet("status")]
    public async Task<IActionResult> Status()
    {
        var (user, deny) = await RequireAuthenticatedAsync(AuditAction.AuditAccessDenied, "self-faceid");
        if (deny != null) return deny;

        var engine = _enroll.EngineStatus;
        var (total, usable, foreign) = await _templates.StatusAsync(user!.Id);

        return Ok(new ApiResponse<FaceIdStatusResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = "查询成功",
            Data = new FaceIdStatusResponse
            {
                Enabled = _enroll.Enabled,
                Enrolled = total > 0,
                TemplateCount = (int)total,
                UsableCount = (int)usable,
                ModelMismatchCount = (int)foreign,
                EnrolledAt = await _templates.LastEnrolledAtAsync(user.Id),
                MaxTemplates = _enroll.MaxTemplates,
                Threshold = _enroll.Threshold,
                SfaceThreshold = _enroll.SFaceThreshold,
                ModelId = _templates.ModelId,
                EngineReady = engine.Ready,
                EngineMessage = engine.Ready ? string.Empty : engine.Message,
                PadEnabled = _enroll.PadEnabled,
                PadReady = _enroll.PadStatus.Ready,
                PadMinLive = _enroll.PadMinLive,
                RejectMultipleFaces = _enroll.RejectMultipleFaces
            }
        });
    }

    /// <summary>
    /// 录入 / 更换 FaceId 模板（单步：口令 → 服务端采集 → 质量闸门 → 写模板）。
    ///
    /// 为什么不做成 2FA 那样的两步式挑战：
    ///   两步式的意义是"把服务端随机决定的动作先告诉用户"（活体挑战）。
    ///   本模块**没有活体挑战**，动作没有任何需要协商的内容，
    ///   多一张一次性 token 只会多一处状态与一处过期逻辑，不增加任何安全性。
    ///   代价是用户点下按钮后有一小段采样时间（最多 ~1 秒），
    ///   界面必须在此期间明确提示"请看镜头"，并在结束后给出可操作的原因。
    /// </summary>
    [HttpPost("enroll")]
    public async Task<IActionResult> Enroll([FromBody] FaceIdPasswordRequest req)
    {
        const string action = AuditAction.FaceIdEnroll;
        const string failAction = AuditAction.FaceIdEnrollFailed;
        var (user, deny) = await RequireAuthenticatedAsync(action, "self-faceid");
        if (deny != null) return deny;

        var requestLog = new { user = user!.Username };
        var statusBefore = user.Status.ToString();

        // 模块关闭 / 引擎不可用 ⇒ 明确拒绝并留痕，而不是给一个"看起来能用"的按钮。
        if (!_enroll.Enabled || !_enroll.EngineStatus.Ready)
        {
            var code = _enroll.Enabled ? BusinessCode.FaceIdEngineUnavailable : BusinessCode.FaceIdDisabled;
            var message = _enroll.Enabled
                ? FaceIdCodes.MessageFor(BusinessCode.FaceIdEngineUnavailable)
                : FaceIdCodes.MessageFor(BusinessCode.FaceIdDisabled);
            var resp = new ApiResponse { Success = false, Code = code, Message = message };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                statusBefore, user.Username, AuditResult.Failed, AuditReason.FaceIdEngineUnavailable);
            return StatusCode(_enroll.Enabled ? 503 : 400, resp);
        }

        if (string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.EmptyFields,
                Message = "录入人脸需要重新输入当前口令"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                statusBefore, user.Username, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        if (!PasswordHasher.Verify(req.Password, user.PasswordHash, _pepper.Pepper).Valid)
        {
            // 这次失败就是"有人在猜这个账号的口令"，与登录时的口令错误同类 ⇒ 计次。
            // 不计次的话，这条路径就是一条无节流的在线口令猜测通道。
            var lockMessage = await ApplyCountedFailureAsync(user);
            var resp = new ApiResponse
            {
                Success = false,
                Code = lockMessage is null ? BusinessCode.InvalidCredentials : BusinessCode.AccountLocked,
                Message = lockMessage ?? "口令校验失败，已拒绝录入人脸",
                Data = new { FailedAttempts = user.FailedLoginAttempts, LockoutEnd = user.LockoutEnd }
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                user.Status.ToString(), user.Username, AuditResult.Failed,
                lockMessage is null ? AuditReason.FaceIdWrongPassword : AuditReason.AccountLocked);
            return Unauthorized(resp);
        }

        var outcome = await _enroll.EnrollAsync(user.Id, user.Username);
        if (!outcome.Success)
        {
            // 计次与否**由码决定**（FaceIdCodes.IsCounted），调用点不许自己判断：
            //   活体失败 = 攻击信号 ⇒ 与口令错同等累加失败窗口（P1b 起）；
            //   质量类/引擎类 = 配合或环境问题 ⇒ 一律不计，否则用户反复调整坐姿就会把自己锁掉。
            var countedLock = FaceIdCodes.IsCounted(outcome.AuditReason)
                ? await ApplyCountedFailureAsync(user)
                : null;

            // 引擎不可用属于本机环境问题（503），质量不合格属于"这次没配合好"（400）。
            // 两者在审计里也分开（FaceIdEngineUnavailable vs FaceIdEnrollRejected）。
            var resp = new ApiResponse
            {
                Success = false,
                Code = countedLock is null ? outcome.BusinessCode : BusinessCode.AccountLocked,
                Message = countedLock ?? outcome.Message,
                Data = countedLock is null ? null : new
                {
                    FailedAttempts = user.FailedLoginAttempts,
                    LockoutEnd = user.LockoutEnd
                }
                // 诊断量（帧数 / 脸数 / 清晰度）只进审计，不进响应体：对用户没有意义
            };
            var httpStatus = string.Equals(outcome.BusinessCode, BusinessCode.FaceIdEngineUnavailable, StringComparison.Ordinal)
                || string.Equals(outcome.BusinessCode, BusinessCode.FaceIdDisabled, StringComparison.Ordinal)
                ? 503 : 400;
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog,
                new
                {
                    user.Username,
                    outcome.BusinessCode,
                    outcome.Diagnostic,
                    ModelId = _templates.ModelId
                },
                statusBefore, user.Username, AuditResult.Failed,
                countedLock is null ? outcome.AuditReason : AuditReason.AccountLocked);
            return StatusCode(countedLock is null ? httpStatus : 401, resp);
        }

        var response = new ApiResponse
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = outcome.Message,
            Data = new
            {
                TemplateCount = outcome.TemplateCount,
                // 换模型后第一次录入会顺手清掉旧模型模板 —— 把这件事告诉用户，
                // 否则"录了一张却显示只有一张"看起来像丢数据。
                PurgedForeign = outcome.PurgedForeign,
                Evicted = outcome.Evicted,
                ModelId = _templates.ModelId,
                Threshold = _enroll.Threshold,
                SfaceThreshold = _enroll.SFaceThreshold,
                EnrolledAt = DateTime.UtcNow
            }
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog,
            new
            {
                user.Username,
                outcome.TemplateCount,
                outcome.PurgedForeign,
                outcome.Evicted,
                outcome.Diagnostic,
                ModelId = _templates.ModelId
            },
            statusBefore, user.Username, AuditResult.Success);
        return Ok(response);
    }

    /// <summary>
    /// 删除本人的 FaceId 模板。**必须重新输入口令**，口令错误计次。
    ///
    /// 为什么删除也要口令：删除等于把"这条登录方式"整条撤掉。
    /// 拿到会话就能删的话，攻击者可以做一件很隐蔽的事 ——
    /// 把受害者的人脸模板删掉，让他"以为系统坏了"，同时自己仍能用口令登录。
    /// </summary>
    [HttpPost("delete")]
    public async Task<IActionResult> Delete([FromBody] FaceIdPasswordRequest req)
    {
        const string action = AuditAction.FaceIdTemplateDeleted;
        var (user, deny) = await RequireAuthenticatedAsync(action, "self-faceid");
        if (deny != null) return deny;

        var requestLog = new { user = user!.Username };
        var statusBefore = user.Status.ToString();

        if (string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.EmptyFields,
                Message = "删除人脸需要重新输入当前口令"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog, resp,
                statusBefore, user.Username, AuditResult.Failed, AuditReason.EmptyFields);
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
                lockMessage is null ? AuditReason.FaceIdWrongPassword : AuditReason.AccountLocked);
            return Unauthorized(resp);
        }

        var removed = await _enroll.DeleteAllAsync(user.Id);
        var response = new ApiResponse
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = removed > 0
                ? $"已删除 {removed} 张纯人脸登录模板"
                : "该账号原本就没有录入可用于登录的人脸",
            Data = new { Removed = removed, Enrolled = false }
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog, response,
            statusBefore, user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 匿名：纯人脸登录 ==================== */

    /**
     * 用户名 + 一次摄像头采集完成登录。**匿名可访问**（与 /api/auth/login 同级）。
     *
     * 与口令登录是**两种并列的登录方式**，不是"口令之后再刷脸"：
     *   请求体里没有口令，画面也永远由服务端自己采集 ——
     *   接口上没有"传一张图 / 传一个特征"这种形状，所以前端无法伪造一次识别。
     *
     * 计次规则由码决定（FaceIdCodes.IsCounted），调用点不自己判断：
     *   MISMATCH（明确不是本人）计次，与口令错同级；
     *   GRAY_ZONE（把握不足）、质量类、引擎类一律不计 ——
     *   把光线问题算成失败，等于让"今天灯太暗"逐步把本人锁在门外。
     */
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] FaceIdLoginRequest req)
    {
        const string action = AuditAction.LoginFailed;
        var username = Norm(req.Username);
        var requestLog = new { req.Username };

        if (string.IsNullOrWhiteSpace(username))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "用户名不能为空" };
            await _auditWriter.WriteAsync("anonymous", "anonymous", action, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();

        // 账号不存在：与"人脸不匹配"**同码同话术**。人脸登录天然要开摄像头，
        // 本来就无法做到与口令登录等价的不可区分；但至少不额外泄露一个"这个用户名存在"。
        if (user == null)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.FaceIdMismatch,
                Message = FaceIdCodes.MessageFor(BusinessCode.FaceIdMismatch)
            };
            await _auditWriter.WriteAsync("anonymous", "anonymous", action, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.FaceIdMismatch);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        // 禁用与锁定都必须在采脸之前拒绝：锁定账号不该再拿到一次识别机会。
        if (user.Status != UserStatus.Enabled)
        {
            if (user.Status == UserStatus.Locked)
            {
                var verdict = TimeGuard.Assess(user, TimeGuard.WallNow(), TimeGuard.UptimeMs());
                await LogClockDriftIfAnyAsync(user, verdict, "FACEID_LOGIN", user.Username);
                return await LockoutRejectionAsync(user, verdict, action, statusBefore, requestLog,
                    user.Username, "账号已锁定，", 401);
            }

            var disabled = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.AccountDisabled,
                Message = "账号已被禁用，请联系管理员"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog, disabled,
                statusBefore, user.Username, AuditResult.Failed, AuditReason.AccountDisabled);
            return StatusCode(403, disabled);
        }

        var outcome = await _login.LoginAsync(user.Id);

        if (outcome.Success)
        {
            ResetFailedAttempts(user);
            user.LastLoginAt = DateTime.UtcNow;
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

            var issued = await _sessions.IssueAsync(user);
            var ok = new ApiResponse<LoginResult>
            {
                Success = true,
                Code = BusinessCode.Ok,
                Message = "登录成功（人脸）",
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

            // 审计里记"第二因子 = FACEID"，让审计员能区分"口令登录"与"人脸登录"；
            // 两个模型的相似度都只进审计（对用户没有意义，对事后判断"是不是擦边通过"
            // 以及"是不是 SFace 那一票否决的"有用）。
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginSuccess, statusBefore,
                new { req.Username, Similarity = outcome.Similarity, SFaceSimilarity = outcome.SFaceSimilarity },
                new
                {
                    user.Username,
                    user.Status,
                    Role = user.Role.ToString(),
                    TicketIssued = true,
                    SecondFactor = "FACEID"
                },
                user.Status.ToString(), user.Username, AuditResult.Success);
            return Ok(ok);
        }

        // 失败：计次与否**只看码**（与录入侧同一套规则）。
        var auditReason = FaceIdCodes.ToAuditReason(outcome.BusinessCode);
        var counted = FaceIdCodes.IsCounted(auditReason);
        var lockMessage = counted ? await ApplyCountedFailureAsync(user) : null;

        var body = new ApiResponse
        {
            Success = false,
            Code = lockMessage is null ? outcome.BusinessCode : BusinessCode.AccountLocked,
            Message = lockMessage ?? outcome.Message,
            Data = new
            {
                // 两个分数都回传给界面：本人看到"0.83 还差一点"就知道是光线问题；
                // 而"主模型 0.81 / SFace 0.39"这种组合说明是第二模型否掉的 ——
                // 界面上给出的是"没通过"，不会替用户解释成"脸不对"。
                // 它不构成可用的攻击信息（本来就能反复试）。
                //
                // ⚠️ 键名刻意写成小写 sfaceSimilarity：默认的 camelCase 策略只把**首字母**
                //    小写，`SFaceSimilarity` 会变成 `sFaceSimilarity` —— 少一个字母的客户端
                //    就永远读到 undefined，而且不会报错（探针第一次就是这么红的）。
                Similarity = outcome.Similarity,
                sfaceSimilarity = outcome.SFaceSimilarity,
                LockoutEnd = lockMessage is null ? (DateTime?)null : user.LockoutEnd
            }
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore,
            new { req.Username, Similarity = outcome.Similarity, SFaceSimilarity = outcome.SFaceSimilarity },
            body, statusBefore, user.Username,
            AuditResult.Failed, lockMessage is null ? auditReason : AuditReason.AccountLocked);
        return Unauthorized(body);
    }
}
