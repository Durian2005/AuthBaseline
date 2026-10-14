namespace AuthServer.Models;

/// <summary>
/// 业务响应码 —— 出现在 <see cref="ApiResponse.Code"/> 里、**返回给前端**的那一套码。
///
/// 与 <see cref="AuditReason"/> / <see cref="AuditAction"/> 的关系
/// ==========================================================
/// **两套码、刻意不合并**，只是偶尔字面量相同：
///
/// | | 本类（业务码） | <c>AuditReason</c>（审计原因码） |
/// |---|---|---|
/// | 去哪 | 响应体，用户看得到 | 审计库，只进不出 |
/// | 用途 | 前端据此决定提示文案 | 支撑"反复弱口令/口令猜测"这类检索 |
/// | 粒度 | 按**用户可理解**划分 | 按**可检索的安全事实**划分 |
///
/// 所以不能合并成一套：
///   · 同一个业务码可能对应多个原因码（"新旧密码相同"从用户角度是一件事，
///     但审计要区分"旧口令验过之后才发现"与"没验就报"，后者会变成口令探针）；
///   · 同一个原因码也可能出现在多个业务码下（`InvalidCredentials` 在登录、
///     重置口令、管理员口令校验三处都可能是不同的对外话术）。
///
/// 两者的转换一律走**显式映射**（如 `VerifyCodeReason.From()`），
/// 不要为了省事直接把业务码透传给审计，那样会把"给用户看的话术"
/// 和"可检索的安全事实"混成一锅，两边都失去意义。
///
/// 改这里的值 = 改前端契约
/// =======================
/// 常量值就是前端 `format.js` 里比对的字符串。改名或改值必须同步前端，
/// 否则前端会落到"未知错误"的兜底分支（不会崩，但提示文案会退化成默认值）。
/// 这正是把字面量收口到常量类的价值：全局搜索一次就能找全。
public static class BusinessCode
{
    /// <summary>成功。所有正常返回都用它。</summary>
    public const string Ok = "OK";

    // ── 通用校验 ────────────────────────────────────────────────
    public const string EmptyFields = "EMPTY_FIELDS";
    public const string NotFound = "NOT_FOUND";
    public const string InvalidEmail = "INVALID_EMAIL";

    // ── 账号 / 口令 ─────────────────────────────────────────────
    /// <summary>
    /// 账号不存在，或凭据不匹配 —— 对外**统一话术**，防枚举。
    /// 注意它同时是审计原因码的字面量，但那是另一套码，别互相引用。
    /// </summary>
    public const string InvalidCredentials = "INVALID_CREDENTIALS";
    public const string WeakPassword = "WEAK_PASSWORD";
    public const string PasswordReused = "PASSWORD_REUSED";
    public const string DuplicateUsername = "DUPLICATE_USERNAME";
    public const string AccountDisabled = "ACCOUNT_DISABLED";
    public const string AccountNotEnabled = "ACCOUNT_NOT_ENABLED";
    public const string AccountLocked = "ACCOUNT_LOCKED";
    public const string PendingApproval = "PENDING_APPROVAL";
    public const string NotPending = "NOT_PENDING";
    public const string NotLocked = "NOT_LOCKED";
    public const string AlreadyFrozen = "ALREADY_FROZEN";

    // ── 邮件验证码 ──────────────────────────────────────────────
    public const string EmailDisabled = "EMAIL_DISABLED";
    public const string EmailAlreadyBound = "EMAIL_ALREADY_BOUND";
    public const string InvalidPurpose = "INVALID_PURPOSE";

    // ── 角色 / 权限 ─────────────────────────────────────────────
    public const string InvalidRole = "INVALID_ROLE";
    public const string ForbiddenRole = "FORBIDDEN_ROLE";
    public const string ForbiddenTarget = "FORBIDDEN_TARGET";
    public const string RoleUnchanged = "ROLE_UNCHANGED";
    public const string CannotSetOwnRole = "CANNOT_SET_OWN_ROLE";
    /// <summary>管理角色不参与沉睡账号冻结（防权力真空）。</summary>
    public const string DormantProtectedRole = "DORMANT_PROTECTED_ROLE";

    // ── 时间源加固 ──────────────────────────────────────────────
    /// <summary>检测到墙钟被拨动。</summary>
    public const string ClockAnomaly = "CLOCK_ANOMALY";

    // ── 人脸（可选第二因子） ─────────────────────────────────────
    // 与 AuditReason.Face* 是**两套码**（见本类顶部说明），只是偶尔字面量相近：
    // 这里的码决定前端显示什么话术，那边的码决定审计怎么归类。
    // 例如"人脸没对上"在界面上要说人话（"人脸与录入时不匹配，请正对摄像头"），
    // 而审计里要的是可检索的事实（FACE_MISMATCH）。

    /// <summary>
    /// 口令已通过，但该账号启用了人脸，**尚未签发任何票据**。
    ///
    /// 这不是错误，而是登录流程的中间态 —— 前端收到它应该切到人脸步骤，
    /// 而不是弹一条"登录失败"。用 200 + Success=false + 本码表达，
    /// 刻意**不用 401**：401 在前端会被当作"账号或口令不对"，
    /// 那会让用户以为自己口令输了。
    /// </summary>
    public const string FaceRequired = "FACE_REQUIRED";

    /// <summary>人脸未达阈值。</summary>
    public const string FaceMismatch = "FACE_MISMATCH";

    /// <summary>活体动作挑战未通过。</summary>
    public const string FaceLivenessFailed = "FACE_LIVENESS_FAILED";

    /// <summary>挑战无效：过期 / 已使用 / 不属于本次尝试。</summary>
    public const string FaceChallengeInvalid = "FACE_CHALLENGE_INVALID";

    /// <summary>画面里没有人脸。</summary>
    public const string FaceNoFace = "FACE_NO_FACE";

    /// <summary>人脸质量不达标（太远 / 太暗 / 侧脸过大）。</summary>
    public const string FaceLowQuality = "FACE_LOW_QUALITY";

    /// <summary>动作做完了但没回正，缺少可比较的一帧。</summary>
    public const string FaceNotReturned = "FACE_NOT_RETURNED";

    /// <summary>录入过程未通过（活体或质量原因），模板没有被写入。</summary>
    public const string FaceEnrollFailed = "FACE_ENROLL_FAILED";

    /// <summary>本机没有人脸模板。</summary>
    public const string FaceNotEnrolled = "FACE_NOT_ENROLLED";

    /// <summary>人脸引擎不可用（模型缺失 / 摄像头打不开）。</summary>
    public const string FaceEngineUnavailable = "FACE_ENGINE_UNAVAILABLE";
}
