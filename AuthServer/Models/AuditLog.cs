using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthServer.Models;

public class AuditLog
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    [BsonElement("operatorId")]
    public string OperatorId { get; set; } = string.Empty;

    [BsonElement("operatorName")]
    public string OperatorName { get; set; } = string.Empty;

    [BsonElement("action")]
    public string Action { get; set; } = string.Empty;

    [BsonElement("statusBefore")]
    public string StatusBefore { get; set; } = string.Empty;

    // 存 JSON 字符串，避免 MongoDB ObjectSerializer 拒绝序列化自定义类型
    [BsonElement("request")]
    public string Request { get; set; } = string.Empty;

    [BsonElement("response")]
    public string Response { get; set; } = string.Empty;

    [BsonElement("statusAfter")]
    public string StatusAfter { get; set; } = string.Empty;

    /// <summary>
    /// 操作结果：成功 / 失败。
    /// 仅看 Action 无法判断操作是否被拒绝（例如 LOGIN 既可能是成功也可能是口令错误），
    /// 因此结果必须独立成列，审计时才能真正区分"登录成功"与"登录失败"。
    /// </summary>
    [BsonElement("result")]
    public string Result { get; set; } = AuditResult.Success;

    /// <summary>被操作的对象用户名（注册/审核/解锁/注销/转让等场景），便于按对象检索。</summary>
    [BsonElement("target")]
    public string Target { get; set; } = string.Empty;

    [BsonElement("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /* ==================== 实验二新增：追责维度 ==================== */

    /// <summary>
    /// 失败 / 拒绝的原因码（如 ACCOUNT_LOCKED、UNAUTHORIZED、WEAK_PASSWORD）。
    /// 成功事件为空串。
    ///
    /// 为什么必须独立成列：只有 result=失败 时，审计员仍不知道"为什么失败"——
    /// 是口令错了、账号被锁，还是越权尝试？原因码把这三者区分开，
    /// 且使"越权尝试"这类高价值线索可以被直接检索出来。
    ///
    /// 兼容性：改造前的老记录没有该字段，读出来是空串，不影响既有界面与筛选。
    /// </summary>
    [BsonElement("reasonCode")]
    public string ReasonCode { get; set; } = string.Empty;

    /// <summary>
    /// 发起本次操作的主体类型：user（已认证）/ anonymous（未认证或身份不可信）/ system（系统自动触发）。
    /// 改造前的老记录该字段为空串，由前端按 operatorId 是否为 anonymous 兜底推断。
    /// </summary>
    [BsonElement("actorType")]
    public string ActorType { get; set; } = string.Empty;

    /// <summary>来源信息（IP + UserAgent），用于回答"这次越权尝试是从哪里发起的"。</summary>
    [BsonElement("sourceIp")]
    public string SourceIp { get; set; } = string.Empty;

    [BsonElement("sourceUserAgent")]
    public string SourceUserAgent { get; set; } = string.Empty;

    /* ==================== 实验二新增：防篡改哈希链 ==================== */

    /// <summary>
    /// 本条记录的自哈希（SHA-256，64 位小写十六进制）。
    /// 输入为"规范化字段串"，见 AuditService.ComputeHash。
    /// 空串表示该记录产生于哈希链上线之前（老数据），完整性校验会跳过它。
    /// </summary>
    [BsonElement("selfHash")]
    public string SelfHash { get; set; } = string.Empty;

    /// <summary>
    /// 前一条记录的 selfHash，链首为 64 个 0。
    ///
    /// 该字段把"单条被改"升级为"整链可验"：
    ///   - 改了本条内容 → 本条 selfHash 与存储值不符；
    ///   - 删了中间一条 → 后一条的 prevHash 对不上，断点立刻暴露；
    ///   - 调换两条顺序 → 两条的 prevHash 同时错位。
    /// </summary>
    [BsonElement("prevHash")]
    public string PrevHash { get; set; } = string.Empty;

    /// <summary>链内严格递增序号，用于定位断点与跨分片排序（时间戳可能重复，不能作序）。</summary>
    [BsonElement("seq")]
    public long Seq { get; set; }

    /// <summary>所在分片集合名，如 AuditLogs_202609。便于归档后按片检索与校验。</summary>
    [BsonElement("shard")]
    public string Shard { get; set; } = string.Empty;
}

/// <summary>主体类型取值。</summary>
public static class ActorType
{
    public const string User = "user";
    public const string Anonymous = "anonymous";
    public const string System = "system";
}

/// <summary>审计结果取值，避免各处硬编码字符串不一致。</summary>
public static class AuditResult
{
    public const string Success = "成功";
    public const string Failed = "失败";
}

/// <summary>审计动作取值。</summary>
public static class AuditAction
{
    public const string Register = "REGISTER";
    public const string LoginSuccess = "LOGIN_SUCCESS";
    public const string LoginFailed = "LOGIN_FAILED";
    public const string Login = "LOGIN"; // 历史数据沿用，新日志已拆分为上面两项

    /// <summary>
    /// 口令修改**失败**。与 ChangePassword 分开的理由：
    ///   "改密成功"是普通操作，"改密被拒"是安全事件 ——
    ///   admin 反复提交不合规的口令、或反复猜自己的旧口令，都属于后者。
    ///   若沿用同一个 action，只能靠 result=失败 间接区分，
    ///   审计员无法用一条查询把"全部改密失败"单独列出来定级。
    /// </summary>
    public const string ChangePasswordFailed = "CHANGE_PASSWORD_FAILED";

    public const string Approve = "APPROVE";
    public const string Unlock = "UNLOCK";
    public const string DeleteUser = "DELETE_USER";
    public const string ChangePassword = "CHANGE_PASSWORD";
    public const string TransferAdmin = "TRANSFER_ADMIN"; // 历史数据沿用，新版本已废弃该功能

    // ---- 角色分离：账号创建与角色任免 ----
    public const string CreateAccount = "CREATE_ACCOUNT";  // 管理员创建账号（含目标角色）
    public const string SetRole = "SET_ROLE";              // 变更他人角色（如任命审计管理员）

    // ---- 邮箱验证码相关 ----
    public const string SendEmailCode = "SEND_EMAIL_CODE";
    public const string ResetPassword = "RESET_PASSWORD";

    /// <summary>重置口令失败（验证码错 / 状态不允许 / 邮箱不匹配）。与上者同理：失败即安全事件。</summary>
    public const string ResetPasswordFailed = "RESET_PASSWORD_FAILED";

    /// <summary>发送验证码被拒（邮箱不存在 / 状态不允许 / 触发限流）。</summary>
    public const string SendEmailCodeFailed = "SEND_EMAIL_CODE_FAILED";

    // ---- 实验二：会话与审计查询相关 ----
    public const string Logout = "LOGOUT";                 // 主动登出，吊销票据
    public const string AuditQuery = "AUDIT_QUERY";        // 查询审计日志（成功也留痕）
    public const string AuditVerify = "AUDIT_VERIFY";      // 执行完整性校验
    public const string AuditAccessDenied = "AUDIT_ACCESS_DENIED"; // 无权限访问审计数据
    public const string AuditTampered = "AUDIT_TAMPERED";  // 校验发现链断裂

    /// <summary>
    /// 检测到系统时钟被拨动（墙钟与本机运行时长两条时间线背离）。
    ///
    /// 为什么要独立成一个动作：加固前，靠拨钟解开锁定是**完全静默**的 ——
    /// 锁定到期走的是登录里的"自动恢复"分支，而那个分支不写任何审计。
    /// 事后翻日志，看不出这个账号曾被"用改时间的方式"放进去过。
    /// 有了这条记录，"有人动过时钟"本身就成为可检索的事件。
    ///
    /// 注意一个诚实的限度：这条记录自己的 timestamp 也来自那个被拨动的时钟，
    /// 所以它的**时间**同样不可信；可信的是"背离量"与两个时间线的读数
    /// （写在 request 报文里），那才是判断拨了多少的依据。
    /// </summary>
    public const string ClockAnomaly = "CLOCK_ANOMALY";
}

/// <summary>
/// 失败 / 拒绝的原因码。
///
/// 与 HTTP 状态码、业务 code 的区别：
///   - HTTP 状态码表达"传输层结果"；
///   - 业务 code 表达"接口层面的业务判定"；
///   - reasonCode 是**审计语义**上的归类，专门回答"这次操作为什么没成功"，
///     并且要让"越权"和"口令错误"能被一条查询直接分开。
/// </summary>
public static class AuditReason
{
    // 会话 / 授权
    public const string NoTicket = "NO_TICKET";
    public const string SessionInvalid = "SESSION_INVALID";
    public const string SessionExpired = "SESSION_EXPIRED";
    public const string SessionRevoked = "SESSION_REVOKED";
    public const string NotAdmin = "NOT_ADMIN";

    /// <summary>
    /// 有登录身份，但不是审计管理员，因此无权查看审计数据。
    ///
    /// 与 NotAdmin 分开的理由：管理员访问审计接口时，若只回 NOT_ADMIN，
    /// 审计员看到的线索是"某个非管理员在试探"，而真实情况是
    /// "一个正常管理员越过了职责边界去够审计数据" —— 这是职责分离
    /// 被破坏的直接证据，价值远高于普通的权限不足，必须能单独检索出来。
    /// </summary>
    public const string NotAuditAdmin = "NOT_AUDIT_ADMIN";

    /// <summary>越界提权：试图把自己或他人设为无权设定的角色（如自封管理员）。</summary>
    public const string ForbiddenRole = "FORBIDDEN_ROLE";

    /// <summary>越界处置：试图操作自己无权处置的目标（如管理员去动另一个管理员）。</summary>
    public const string ForbiddenTarget = "FORBIDDEN_TARGET";

    public const string AccountNotEnabled = "ACCOUNT_NOT_ENABLED";

    // 业务
    public const string InvalidCredentials = "INVALID_CREDENTIALS";

    /// <summary>
    /// 旧口令错误。
    ///
    /// 与 InvalidCredentials 分开的理由：两者都会返回同一个业务 code
    /// （对外统一话术，不透露用户名是否存在），但审计语义完全不同 ——
    /// INVALID_CREDENTIALS 是"账号根本不存在"，本码是"账号存在、登录口令不符"。
    /// 后者是口令猜测攻击的直接指纹，必须能单独检索。
    /// </summary>
    public const string WrongOldPassword = "WRONG_OLD_PASSWORD";

    /// <summary>新旧口令完全相同，被策略拒绝（改密后等于没改）。</summary>
    public const string PasswordReused = "PASSWORD_REUSED";

    public const string AccountLocked = "ACCOUNT_LOCKED";
    public const string PendingApproval = "PENDING_APPROVAL";
    public const string AccountDisabled = "ACCOUNT_DISABLED";
    public const string WeakPassword = "WEAK_PASSWORD";
    public const string EmptyFields = "EMPTY_FIELDS";
    public const string DuplicateUsername = "DUPLICATE_USERNAME";
    public const string InvalidEmail = "INVALID_EMAIL";
    public const string NotFound = "NOT_FOUND";
    public const string NotPending = "NOT_PENDING";
    public const string NotLocked = "NOT_LOCKED";
    public const string CodeInvalid = "CODE_INVALID";

    /// <summary>验证码与所填邮箱不是同一封信。</summary>
    public const string EmailMismatch = "EMAIL_MISMATCH";

    /// <summary>验证码已过期。</summary>
    public const string CodeExpired = "CODE_EXPIRED";

    /// <summary>验证码错误次数用尽，记录已作废。</summary>
    public const string CodeTooManyAttempts = "CODE_TOO_MANY_ATTEMPTS";

    /// <summary>验证码已使用过（一次性，用过即废）。</summary>
    public const string CodeUsed = "CODE_USED";

    /// <summary>未填验证码。</summary>
    public const string CodeRequired = "CODE_REQUIRED";

    /// <summary>发码过于频繁，触发 60 秒冷却。</summary>
    public const string ResendTooSoon = "RESEND_TOO_SOON";

    /// <summary>发信通道未启用（EMAIL_DISABLED），口令找回链路整体不可用。</summary>
    public const string EmailDisabled = "EMAIL_DISABLED";

    /// <summary>发码用途不合法（既不是 REGISTER 也不是 RESET）。</summary>
    public const string InvalidPurpose = "INVALID_PURPOSE";

    /// <summary>发信失败（SMTP / 通道异常），验证码未能送达。</summary>
    public const string EmailSendFailed = "EMAIL_SEND_FAILED";

    /// <summary>目标邮箱已被其它账号绑定，不能再用于注册。</summary>
    public const string EmailAlreadyBound = "EMAIL_ALREADY_BOUND";

    /// <summary>角色未发生变化（请求的新角色与目标当前角色一致，无需变更）。</summary>
    public const string RoleUnchanged = "ROLE_UNCHANGED";

    // 完整性
    public const string ChainBroken = "CHAIN_BROKEN";

    // ---- 时钟背离（配合 AuditAction.ClockAnomaly） ----

    /// <summary>
    /// 墙钟快于单调线 —— 被**前拨**了。
    /// 这是"想靠改时间提前解开锁定"的直接指纹，也是本次加固要盯住的那一类。
    /// </summary>
    public const string ClockRolledForward = "CLOCK_ROLLED_FORWARD";

    /// <summary>
    /// 墙钟慢于单调线 —— 被**回拨**了。
    ///
    /// 与上者分开的理由：两者的安全含义完全不同。前拨是**攻击**（试图提前解锁）；
    /// 回拨通常是**事故**（主板电池耗尽、虚拟机快照回滚），后果是把锁定拖得极长。
    /// 混在一个码里，审计员无法区分"有人在攻击"和"有台机器坏了"。
    /// </summary>
    public const string ClockRolledBackward = "CLOCK_ROLLED_BACKWARD";
}
