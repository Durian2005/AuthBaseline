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
    public const string Approve = "APPROVE";
    public const string Unlock = "UNLOCK";
    public const string DeleteUser = "DELETE_USER";
    public const string ChangePassword = "CHANGE_PASSWORD";
    public const string TransferAdmin = "TRANSFER_ADMIN";

    // ---- 邮箱验证码相关 ----
    public const string SendEmailCode = "SEND_EMAIL_CODE";
    public const string ResetPassword = "RESET_PASSWORD";

    // ---- 实验二：会话与审计查询相关 ----
    public const string Logout = "LOGOUT";                 // 主动登出，吊销票据
    public const string AuditQuery = "AUDIT_QUERY";        // 查询审计日志（成功也留痕）
    public const string AuditVerify = "AUDIT_VERIFY";      // 执行完整性校验
    public const string AuditAccessDenied = "AUDIT_ACCESS_DENIED"; // 无权限访问审计数据
    public const string AuditTampered = "AUDIT_TAMPERED";  // 校验发现链断裂
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
    public const string AccountNotEnabled = "ACCOUNT_NOT_ENABLED";

    // 业务
    public const string InvalidCredentials = "INVALID_CREDENTIALS";
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

    // 完整性
    public const string ChainBroken = "CHAIN_BROKEN";
}
