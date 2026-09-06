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
}
