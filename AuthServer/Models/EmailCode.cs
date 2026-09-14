using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthServer.Models;

/// <summary>
/// 验证码用途。必须严格隔离：
/// 注册码不能用于重置密码，重置码也不能用于注册，
/// 否则一次验证码就能通吃所有场景，等于没有验证。
/// </summary>
public static class EmailCodePurpose
{
    public const string Register = "REGISTER";
    public const string Reset = "RESET";

    public static bool IsValid(string? purpose) =>
        purpose == Register || purpose == Reset;

    public static string Describe(string purpose) => purpose switch
    {
        Register => "注册绑定邮箱",
        Reset => "重置密码",
        _ => purpose
    };
}

/// <summary>
/// 邮箱验证码记录。
///
/// 安全设计：
///   - 只存口令散列（BCrypt），不存明文验证码。数据库泄露也无法直接使用。
///   - 记录与 (username, purpose) 绑定，A 收到的验证码无法用于 B 的账号。
///   - 一次性：校验通过立即写 consumedAt，同一验证码不可复用。
///   - 过期时间写进 expiresAt，并建立 TTL 索引由 MongoDB 自动清理，
///     既不用写定时任务，也不会让过期验证码长期驻留。
/// </summary>
public class EmailCode
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    /// <summary>申请验证码的账号（注册场景为待创建的用户名），统一小写。</summary>
    [BsonElement("username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>验证码实际发送到的邮箱，统一小写规范化。</summary>
    [BsonElement("email")]
    public string Email { get; set; } = string.Empty;

    [BsonElement("purpose")]
    public string Purpose { get; set; } = EmailCodePurpose.Register;

    /// <summary>BCrypt 散列后的 6 位验证码，绝不明文落库。</summary>
    [BsonElement("codeHash")]
    public string CodeHash { get; set; } = string.Empty;

    [BsonElement("expiresAt")]
    public DateTime ExpiresAt { get; set; }

    /// <summary>已尝试校验次数，达到上限后该验证码立即作废。</summary>
    [BsonElement("attempts")]
    public int Attempts { get; set; }

    /// <summary>被使用的时刻；非空表示该验证码已失效（用过或作废）。</summary>
    [BsonElement("consumedAt")]
    public DateTime? ConsumedAt { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>最近一次发送时刻，用于 60 秒重发冷却判定。</summary>
    [BsonElement("lastSentAt")]
    public DateTime LastSentAt { get; set; } = DateTime.UtcNow;
}
