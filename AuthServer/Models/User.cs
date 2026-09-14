using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthServer.Models;

public enum UserStatus
{
    Pending,    // 待审核
    Enabled,    // 启用
    Locked,     // 锁定
    Disabled    // 禁用（可选）
}

public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    [BsonElement("username")]
    public string Username { get; set; } = string.Empty;

    [BsonElement("passwordHash")]
    public string PasswordHash { get; set; } = string.Empty;

    [BsonElement("status")]
    [BsonRepresentation(BsonType.String)]
    public UserStatus Status { get; set; } = UserStatus.Pending;

    /// <summary>
    /// 绑定的邮箱（统一小写规范化后存储）。
    /// 老账号为 null —— 邮箱功能上线前注册的账号允许继续使用，不强制补绑。
    /// </summary>
    [BsonElement("email")]
    public string? Email { get; set; }

    /// <summary>
    /// 邮箱是否已通过验证码验证。
    /// 只有走完"发码 → 校验"流程的邮箱才置为 true，用于找回密码链路的前置条件。
    /// </summary>
    [BsonElement("emailVerified")]
    public bool EmailVerified { get; set; } = false;

    [BsonElement("failedLoginAttempts")]
    public int FailedLoginAttempts { get; set; } = 0;

    [BsonElement("lockoutEnd")]
    public DateTime? LockoutEnd { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("isAdmin")]
    public bool IsAdmin { get; set; } = false;
}

public class UserResponse
{
    public string Id { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;

    /// <summary>脱敏后的邮箱（如 s*****@example.com）。老账号无邮箱时为空串。</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>邮箱是否已验证。管理员据此判断该账号能否走"找回密码"。</summary>
    public bool EmailVerified { get; set; }

    public int FailedLoginAttempts { get; set; }
    public DateTime? LockoutEnd { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsAdmin { get; set; }
}
