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
    public int FailedLoginAttempts { get; set; }
    public DateTime? LockoutEnd { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsAdmin { get; set; }
}
