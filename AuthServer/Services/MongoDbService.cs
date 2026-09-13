using AuthServer.Models;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AuthServer.Services;

public class MongoDbService
{
    private readonly IMongoDatabase _database;
    private readonly IMongoCollection<User> _users;
    private readonly IMongoCollection<AuditLog> _auditLogs;
    private readonly IMongoCollection<EmailCode> _emailCodes;

    public MongoDbService(IConfiguration configuration)
    {
        var connectionString = configuration.GetValue<string>("MongoDbSettings:ConnectionString")
            ?? "mongodb://localhost:27017";
        var databaseName = configuration.GetValue<string>("MongoDbSettings:DatabaseName")
            ?? "AuthBaselineDb";

        var client = new MongoClient(connectionString);
        _database = client.GetDatabase(databaseName);
        _users = _database.GetCollection<User>("Users");
        _auditLogs = _database.GetCollection<AuditLog>("AuditLogs");
        _emailCodes = _database.GetCollection<EmailCode>("EmailCodes");

        EnsureIndexes();

        // 预置管理员账号（如果不存在），使用同步方法避免构造函数中 .Wait() 死锁
        SeedAdmin();
    }

    private void EnsureIndexes()
    {
        // 创建唯一索引：用户名
        var usernameKeys = Builders<User>.IndexKeys.Ascending(u => u.Username);
        _users.Indexes.CreateOne(new CreateIndexModel<User>(
            usernameKeys, new CreateIndexOptions { Unique = true }));

        try
        {
            // 邮箱唯一：必须用"部分索引"，只约束真正是字符串的 email 字段。
            // 直接建普通唯一索引会因为大量老账号 email 为 null 而报
            // "multiple null values" 冲突，导致服务起不来。
            var emailKeys = Builders<User>.IndexKeys.Ascending(u => u.Email);
            var emailOptions = new CreateIndexOptions<User>
            {
                Unique = true,
                Name = "uniq_email_when_present",
                PartialFilterExpression = Builders<User>.Filter
                    .Type(u => u.Email, BsonType.String)
            };
            _users.Indexes.CreateOne(new CreateIndexModel<User>(emailKeys, emailOptions));
        }
        catch (Exception ex)
        {
            // 索引问题不应阻断服务启动：业务侧仍会做邮箱查重兜底
            Console.WriteLine($"[Mongo] 邮箱唯一索引创建失败（不影响主流程）: {ex.Message}");
        }

        try
        {
            // 验证码记录：到点自动清理，不需要额外写定时任务。
            // 该版本驱动用 TimeSpan 形式的 ExpireAfter（等价于 TTL 的 expireAfterSeconds=0）。
            var ttlKeys = Builders<EmailCode>.IndexKeys.Ascending(x => x.ExpiresAt);
            var ttlOptions = new CreateIndexOptions { ExpireAfter = TimeSpan.Zero, Name = "ttl_expires_at" };
            _emailCodes.Indexes.CreateOne(new CreateIndexModel<EmailCode>(ttlKeys, ttlOptions));

            // 按 (用户名, 用途) 查询：既支撑校验，也支撑 60 秒重发冷却判定
            var lookupKeys = Builders<EmailCode>.IndexKeys
                .Ascending(x => x.Username)
                .Ascending(x => x.Purpose);
            _emailCodes.Indexes.CreateOne(new CreateIndexModel<EmailCode>(lookupKeys));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Mongo] 验证码索引创建失败（不影响主流程）: {ex.Message}");
        }
    }

    private void SeedAdmin()
    {
        var admin = _users.Find(u => u.Username == "admin").FirstOrDefault();
        if (admin == null)
        {
            var hash = BCrypt.Net.BCrypt.HashPassword("Admin123");
            _users.InsertOne(new User
            {
                Username = "admin",
                PasswordHash = hash,
                Status = UserStatus.Enabled,
                IsAdmin = true,
                CreatedAt = DateTime.UtcNow
            });
        }
    }

    public IMongoCollection<User> Users => _users;
    public IMongoCollection<AuditLog> AuditLogs => _auditLogs;
    public IMongoCollection<EmailCode> EmailCodes => _emailCodes;
}
