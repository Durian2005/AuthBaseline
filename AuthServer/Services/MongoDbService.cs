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
    private readonly IMongoCollection<Session> _sessions;
    private readonly IMongoCollection<AuditChainHead> _auditChainHeads;

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
        _sessions = _database.GetCollection<Session>("Sessions");
        _auditChainHeads = _database.GetCollection<AuditChainHead>("AuditChainHeads");

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

        try
        {
            // 会话票据：ticket 唯一，且必须能按票据快速查（每次请求都要校验）
            var ticketKeys = Builders<Session>.IndexKeys.Ascending(s => s.Ticket);
            _sessions.Indexes.CreateOne(new CreateIndexModel<Session>(
                ticketKeys, new CreateIndexOptions { Unique = true, Name = "uniq_ticket" }));

            // 过期票据自动清理：与 EmailCodes 同样的 TTL 手法，无需定时任务
            var ttlKeys = Builders<Session>.IndexKeys.Ascending(s => s.ExpiresAt);
            _sessions.Indexes.CreateOne(new CreateIndexModel<Session>(
                ttlKeys, new CreateIndexOptions { ExpireAfter = TimeSpan.Zero, Name = "ttl_session_expires" }));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Mongo] 会话索引创建失败（不影响主流程）: {ex.Message}");
        }
    }

    /// <summary>
    /// 取出某个审计分片的集合句柄。
    /// 分片名由 AuditService 决定（AuditLogs_yyyyMM 或按条数滚动），
    /// 集合不存在时 MongoDB 会在首次写入时自动创建。
    /// </summary>
    public IMongoCollection<AuditLog> GetAuditShard(string shard) =>
        _database.GetCollection<AuditLog>(shard);

    /// <summary>
    /// 列举所有审计分片名：以 AuditLogs 开头，但排除链尾锚点等非分片集合。
    /// 含改造前的 AuditLogs 主集合（它作为"历史分片"继续可查、可展示）。
    /// </summary>
    public async Task<List<string>> ListAuditShardNamesAsync()
    {
        var names = new List<string>();
        using var cursor = await _database.ListCollectionNamesAsync();
        var all = await cursor.ToListAsync();
        foreach (var n in all)
        {
            if (n.StartsWith("AuditLogs", StringComparison.Ordinal))
                names.Add(n);
        }
        names.Sort(StringComparer.Ordinal);
        return names;
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
    public IMongoCollection<Session> Sessions => _sessions;
    public IMongoCollection<AuditChainHead> AuditChainHeads => _auditChainHeads;
}
