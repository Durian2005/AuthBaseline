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
    private readonly PepperProvider _pepper;

    public MongoDbService(IConfiguration configuration, PepperProvider pepper)
    {
        _pepper = pepper;

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
            // 顺序不能反：先升级老文档，再建唯一索引。
            UpgradeLegacySessionTickets();

            // 老索引 uniq_ticket 建在**已被移除的明文 ticket 字段**上，必须删掉：
            // 字段缺失时 MongoDB 一律按 null 参与唯一约束，留着它会让第二条会话就插不进去
            // （症状是"第一次登录正常、第二次登录起 500"，且报错指向 dup key null，很难联想到这里）。
            var hasLegacyIndex = false;
            using (var cursor = _sessions.Indexes.List())
            {
                foreach (var idx in cursor.ToList())
                {
                    if (idx.GetValue("name", "").AsString == "uniq_ticket") { hasLegacyIndex = true; break; }
                }
            }
            if (hasLegacyIndex)
            {
                _sessions.Indexes.DropOne("uniq_ticket");
                Console.WriteLine("[Mongo] 已删除建在明文 ticket 上的老索引 uniq_ticket");
            }

            // 票据哈希唯一，且保证按哈希等值查询走索引（每个请求都要校验一次）
            var ticketKeys = Builders<Session>.IndexKeys.Ascending(s => s.TicketHash);
            _sessions.Indexes.CreateOne(new CreateIndexModel<Session>(
                ticketKeys, new CreateIndexOptions { Unique = true, Name = "uniq_ticket_hash" }));

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
    /// 一次性升级：早期版本把票据**明文**存在 <c>ticket</c> 字段里（哈希化改造前的形态）。
    ///
    /// 老文档里既然能读到明文，就可以就地折算成哈希后再删掉明文字段 ——
    /// **已登录的会话不会因此失效**，不需要把所有人踢下线重登。
    /// 升级后集合中不再存在 <c>ticket</c> 字段，明文只在客户端手里。
    /// </summary>
    private void UpgradeLegacySessionTickets()
    {
        var raw = _database.GetCollection<BsonDocument>("Sessions");
        var legacy = raw.Find(new BsonDocument("ticket", new BsonDocument("$exists", true))).ToList();
        if (legacy.Count == 0) return;

        foreach (var doc in legacy)
        {
            var plain = doc.TryGetValue("ticket", out var v) && v.IsString ? v.AsString : null;
            var update = Builders<BsonDocument>.Update.Unset("ticket");
            if (!string.IsNullOrEmpty(plain))
                update = update.Set("ticketHash", TicketHasher.Hash(plain));
            raw.UpdateOne(new BsonDocument("_id", doc["_id"]), update);
        }

        Console.WriteLine($"[Mongo] 会话票据「明文 → 哈希」升级完成：{legacy.Count} 条");
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
            // 种子口令同样必须走 PasswordHasher —— 直接调 BCrypt 会写出一条
            // "无 pepper" 的哈希，那条记录在 pepper 上线后依然能验过（走旧格式分支），
            // 于是这台机器上永远有一条不受 pepper 保护的账号，是纯粹的漏洞。
            var hash = PasswordHasher.Hash("Admin123", _pepper.Pepper);
            _users.InsertOne(new User
            {
                Username = "admin",
                PasswordHash = hash,
                Status = UserStatus.Enabled,
                Role = UserRole.Admin,
                CreatedAt = DateTime.UtcNow
            });
        }

        MigrateLegacyRoles();
    }

    /// <summary>
    /// 角色分离改造的一次性数据回填。
    ///
    /// 改造前的账号只有 `isAdmin` 布尔位、没有 `role` 字段。驱动反序列化时
    /// 缺失的枚举字段会取默认值 0（User），因此**无法在代码里区分**
    /// "角色真的是 User" 和 "字段压根不存在" —— 必须用 BSON 层面的
    /// `Exists(role, false)` 去判断。
    ///
    /// 映射规则：老管理员 → Admin，其余老账号 → User。
    /// 这是幂等的：回填后所有文档都有了 role 字段，下次启动两个 UpdateMany 命中 0 条。
    /// </summary>
    private void MigrateLegacyRoles()
    {
        try
        {
            var noRoleField = Builders<User>.Filter.Exists("role", false);

            // 先迁移老管理员（isAdmin=true），再兜底其余账号为普通用户。
            // 顺序不能反：后一条会把所有"无 role 字段"的文档都设成 User。
            var admins = _users.UpdateMany(
                noRoleField & Builders<User>.Filter.Eq("isAdmin", true),
                Builders<User>.Update.Set(u => u.Role, UserRole.Admin));

            var others = _users.UpdateMany(
                noRoleField,
                Builders<User>.Update.Set(u => u.Role, UserRole.User));

            if (admins.ModifiedCount > 0 || others.ModifiedCount > 0)
            {
                Console.WriteLine(
                    $"[Mongo] 角色回填完成：老管理员 {admins.ModifiedCount} 个 → Admin，"
                    + $"普通账号 {others.ModifiedCount} 个 → User");
            }
        }
        catch (Exception ex)
        {
            // 回填失败不应阻断启动，但必须显式暴露 —— 否则会出现
            // "老管理员登录后没了管理权限"这种难以定位的现象。
            Console.WriteLine($"[Mongo] 角色回填失败（可能导致老管理员权限丢失）: {ex.Message}");
        }
    }

    public IMongoCollection<User> Users => _users;
    public IMongoCollection<AuditLog> AuditLogs => _auditLogs;
    public IMongoCollection<EmailCode> EmailCodes => _emailCodes;
    public IMongoCollection<Session> Sessions => _sessions;
    public IMongoCollection<AuditChainHead> AuditChainHeads => _auditChainHeads;
}
