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
    private readonly IMongoCollection<FaceTemplate> _faceTemplates;
    private readonly IMongoCollection<AuthServer.Models.FaceIdTemplate> _faceIdTemplates;
    private readonly IMongoCollection<OtpChain> _otpChains;
    private readonly PepperProvider _pepper;

    /// <summary>
    /// 一次性口令参数。种子管理员也要建链，而建链需要 N 与 PBKDF2 迭代次数 ——
    /// 这两项在 <see cref="OtpChainStore"/> 里，但那个类依赖本类构造出的集合句柄，
    /// 构造顺序上只能由本类自己算一次（不引入反向依赖）。
    /// </summary>
    private readonly AuthServer.Services.Otp.OtpOptions _otp;

    public MongoDbService(IConfiguration configuration, PepperProvider pepper,
        AuthServer.Services.Otp.OtpOptions otp)
    {
        _pepper = pepper;
        _otp = otp;

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
        _faceTemplates = _database.GetCollection<FaceTemplate>("FaceTemplates");
        _faceIdTemplates = _database.GetCollection<AuthServer.Models.FaceIdTemplate>("FaceIdTemplates");

        // 一次性口令（哈希链）状态：**独立集合**（理由见 OtpChain 的注释 ——
        // 挂进 Users 会被整篇 ReplaceOne 静默回滚 k，开出可重放窗口）。
        _otpChains = _database.GetCollection<OtpChain>(AuthServer.Services.Otp.OtpChainStore.CollectionName);

        EnsureIndexes();

        // 预置管理员账号（如果不存在），使用同步方法避免构造函数中 .Wait() 死锁
        SeedAdmin();

        // P8 迁移自检：把「还留着历史口令哈希、却没有链」的账号列出来。
        // 它们在新版本里**登不进来**（口令路径已删除），所以必须在启动日志里点名，
        // 而不是等用户报"口令明明对"。
        ReportUnchainedLegacyAccounts();

        // 沉睡账号治理的数据准备：从审计里回填 lastLoginAt。
        // 放在最后：它需要 Users 与 AuditLogs_* 都可用。
        BackfillLastLoginAt();
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

        try
        {
            // 人脸模板按 userId 查（登录验证、状态查询、删除都走这一个入口）。
            // 不建唯一索引：一个人**可以有多张**模板（见 FaceTemplateStore.AddAsync）。
            var faceKeys = Builders<FaceTemplate>.IndexKeys.Ascending(t => t.UserId);
            _faceTemplates.Indexes.CreateOne(new CreateIndexModel<FaceTemplate>(faceKeys));

            // 注销账号时按用户名清理（那条路径手里只有用户名，见 FaceTemplateStore.DeleteByUsernameAsync）
            var faceNameKeys = Builders<FaceTemplate>.IndexKeys.Ascending(t => t.Username);
            _faceTemplates.Indexes.CreateOne(new CreateIndexModel<FaceTemplate>(faceNameKeys));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Mongo] 人脸模板索引创建失败（人脸功能将不可用）: {ex.Message}");
        }

        try
        {
            // 纯人脸登录模板：与 2FA 的 FaceTemplates **分开一个集合**（理由见 FaceIdTemplate 注释）。
            // 查询模式与 2FA 相同：按 userId 取全部 / 计数，按 username 清理注销账号。
            // 同样不建唯一索引 —— 一人最多 MaxTemplates 张（默认 3）。
            var faceIdKeys = Builders<AuthServer.Models.FaceIdTemplate>.IndexKeys
                .Ascending(t => t.UserId);
            _faceIdTemplates.Indexes.CreateOne(
                new CreateIndexModel<AuthServer.Models.FaceIdTemplate>(faceIdKeys));

            var faceIdNameKeys = Builders<AuthServer.Models.FaceIdTemplate>.IndexKeys
                .Ascending(t => t.Username);
            _faceIdTemplates.Indexes.CreateOne(
                new CreateIndexModel<AuthServer.Models.FaceIdTemplate>(faceIdNameKeys));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Mongo] 纯人脸登录模板索引创建失败（该功能将不可用）: {ex.Message}");
        }

        try
        {
            // 一人一条链：`userId` **唯一**。
            // 这不只是查询优化，它是"并发首次登录同时建链"的唯一拦截手段 ——
            // 没有它，两个请求会各插一条，此后每次登录随机命中其中一条，
            // 表现为"时好时坏地登不上"，且两条链各自推进、互不知情。
            var otpUserKeys = Builders<OtpChain>.IndexKeys.Ascending(c => c.UserId);
            _otpChains.Indexes.CreateOne(new CreateIndexModel<OtpChain>(
                otpUserKeys, new CreateIndexOptions { Unique = true, Name = "uniq_otp_user" }));

            // 注销路径手里只有用户名（见 IUserDataPurger），这条索引让清理不必全表扫。
            var otpNameKeys = Builders<OtpChain>.IndexKeys.Ascending(c => c.Username);
            _otpChains.Indexes.CreateOne(new CreateIndexModel<OtpChain>(
                otpNameKeys, new CreateIndexOptions { Name = "idx_otp_username" }));
        }
        catch (Exception ex)
        {
            // 索引建不起来不影响启动：业务侧仍会按 userId 等值查询（只是慢），
            // 但**并发建链的保护会失效**，所以必须把它喊出来而不是静默降级。
            Console.WriteLine($"[Mongo] OTP 链索引创建失败（并发建链将失去唯一性保护）: {ex.Message}");
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

    /**
     * 空库时播种 `admin / Admin123`。
     *
     * P8 起种子账号也**只建链、不写任何口令派生哈希** —— 这里拿到的 "Admin123"
     * 是明文常量，正好直接折叠成一条链。于是"全新部署"与"存量迁移完"是同一种数据形态：
     * 库里除了链之外没有第二个能验口令的东西。
     *
     * ⚠️ 两步（插账号 → 建链）之间失败会导致"有账号没链"。这里刻意**不删账号重试**：
     *    空库播种发生在启动路径上，把账号删掉再抛异常会让下次启动重复播种，
     *    而留下一个无链 admin 至少是可诊断的（登录会得到统一的「用户名或口令错误」，
     *    运维用 `--rechain` 一次即可修好）。真正不可接受的是"启动成功但谁都进不去"，
     *    所以下面的 catch 会把结论写进控制台。
     */
    private void SeedAdmin()
    {
        var admin = _users.Find(u => u.Username == "admin").FirstOrDefault();
        if (admin == null)
        {
            var seeded = new User
            {
                Id = ObjectId.GenerateNewId().ToString(),
                Username = "admin",
                Status = UserStatus.Enabled,
                Role = UserRole.Admin,
                CreatedAt = DateTime.UtcNow
            };
            _users.InsertOne(seeded);

            try
            {
                var seed = AuthServer.Services.Otp.OtpChainStore.NewSeed();
                var state = AuthServer.Services.Otp.OtpVerifier.Create(
                    "Admin123", seed, _otp.KdfIterations, _otp.Length);

                _otpChains.InsertOne(new OtpChain
                {
                    UserId = seeded.Id,
                    Username = seeded.Username,
                    R = seed,
                    Algorithm = AuthServer.Services.Otp.OtpVerifier.ChainAlgorithm,
                    Kdf = AuthServer.Services.Otp.OtpVerifier.KdfName,
                    KdfIterations = _otp.KdfIterations,
                    Length = _otp.Length,
                    V = state.V,
                    K = state.K,
                    Generation = 1,
                    CreatedAt = DateTime.UtcNow
                });

                Console.WriteLine("[Mongo] 已播种种子管理员 admin（口令 Admin123）并建好一次性口令链");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Mongo] ⚠️ 种子管理员已插入，但建链失败：{ex.Message}。" +
                                  "该账号当前无法登录，请在服务起来后用 `authserver.exe --rechain --username admin --password Admin123` 修复");
            }
        }

        MigrateLegacyRoles();
    }

    /**
     * 列出「有历史口令哈希、但没有链」的账号。
     *
     * 这类账号是 P8 唯一的**硬失败面**：登录只收链值，而它没有链；而链又只能由明文口令派生，
     * 服务端从哈希反推不出来。所以它必须由运维执行一次：
     *   authserver.exe --rechain --username <账号>
     *
     * 为什么打在启动日志里而不是只在文档里写：迁移是**一次性**动作，做完这批账号就永远没有了；
     * 而"文档写了但没人读"是这类过渡期最常见的失败方式 —— 上线当天发现登不进去，
     * 却不知道是因为库里还有几个账号没迁。日志是排障第一现场，所以点名到这里。
     *
     * 只统计、不阻断启动：阻断会让"库里有一个测试账号没迁"变成整站起不来，
     * 而真正在用的账号可能个个都好好的。
     */
    private void ReportUnchainedLegacyAccounts()
    {
        try
        {
            var legacy = _users
                .Find(Builders<User>.Filter.Exists("passwordHash", true))
                .ToList();

            if (legacy.Count == 0) return;

            var chained = _otpChains
                .Find(Builders<OtpChain>.Filter.Empty)
                .Project(c => c.UserId)
                .ToList()
                .ToHashSet(StringComparer.Ordinal);

            var pending = legacy.Where(u => !chained.Contains(u.Id)).Select(u => u.Username).ToList();
            if (pending.Count == 0) return;

            Console.WriteLine($"[Otp] ⚠️ 有 {pending.Count} 个账号仍停留在「只有口令哈希、没有链」的状态：" +
                              $"{string.Join("、", pending)}");
            Console.WriteLine("[Otp]    本版本已移除口令登录，这些账号**当前无法登录**。迁移方式（逐条执行）：");
            foreach (var name in pending)
                Console.WriteLine($"[Otp]      authserver.exe --rechain --username {name}");
        }
        catch (Exception ex)
        {
            // 自检失败不该拦住启动：它是诊断信息，不是安全闸门。
            Console.WriteLine($"[Otp] 迁移自检未完成（不影响启动）：{ex.Message}");
        }
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

    /// <summary>
    /// 沉睡账号治理的一次性数据回填：给缺少 <c>lastLoginAt</c> 的账号，
    /// 从审计日志里找出它**最后一次成功登录**的时间补上。
    ///
    /// 为什么要回填而不是"从现在开始攒"：登录审计（<c>LOGIN_SUCCESS</c>）早已在记录，
    /// 存量数据完全够用。若不回填，所有老账号的基准时间都退化成创建时间，
    /// 于是"注册很久但天天在用"的账号会被误判成沉睡 —— 这正是治理功能
    /// 最不该犯的错。回填之后，基准时间才是真实可信的。
    ///
    /// 两条硬性边界：
    ///   ① **只读**审计分片。回填是"从审计里算出一个值"，不是"改审计"——
    ///      任何对 AuditLogs_* 的写入都会破坏哈希链。
    ///   ② **只写** Users 的新字段，用 Unset 时保留其余字段不动。
    ///
    /// 幂等：只处理 <c>lastLoginAt</c> 缺失的账号，回填后字段存在，下次启动命中 0 条。
    /// </summary>
    private void BackfillLastLoginAt()
    {
        try
        {
            var missing = _users.Find(Builders<User>.Filter
                .Exists("lastLoginAt", false)).ToList();
            if (missing.Count == 0) return;

            // 一次取回全部审计分片名（含改造前的 AuditLogs 主集合）。
            var shardNames = new List<string>();
            using (var cursor = _database.ListCollectionNames())
            {
                foreach (var n in cursor.ToList())
                {
                    if (n.StartsWith("AuditLogs", StringComparison.Ordinal)) shardNames.Add(n);
                }
            }
            if (shardNames.Count == 0) return;

            var filled = 0;
            foreach (var user in missing)
            {
                // 在每个分片里各查一把"该用户最近一次成功登录"，再跨分片取最大。
                // 排序放服务端（Sort + Limit 1），避免把某人的全部登录记录拉回内存。
                DateTime? latest = null;
                foreach (var shard in shardNames)
                {
                    var col = _database.GetCollection<AuditLog>(shard);
                    var filter = Builders<AuditLog>.Filter.And(
                        Builders<AuditLog>.Filter.Eq(a => a.OperatorName, user.Username),
                        Builders<AuditLog>.Filter.Eq(a => a.Action, AuditAction.LoginSuccess));
                    var hit = col.Find(filter)
                        .Sort(Builders<AuditLog>.Sort.Descending(a => a.Timestamp))
                        .Limit(1)
                        .FirstOrDefault();
                    if (hit != null && (latest is null || hit.Timestamp > latest.Value))
                        latest = hit.Timestamp;
                }

                if (latest is null) continue; // 从未登录过：保持 null，判定时回退 createdAt

                // 只写这一个字段，绝不 ReplaceOne（那会带上反序列化出的整套字段，风险更大）。
                _users.UpdateOne(Builders<User>.Filter.Eq(u => u.Id, user.Id),
                    Builders<User>.Update.Set(u => u.LastLoginAt, latest.Value));
                filled++;
            }

            if (filled > 0)
                Console.WriteLine($"[Mongo] 沉睡治理回填：{filled} 个账号的 lastLoginAt 已从审计补齐");
        }
        catch (Exception ex)
        {
            // 回填失败不应阻断启动：功能退化为"基准时间取 createdAt"，
            // 判定会偏保守（可能多报几个沉睡），不会导致任何不可逆后果。
            Console.WriteLine($"[Mongo] lastLoginAt 回填失败（判定将回退到 createdAt）: {ex.Message}");
        }
    }

    public IMongoCollection<User> Users => _users;
    public IMongoCollection<AuditLog> AuditLogs => _auditLogs;
    public IMongoCollection<EmailCode> EmailCodes => _emailCodes;
    public IMongoCollection<Session> Sessions => _sessions;
    public IMongoCollection<AuditChainHead> AuditChainHeads => _auditChainHeads;

    /// <summary>人脸特征模板。**不参与审计哈希链**，是独立集合。</summary>
    public IMongoCollection<FaceTemplate> FaceTemplates => _faceTemplates;

    /// <summary>纯人脸登录（FaceId）的模板集合 —— 与 <see cref="FaceTemplates"/>（2FA）刻意分开。</summary>
    public IMongoCollection<AuthServer.Models.FaceIdTemplate> FaceIdTemplates => _faceIdTemplates;

    /// <summary>
    /// 一次性口令（哈希链）的链状态。**独立集合**，只由 <c>OtpChainStore</c> 推进；
    /// 本属性之所以公开，是因为那个 Store 拿的是集合句柄而不是整个 <see cref="MongoDbService"/>。
    /// </summary>
    public IMongoCollection<OtpChain> OtpChains => _otpChains;
}
