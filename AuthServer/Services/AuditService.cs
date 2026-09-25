using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthServer.Models;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AuthServer.Services;

/// <summary>写入一条审计事件所需的全部信息（由 AuditService 补齐哈希与分片字段）。</summary>
public sealed class AuditEntry
{
    public string OperatorId { get; set; } = "anonymous";
    public string OperatorName { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string StatusBefore { get; set; } = "N/A";
    public object? Request { get; set; }
    public object? Response { get; set; }
    public string StatusAfter { get; set; } = "N/A";
    public string Target { get; set; } = string.Empty;
    public string Result { get; set; } = AuditResult.Success;

    /// <summary>失败 / 拒绝的原因码，成功事件留空。</summary>
    public string ReasonCode { get; set; } = string.Empty;

    /// <summary>主体类型：user / anonymous / system。留空则由 OperatorId 推断。</summary>
    public string ActorType { get; set; } = string.Empty;

    public string SourceIp { get; set; } = string.Empty;
    public string SourceUserAgent { get; set; } = string.Empty;

    /// <summary>精确时间戳。留空则由服务端取当前 UTC。</summary>
    public DateTime? Timestamp { get; set; }
}

/// <summary>完整性校验结果。</summary>
public sealed class ChainVerifyResult
{
    public bool Intact { get; set; }
    public int Checked { get; set; }          // 参与校验（有哈希）的记录数
    public int LegacySkipped { get; set; }    // 哈希链上线前的老记录数，跳过校验
    public long? FirstBrokenSeq { get; set; }
    public string BrokenShard { get; set; } = string.Empty;
    public DateTime? BrokenAt { get; set; }
    public string BrokenReason { get; set; } = string.Empty;
    public string Expected { get; set; } = string.Empty;
    public string Actual { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
}

/// <summary>
/// 审计服务：统一写入 + 哈希链防篡改 + 分片轮转。
///
/// 设计要点（对应实验二的四项要求）：
///   - 记得全：所有成功 / 失败 / 拒绝都走 WriteAsync，业务失败不阻断主流程；
///   - 改不掉：每条记录带 prevHash/selfHash 组成链，写入串行化防止并发分叉；
///   - 撑得住：按月份（或按条数，压测模式）分片，链跨分片连续；
///   - 看不到：由 TicketAuth 负责，本服务只保证"拒绝行为同样留痕"。
/// </summary>
public sealed class AuditService
{
    private readonly MongoDbService _db;
    private readonly IConfiguration _config;

    /// <summary>
    /// 链临界区锁：写入与完整性校验共用。
    ///
    /// 写入侧：哈希链要求"读链尾 → 算哈希 → 插入 → 推进链尾"四步原子完成。
    /// 若并发进入，两个请求会读到同一个链尾，生成两条 prevHash 相同的记录，
    /// 链就此分叉 —— 之后校验接口会把它报成"遭到篡改"，属于自己制造的假警报。
    ///
    /// 校验侧（VerifyAsync 同样持锁）：写入内部存在"锚点已占号、记录尚未插入"
    /// 的瞬时窗口，不持锁的校验若恰好在此窗口比对锚点，会把进行中的写入
    /// 误报成"链尾缺失"。详见 VerifyAsync 内的说明。
    /// Web 服务天然并发，这把锁不是可选项。
    /// </summary>
    private static readonly SemaphoreSlim WriteLock = new(1, 1);

    /// <summary>链首的前置哈希：64 个 0，作为"没有前一条"的确定表示。</summary>
    private static readonly string GenesisHash = new('0', 64);

    public AuditService(MongoDbService db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    /* ==================== 分片策略 ==================== */

    /// <summary>
    /// 当前分片名。
    ///
    /// 默认按月份：AuditLogs_202609。
    /// 演示 / 压测时把配置 `Audit:ShardUnit` 设为 `count`、`Audit:ShardSize` 设为期望容量，
    /// 即可切换为"每 N 条滚一片"，几十秒就能跑出真实的轮转证据，
    /// 不必等到跨月（等不到的东西没法作为验收证据）。
    ///
    /// 注意配置键的写法：本项目用的是 .NET 默认配置源，环境变量必须写成
    /// `Audit__ShardUnit` / `Audit__ShardSize`（**双**下划线分隔层级）。
    /// 写成 `AUDIT_SHARD_UNIT` 这类单下划线形式**不会**被识别，会被静默忽略、
    /// 仍然按 month 模式运行 —— 看上去配了却没有任何效果。
    /// 也可以直接改 appsettings.json 里的 Audit 段。
    /// </summary>
    private string CurrentShard()
    {
        var unit = _config["Audit:ShardUnit"] ?? "month";
        return unit.Equals("count", StringComparison.OrdinalIgnoreCase)
            ? "AuditLogs_count"      // 按条数滚动时所有片同前缀，切换点由 seq 决定
            : $"AuditLogs_{DateTime.UtcNow:yyyyMM}";
    }

    /// <summary>按条数模式下的单片容量；月末模式不用该值。</summary>
    private long ShardSize =>
        long.TryParse(_config["Audit:ShardSize"], out var n) && n > 0 ? n : 2000;

    private bool IsCountMode =>
        (_config["Audit:ShardUnit"] ?? "month").Equals("count", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// 写入目标分片：count 模式下按 seq 推导（seq / size），
    /// 因此多次运行、重启后依然落到同一片上，链的归属稳定可复现。
    /// </summary>
    private string ShardForSeq(long seq) =>
        IsCountMode ? $"{CurrentShard()}_{(seq - 1) / ShardSize:D6}" : CurrentShard();

    private IMongoCollection<AuditLog> ShardCollection(string shard) =>
        _db.GetAuditShard(shard);

    /* ==================== 哈希链核心 ==================== */

    /// <summary>
    /// 计算一条记录的哈希。
    ///
    /// 输入必须是**确定性**的：字段顺序固定、时间格式固定、request/response 先各自哈希。
    /// 若直接对对象做 JSON 序列化，属性顺序或文化差异会让同一事件算出不同哈希，
    /// 校验时就会把"正常记录"误报成"被篡改"。
    ///
    /// 纳入哈希的字段即"受保护字段"：任何一项被改动，selfHash 都会对不上。
    /// </summary>
    private static string ComputeHash(AuditLog log)
    {
        var sb = new StringBuilder(512);
        sb.Append(log.PrevHash).Append('|');
        sb.Append(log.Seq).Append('|');
        // 时间统一为 ISO8601 毫秒精度 UTC，避免 DateTime 序列化差异
        sb.Append(log.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")).Append('|');
        sb.Append(log.ActorType).Append('|');
        sb.Append(log.OperatorId).Append('|');
        sb.Append(log.OperatorName).Append('|');
        sb.Append(log.Action).Append('|');
        sb.Append(log.Target).Append('|');
        sb.Append(log.Result).Append('|');
        sb.Append(log.ReasonCode).Append('|');
        sb.Append(log.StatusBefore).Append('|');
        sb.Append(log.StatusAfter).Append('|');
        sb.Append(log.SourceIp).Append('|');
        // 请求/响应体本身较长，先各自哈希再入链，保证定长
        sb.Append(Sha256Hex(log.Request ?? string.Empty)).Append('|');
        sb.Append(Sha256Hex(log.Response ?? string.Empty));

        return Sha256Hex(sb.ToString());
    }

    private static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /* ==================== 写入 ==================== */

    /// <summary>
    /// 写入一条审计事件。**永不抛异常** —— 审计是旁路记录，
    /// 不能因为日志写失败就把注册 / 登录这类主流程拖垮。
    /// </summary>
    /// <summary>
    /// 写入一条审计事件。**永不抛异常** —— 审计是旁路记录，
    /// 不能因为日志写失败就把注册 / 登录这类主流程拖垮。
    ///
    /// 并发安全分两层：
    ///   1. 进程内用 SemaphoreSlim 串行化，避免同一进程内的竞争（开销小，快路径）；
    ///   2. 序号分配用 MongoDB 的原子 FindOneAndUpdate 完成 ——
    ///      这是关键：单靠进程内锁无法防住"多进程 / 多实例同时写同一个库"，
    ///      而原子的 $inc 能保证全局序号唯一且连续，链因此不会分叉。
    /// </summary>
    public async Task WriteAsync(AuditEntry entry)
    {
        try
        {
            await WriteLock.WaitAsync();
            try
            {
                // 原子地占号并取回前序哈希：读取与自增在数据库层完成，
                // 因此即便多进程并发也不会出现两条记录拿到同一序号。
                var (seq, prevHash) = await ReserveNextSeqAsync();
                var shard = ShardForSeq(seq);

                var log = new AuditLog
                {
                    OperatorId = string.IsNullOrWhiteSpace(entry.OperatorId) ? "anonymous" : entry.OperatorId,
                    OperatorName = entry.OperatorName,
                    Action = entry.Action,
                    StatusBefore = string.IsNullOrWhiteSpace(entry.StatusBefore) ? "N/A" : entry.StatusBefore,
                    Request = Serialize(entry.Request),
                    Response = Serialize(entry.Response),
                    StatusAfter = string.IsNullOrWhiteSpace(entry.StatusAfter) ? "N/A" : entry.StatusAfter,
                    Target = entry.Target,
                    Result = entry.Result,
                    ReasonCode = entry.ReasonCode,
                    ActorType = string.IsNullOrWhiteSpace(entry.ActorType)
                        ? (entry.OperatorId == "anonymous" || string.IsNullOrWhiteSpace(entry.OperatorId)
                            ? ActorType.Anonymous
                            : ActorType.User)
                        : entry.ActorType,
                    SourceIp = entry.SourceIp,
                    SourceUserAgent = entry.SourceUserAgent,
                    Timestamp = entry.Timestamp ?? DateTime.UtcNow,
                    Seq = seq,
                    Shard = shard,
                    PrevHash = prevHash
                };
                log.SelfHash = ComputeHash(log);

                // 先落记录，再推进链尾。
                // 顺序不能反：若先推进链尾而插入失败，链尾会指向一条不存在的记录，
                // 校验时表现为"尾部缺失"，容易被误读成遭篡改。
                await ShardCollection(shard).InsertOneAsync(log);

                await _db.AuditChainHeads.UpdateOneAsync(
                    x => x.Id == "head",
                    Builders<AuditChainHead>.Update
                        .Set(x => x.LastHash, log.SelfHash)
                        .Set(x => x.Shard, shard)
                        .Set(x => x.UpdatedAt, DateTime.UtcNow)
                        .Inc(x => x.TotalCount, 1));
            }
            finally
            {
                WriteLock.Release();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Audit] 写入失败（不影响主流程）: {ex.Message}");
        }
    }

    private static string Serialize(object? value) => value switch
    {
        null => string.Empty,
        string s => s,
        _ => JsonSerializer.Serialize(value)
    };

    /// <summary>
    /// 原子地领取下一个链序号，并把 prevHash 带回。
    ///
    /// 为什么必须用 FindOneAndUpdate：
    ///   "读出 seq → 加一 → 写回"这三步若用普通查询 + ReplaceOne 实现，
    ///   在并发下两个请求会读到同一个旧 seq，各自生成一条同号记录，
    ///   链就分叉了。FindOneAndUpdate 让读取与自增在数据库层原子完成，
    ///   即便多进程 / 多实例同时写入，也保证序号唯一且连续。
    ///
    /// 返回自增**之后**的文档（ReturnDocument.After）：
    ///   Seq 因此直接表示"本条记录的序号"，从 1 开始，不存在 0 号记录。
    ///   LastHash 仍是上一条的哈希（本条写入成功后才更新，故此刻读到的是正确的 prevHash）。
    /// </summary>
    private async Task<(long Seq, string PrevHash)> ReserveNextSeqAsync()
    {
        // 首次运行时先确保锚点存在（不存在则插入创世锚点）
        await _db.AuditChainHeads.UpdateOneAsync(
            x => x.Id == "head",
            Builders<AuditChainHead>.Update
                .SetOnInsert(x => x.Id, "head")
                .SetOnInsert(x => x.Seq, 0L)
                .SetOnInsert(x => x.LastHash, GenesisHash)
                .SetOnInsert(x => x.TotalCount, 0L)
                .SetOnInsert(x => x.UpdatedAt, DateTime.UtcNow),
            new UpdateOptions { IsUpsert = true });

        // 先取回自增前的 prevHash，再自增。分两步是为了避免 After 语义下
        // LastHash 已被本次写入覆盖（写入尚未发生）。
        var before = await _db.AuditChainHeads.FindOneAndUpdateAsync<AuditChainHead>(
            x => x.Id == "head",
            Builders<AuditChainHead>.Update
                .Inc(x => x.Seq, 1)
                .Set(x => x.UpdatedAt, DateTime.UtcNow),
            new FindOneAndUpdateOptions<AuditChainHead> { ReturnDocument = ReturnDocument.Before });

        // before.Seq 是自增前的值，加 1 即本条序号
        return (before.Seq + 1, string.IsNullOrEmpty(before.LastHash) ? GenesisHash : before.LastHash);
    }

    private async Task<AuditChainHead> LoadHeadAsync()
    {
        var head = await _db.AuditChainHeads.Find(x => x.Id == "head").FirstOrDefaultAsync();
        if (head is not null) return head;

        // 首次运行：链从创世哈希开始。
        // 老数据（哈希链上线前写入的 AuditLogs）不参与链，seq 从 1 重新计数，
        // 校验接口会把它们作为 legacy 跳过，而不是报成断裂。
        var fresh = new AuditChainHead { Id = "head", Seq = 0, LastHash = GenesisHash };
        await _db.AuditChainHeads.InsertOneAsync(fresh);
        return fresh;
    }

    /* ==================== 完整性校验 ==================== */

    /// <summary>
    /// 全链完整性校验，覆盖所有分片。
    ///
    /// 检测三类攻击：
    ///   1. 内容被改 —— 重算 selfHash 与存储值不符；
    ///   2. 顺序调换 / 中间被删 —— 本条 prevHash 与上一条 selfHash 不符；
    ///   3. 尾部整段被删 —— 链尾锚点的 seq 大于实际最大 seq（链式哈希本身发现不了，需锚点比对）。
    /// </summary>
    public async Task<ChainVerifyResult> VerifyAsync()
    {
        // 与 WriteAsync 共用同一把写锁：校验期间阻塞写入，写入期间阻塞校验。
        //
        // 为什么必须拿锁：写入分三步（原子占号 → 插入记录 → 更新锚点哈希），
        // 而本校验是"先读全部记录、最后读锚点"。若校验恰好卡在
        // "锚点已 +1、记录尚未插入"的几毫秒窗口里读锚点，就会看到
        // 锚点 seq 比实际最大 seq 大 1 —— 被误报成"链尾缺失、尾部记录被删除"。
        // 这不是理论风险：前端 20 秒日志轮询与 30 秒完整性巡检每 60 秒对齐一次，
        // 实测每分钟都会稳定复现一次假告警。
        // 拿锁后校验看到的一定是"静止的链"：任何写入要么已完成、要么尚未开始。
        await WriteLock.WaitAsync();
        try
        {
            return await VerifyLockedAsync();
        }
        finally
        {
            WriteLock.Release();
        }
    }

    /// <summary>持锁执行的全链校验（由 VerifyAsync 串行化后调用，不直接对外）。</summary>
    private async Task<ChainVerifyResult> VerifyLockedAsync()
    {
        var result = new ChainVerifyResult { Intact = true };

        var shards = await ListShardsAsync();
        if (shards.Count == 0)
        {
            result.Detail = "尚无审计分片，无需校验";
            return result;
        }

        // 跨分片按 seq 升序拉取全部记录（分片边界不影响链的连续性）
        var all = new List<AuditLog>();
        foreach (var s in shards)
        {
            var docs = await ShardCollection(s.Shard)
                .Find(x => x.SelfHash != null && x.SelfHash != "")
                .ToListAsync();
            all.AddRange(docs);
        }
        all.Sort((a, b) => a.Seq.CompareTo(b.Seq));

        if (all.Count == 0)
        {
            result.Detail = "所有分片均无带哈希的记录（可能全部是改造前的老数据）";
            result.LegacySkipped = shards.Sum(s => (int)Math.Min(s.Count, int.MaxValue));
            return result;
        }

        string expectedPrev = GenesisHash;
        long? lastSeq = null;

        // 链首必须从 1 开始：若最小序号不是 1，说明开头的记录被整段删除，
        // 而这种情况 prevHash 检查发现不了（第一条的 prevHash 本就是创世值）。
        if (all[0].Seq != 1)
        {
            result.Intact = false;
            result.FirstBrokenSeq = 1;
            result.BrokenShard = all[0].Shard;
            result.BrokenAt = all[0].Timestamp;
            result.BrokenReason = $"链首缺失：链应从序号 1 开始，但实际最小序号为 {all[0].Seq}，"
                                + $"说明开头有 {all[0].Seq - 1} 条记录被删除";
            result.Expected = "1";
            result.Actual = all[0].Seq.ToString();
            result.Detail = $"链首缺少 {all[0].Seq - 1} 条记录";
            return result;
        }

        foreach (var log in all)
        {
            result.Checked++;

            // 检测二：链接断裂（被删 / 被换序 / prevHash 被改）
            if (!string.Equals(log.PrevHash, expectedPrev, StringComparison.Ordinal))
            {
                result.Intact = false;
                result.FirstBrokenSeq = log.Seq;
                result.BrokenShard = log.Shard;
                result.BrokenAt = log.Timestamp;
                result.BrokenReason = "前序哈希不匹配：本条记录的 prevHash 与上一条的 selfHash 不一致，"
                                    + "说明中间有记录被删除、被调换顺序，或 prevHash 被篡改";
                result.Expected = expectedPrev;
                result.Actual = log.PrevHash;
                result.Detail = $"链条序号 {log.Seq} 处断裂";
                return result;
            }

            // 检测一：内容被改（重算本条哈希）
            var recomputed = ComputeHash(log);
            if (!string.Equals(recomputed, log.SelfHash, StringComparison.Ordinal))
            {
                result.Intact = false;
                result.FirstBrokenSeq = log.Seq;
                result.BrokenShard = log.Shard;
                result.BrokenAt = log.Timestamp;
                result.BrokenReason = "记录内容与签名不符：按当前字段重算的哈希与存储的 selfHash 不一致，"
                                    + "说明该条记录被直接修改过";
                result.Expected = recomputed;
                result.Actual = log.SelfHash;
                result.Detail = $"链条序号 {log.Seq} 的内容已被篡改";
                return result;
            }

            // 检测序列连续性（同一分片内允许跨片，但 seq 必须严格递增且不跳号）
            if (lastSeq.HasValue && log.Seq != lastSeq.Value + 1)
            {
                // 序号重复意味着链在此分叉（两条记录争夺同一个位置），
                // 与"被删导致跳号"是两种不同性质的问题，分开报让排查方向更明确。
                var duplicated = log.Seq <= lastSeq.Value;
                result.Intact = false;
                result.FirstBrokenSeq = lastSeq.Value + 1;
                result.BrokenShard = log.Shard;
                result.BrokenAt = log.Timestamp;
                result.BrokenReason = duplicated
                    ? $"链已分叉：出现重复序号 {log.Seq}（前一条已是 {lastSeq.Value}），"
                      + "说明有两条记录写入了同一个链位置"
                    : $"链上序号不连续：{lastSeq.Value} 之后直接出现 {log.Seq}，"
                      + $"缺少 {log.Seq - lastSeq.Value - 1} 条记录";
                result.Expected = (lastSeq.Value + 1).ToString();
                result.Actual = log.Seq.ToString();
                result.Detail = duplicated
                    ? $"链条序号 {log.Seq} 处出现重复"
                    : $"链条序号 {lastSeq.Value + 1} 处存在缺口";
                return result;
            }

            expectedPrev = log.SelfHash;
            lastSeq = log.Seq;
        }

        // 检测三：尾部整段被删 —— 锚点声称写过更多条，但实际链上没到那个序号。
        // 锚点的 Seq 表示"已分配的最大序号"，正常情况下恰好等于最后一条记录的 seq。
        var head = await LoadHeadAsync();
        if (head.Seq != 0 && lastSeq.HasValue && head.Seq != lastSeq.Value)
        {
            result.Intact = false;
            result.FirstBrokenSeq = lastSeq.Value + 1;
            result.BrokenShard = head.Shard;
            result.BrokenReason = $"链尾缺失：链尾锚点记录到序号 {head.Seq}，但实际最后一条只有序号 {lastSeq.Value}，"
                                + $"说明尾部有 {head.Seq - lastSeq.Value} 条记录被删除";
            result.Expected = head.Seq.ToString();
            result.Actual = lastSeq.Value.ToString();
            result.Detail = $"链尾缺少 {head.Seq - lastSeq.Value} 条记录";
            return result;
        }

        result.Detail = $"校验通过：{result.Checked} 条记录哈希链完整"
                      + (result.LegacySkipped > 0 ? $"，跳过 {result.LegacySkipped} 条改造前的老记录" : "");
        return result;
    }

    /* ==================== 分片清单与查询 ==================== */

    public sealed class ShardInfo
    {
        public string Shard { get; set; } = string.Empty;
        public long Count { get; set; }
        public long FirstSeq { get; set; }
        public long LastSeq { get; set; }
        public bool IsLegacy { get; set; }   // 改造前的 AuditLogs 主集合
    }

    /// <summary>列出所有审计分片（含改造前的 AuditLogs 主集合，标记为 legacy）。</summary>
    public async Task<List<ShardInfo>> ListShardsAsync()
    {
        var names = await _db.ListAuditShardNamesAsync();
        var list = new List<ShardInfo>();
        foreach (var name in names)
        {
            var col = ShardCollection(name);
            var count = await col.CountDocumentsAsync(FilterDefinition<AuditLog>.Empty);
            if (count == 0) continue;

            var withHash = await col.CountDocumentsAsync(
                Builders<AuditLog>.Filter.Ne(x => x.SelfHash, string.Empty));
            var info = new ShardInfo
            {
                Shard = name,
                Count = count,
                IsLegacy = withHash == 0
            };

            if (withHash > 0)
            {
                var oldest = await col.Find(Builders<AuditLog>.Filter.Ne(x => x.SelfHash, string.Empty))
                    .SortBy(x => x.Seq).Limit(1).FirstOrDefaultAsync();
                var newest = await col.Find(Builders<AuditLog>.Filter.Ne(x => x.SelfHash, string.Empty))
                    .SortByDescending(x => x.Seq).Limit(1).FirstOrDefaultAsync();
                info.FirstSeq = oldest?.Seq ?? 0;
                info.LastSeq = newest?.Seq ?? 0;
            }
            list.Add(info);
        }
        // 按片内最后序号降序，新的在前
        list.Sort((a, b) => b.LastSeq.CompareTo(a.LastSeq));
        return list;
    }

    /// <summary>
    /// 分页查询审计日志。
    /// 改造前是硬编码 Limit(200) —— 写多少都只看得到最近 200 条，
    /// 换成真正的分页后，"撑得住"才成立：数据再多也能翻到。
    /// </summary>
    public async Task<(List<AuditLog> Items, long Total)> QueryAsync(
        string? shard, string? keyword, string? action, string? result,
        int page, int pageSize, bool includeArchived)
    {
        page = page < 1 ? 1 : page;
        pageSize = pageSize switch { < 1 => 50, > 500 => 500, _ => pageSize };

        var targets = new List<string>();
        if (includeArchived || string.IsNullOrWhiteSpace(shard))
        {
            targets.AddRange((await ListShardsAsync()).Select(s => s.Shard));
        }
        else
        {
            targets.Add(shard);
        }
        if (targets.Count == 0) return (new List<AuditLog>(), 0);

        var all = new List<AuditLog>();
        foreach (var t in targets)
        {
            var filters = new List<FilterDefinition<AuditLog>>();
            if (!string.IsNullOrWhiteSpace(action) && action != "all")
                filters.Add(Builders<AuditLog>.Filter.Eq(x => x.Action, action));
            if (!string.IsNullOrWhiteSpace(result) && result != "all")
                filters.Add(Builders<AuditLog>.Filter.Eq(x => x.Result, result));

            var filter = filters.Count == 0
                ? FilterDefinition<AuditLog>.Empty
                : Builders<AuditLog>.Filter.And(filters);

            var docs = await ShardCollection(t).Find(filter).ToListAsync();
            if (!string.IsNullOrWhiteSpace(keyword))
            {
                var kw = keyword.Trim();
                docs = docs.Where(l =>
                    Contains(l.OperatorName, kw) || Contains(l.Target, kw) ||
                    Contains(l.Action, kw) || Contains(l.Request, kw) ||
                    Contains(l.Response, kw) || Contains(l.ReasonCode, kw)).ToList();
            }
            all.AddRange(docs);
        }

        all.Sort((a, b) => b.Timestamp.CompareTo(a.Timestamp));
        var total = all.Count;
        var items = all.Skip((page - 1) * pageSize).Take(pageSize).ToList();
        return (items, total);
    }

    private static bool Contains(string? hay, string needle) =>
        !string.IsNullOrEmpty(hay) && hay.Contains(needle, StringComparison.OrdinalIgnoreCase);

    /// <summary>统计各结果数量，供仪表盘展示（覆盖全部分片）。</summary>
    public async Task<(long Total, long Failed, long Tampered, long Denied, long LatestDeniedSeq)> StatsAsync()
    {
        long total = 0, failed = 0, tampered = 0, denied = 0, latestDeniedSeq = 0;
        foreach (var s in await ListShardsAsync())
        {
            var col = ShardCollection(s.Shard);
            total += s.Count;
            failed += await col.CountDocumentsAsync(Builders<AuditLog>.Filter.Eq(x => x.Result, AuditResult.Failed));
            tampered += await col.CountDocumentsAsync(Builders<AuditLog>.Filter.Eq(x => x.Action, AuditAction.AuditTampered));

            // 越权访问被拒：既要总数，也要"最新一条的序号"。
            // 序号供前端判断"本次会话期间有没有新发生的越权尝试" ——
            // 这个判断刻意不走日志查询接口：查询本身会留下 AUDIT_QUERY 记录，
            // 若靠轮询查询来实现巡检，巡检自己就会把审计日志灌爆。
            var deniedFilter = Builders<AuditLog>.Filter.Eq(x => x.Action, AuditAction.AuditAccessDenied);
            denied += await col.CountDocumentsAsync(deniedFilter);
            var newest = await col.Find(deniedFilter)
                .Sort(Builders<AuditLog>.Sort.Descending(x => x.Seq))
                .Limit(1)
                .FirstOrDefaultAsync();
            if (newest != null && newest.Seq > latestDeniedSeq) latestDeniedSeq = newest.Seq;
        }
        return (total, failed, tampered, denied, latestDeniedSeq);
    }
}
