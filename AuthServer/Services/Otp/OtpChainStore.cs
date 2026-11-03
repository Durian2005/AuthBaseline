using System.Security.Cryptography;
using AuthServer.Models;
using MongoDB.Driver;

namespace AuthServer.Services.Otp;

/// <summary>
/// 一次链值提交在**存储层**的结局。
///
/// 比 <see cref="OtpVerifyStatus"/> 多出三种，因为它们描述的是存储/编排层的事，不是数学结论：
///   · <see cref="NotEnrolled"/> —— 这个账号还没有链（迁移期的存量账号走这条分支）；
///   · <see cref="Conflict"/> —— 读到的状态在写入前被别人改掉了（并发 CAS 失败）。
///     它与 <see cref="Mismatch"/> 必须分开：**前者可以重取 k 重试一次，后者不能重试**。
///     混成一个值，就只能靠"再试一次也许能过"来兜，而那会把普通的口令错也变成两次尝试。
/// </summary>
public enum OtpConsumeOutcome
{
    /// <summary>核销成功，链已推进一格。</summary>
    Consumed,

    /// <summary>提交值不是这一格（或格式不像）。</summary>
    Mismatch,

    /// <summary>配额已尽，需重建。</summary>
    Exhausted,

    /// <summary>链记录损坏（服务端数据问题，不计入用户失败次数）。</summary>
    Malformed,

    /// <summary>并发冲突：本次读到的状态已被别的请求推进。</summary>
    Conflict,

    /// <summary>该账号没有链。</summary>
    NotEnrolled
}

/// <summary>
/// 核销时**读到的那一代链**的只读快照。
///
/// 续期需要它，而且必须是"读的时候那一代"而不是"现在再读一次"：
/// 两步写之间可能夹着另一次续期，若续期时重新去库里读 R，
/// 就会把"别人刚换好的新链"当成自己的起点再换一次 —— 代数越滚越多，
/// 而每次覆盖都让上一次的新链作废（用户手里刚算好的格立刻失效）。
/// </summary>
public readonly record struct OtpChainSnapshot(string R, int KdfIterations, int Length, int Generation);

/// <summary>
/// 核销结果。<see cref="NewState"/> 仅在核销成功时非空；
/// <see cref="Snapshot"/> 是核销时读到的那一代链（续期要用，见上）。
/// </summary>
public readonly record struct OtpConsumeResult(
    OtpConsumeOutcome Outcome,
    OtpChainState? NewState,
    bool NeedsRenewal,
    bool AtAlertLine,
    OtpChainSnapshot? Snapshot)
{
    /// <summary>是否核销成功。</summary>
    public bool Consumed => Outcome == OtpConsumeOutcome.Consumed;
}

/// <summary>
/// `OtpChains` 的**唯一**读写入口：建链、CAS 核销、条件续期替换、注销清理。
///
/// ── 三条边界 ──────────────────────────────────────────────────
/// ① 数学判定不在这里。<see cref="OtpVerifier"/> 说"这个值对不对"，本类只说"怎么原子地把它写下去"。
///    混在一起会让"为什么登录失败"永远分不清是算错了还是写输了。
/// ② 不写审计、不签票、不计次。那些是控制器/编排层的事（审计失败绝不能让登录失败）。
/// ③ 只碰 `OtpChains`。构造参数是**一个集合句柄**而不是整个 `MongoDbService` ——
///    拿整个库对象就等于有能力顺手改 `Users` 或审计分片，而链推进最怕的正是别处的覆盖（§5.2）。
///
/// ── 为什么核销必须是一条带条件的更新 ──────────────────────────
/// 两个客户端同时提交同一格时，"读 → 判 → 写"三步会双写成功，链被推进两格，
/// 其中一格被白吃（用户少一次配额，且两边的票据都签发）。所以写入条件必须
/// **同时**钉住 <c>userId + v + k</c>：只有读到的那一份状态还在，才允许写。
/// 抢输的一方拿到 <see cref="OtpConsumeOutcome.Conflict"/>，由上层重取 k 重试一次 ——
/// 注意重试不是拿同一个码再交一次（那必然失败），而是用新的 k 重算。
/// </summary>
public sealed class OtpChainStore : IUserDataPurger
{
    /// <summary>集合名。注销清理与探针都按这个名字找。</summary>
    public const string CollectionName = "OtpChains";

    private readonly IMongoCollection<OtpChain> _chains;
    private readonly OtpOptions _opt;

    public OtpChainStore(IMongoCollection<OtpChain> chains, OtpOptions opt)
    {
        _chains = chains;
        _opt = opt;
    }

    /// <inheritdoc />
    public string Name => CollectionName;

    /// <summary>取整条记录（含 r / generation 等只读展示用字段）。没有链返回 null。</summary>
    public async Task<OtpChain?> FindAsync(string userId) =>
        await _chains.Find(c => c.UserId == userId).FirstOrDefaultAsync();

    /// <summary>取判定需要的三要素。没有链返回 null。</summary>
    public async Task<OtpChainState?> GetStateAsync(string userId)
    {
        var chain = await FindAsync(userId);
        return chain is null ? null : new OtpChainState(chain.V, chain.K, chain.Length);
    }

    /// <summary>
    /// 按用户名取链 —— 只给"签发挑战"用。
    ///
    /// 为什么挑战端点不先查 `Users` 再按 userId 找链：那要多一次往返，且
    /// **多知道一点东西**（账号是否存在、状态如何）。挑战只需要"有没有可用的链参数"，
    /// 而链记录自己就冗余了用户名。少查一张表 = 少一处可能把存在性泄露到响应里的地方。
    /// </summary>
    public async Task<OtpChain?> FindByUsernameAsync(string username) =>
        await _chains.Find(c => c.Username == username).FirstOrDefaultAsync();

    /// <summary>该账号是否已建链（迁移分流就靠这一个判断）。</summary>
    public async Task<bool> ExistsAsync(string userId) =>
        await _chains.CountDocumentsAsync(c => c.UserId == userId) > 0;

    /// <summary>
    /// 建链：把口令折叠成一条新链，**只存链头与初始 k**，<c>x₀</c> 用完即弃。
    ///
    /// 调用时机只有三处：注册、管理员创建账号、存量账号首次登录（迁移）。
    /// 三处共同点是服务端**本来就是请求体里的明文口令**，所以"算一次链"不违背"不保存口令"——
    /// 原则是不保存，不是不接触。
    ///
    /// ⚠️ 并发首次登录会同时建两条链。唯一索引让第二条失败（11000），此时**返回已存在的那条**，
    ///    而不是抛异常：用户看到的表现应该是"登录成功"，而不是 500。
    ///    代价是抢输的一方算了一条废链（白花一次 PBKDF2），换取"不需要分布式锁"。
    /// </summary>
    /// <param name="userId">账号 Id。</param>
    /// <param name="username">用户名（冗余，供注销清理）。</param>
    /// <param name="password">明文口令。只在本次调用内存在。</param>
    /// <param name="r">链种子。传 null 则用 CSPRNG 现生成；只有测试/探针会显式指定。</param>
    public async Task<OtpChain> CreateAsync(string userId, string username, string password, string? r = null)
    {
        var seed = string.IsNullOrWhiteSpace(r) ? NewSeed() : r!;
        var state = OtpVerifier.Create(password, seed, _opt.KdfIterations, _opt.Length);

        var chain = new OtpChain
        {
            UserId = userId,
            Username = username,
            R = seed,
            Algorithm = OtpVerifier.ChainAlgorithm,
            Kdf = OtpVerifier.KdfName,
            KdfIterations = _opt.KdfIterations,
            Length = _opt.Length,
            V = state.V,
            K = state.K,
            Generation = 1,
            CreatedAt = DateTime.UtcNow
        };

        try
        {
            await _chains.InsertOneAsync(chain);
            return chain;
        }
        catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            // 唯一索引挡住了并发重复建链 —— 对方已经建好，直接用它的。
            var existing = await FindAsync(userId);
            if (existing is null)
                throw; // 理论上不可达：报重复键却查不到，说明索引与数据不一致，不该被吞掉

            Console.WriteLine($"[Otp] 账号「{username}」并发建链，沿用已存在的那条（k={existing.K}/{existing.Length}）");
            return existing;
        }
    }

    /// <summary>
    /// CAS 核销一格：判定 + 条件更新。
    ///
    /// 返回的 <see cref="OtpConsumeResult.NeedsRenewal"/> 只表示"该续期了"，
    /// **本方法不做续期** —— 续期必须与核销分成两次写（§7.3），
    /// 否则续期失败会连带本次登录失败，而登录失败是用户可见的、续期失败是不该被看见的。
    /// </summary>
    public async Task<OtpConsumeResult> ConsumeAsync(string userId, string? submittedCode)
    {
        var chain = await FindAsync(userId);
        if (chain is null)
            return new OtpConsumeResult(OtpConsumeOutcome.NotEnrolled, null, false, false, null);

        var state = new OtpChainState(chain.V, chain.K, chain.Length);
        var verdict = OtpVerifier.Verify(state, submittedCode);
        if (!verdict.Valid)
        {
            var outcome = verdict.Status switch
            {
                OtpVerifyStatus.Exhausted => OtpConsumeOutcome.Exhausted,
                OtpVerifyStatus.Malformed => OtpConsumeOutcome.Malformed,
                _ => OtpConsumeOutcome.Mismatch
            };
            return new OtpConsumeResult(outcome, null, false, false, null);
        }

        var next = OtpVerifier.Advance(state, submittedCode!);

        // 条件写：读到的 (v, k) 必须还在。少一个条件都会导致"双写成功、白吃一格"。
        var filter = Builders<OtpChain>.Filter.Eq(c => c.UserId, userId)
                     & Builders<OtpChain>.Filter.Eq(c => c.V, state.V)
                     & Builders<OtpChain>.Filter.Eq(c => c.K, state.K);
        var update = Builders<OtpChain>.Update
            .Set(c => c.V, next.V)
            .Set(c => c.K, next.K);

        var updated = await _chains.FindOneAndUpdateAsync(
            filter, update, new FindOneAndUpdateOptions<OtpChain> { ReturnDocument = ReturnDocument.After });

        if (updated is null)
            return new OtpConsumeResult(OtpConsumeOutcome.Conflict, null, false, false, null);

        return new OtpConsumeResult(
            OtpConsumeOutcome.Consumed,
            new OtpChainState(updated.V, updated.K, updated.Length),
            verdict.NeedsRenewal,
            verdict.AtAlertLine,
            new OtpChainSnapshot(chain.R, chain.KdfIterations, chain.Length, chain.Generation));
    }

    /// <summary>
    /// 条件替换成新链（静默续期的第二步，§7.3 步骤 b）。
    ///
    /// 条件里必须带 <c>r == expectedR</c>：并发下两个客户端可能各算了一条新链，
    /// 后写的那个如果不带条件，就会覆盖掉"刚刚换好、并且已经被用于登录"的那条，
    /// 结果是两边各持一条不同的链、只有一方能继续用 —— 而失败方**看起来像是口令错了**。
    /// 带 r 条件后，抢输的一方写入失败，旧链继续有效，这次登录不受影响（失败也只是少续一次）。
    /// </summary>
    /// <param name="userId">账号 Id。</param>
    /// <param name="expectedR">调用方读到的那一代链的种子。</param>
    /// <param name="newR">新链的种子（客户端用 CSPRNG 生成，随登录一并提交）。</param>
    /// <param name="next">新链的链头与初始 k（由客户端算出并随登录提交）。</param>
    /// <param name="kdfIterations">新链使用的 PBKDF2 迭代次数。</param>
    /// <param name="length">新链链长。</param>
    /// <returns>是否替换成功。false ⇒ 链已被别人换过（不是错误，忽略即可）。</returns>
    public async Task<bool> RenewAsync(string userId, string expectedR, string newR, OtpChainState next,
        int kdfIterations, int length)
    {
        // 入参自检：这些值来自客户端（新链头、新种子），形状不对时**必须在写库前**拒绝。
        // 尤其是 R —— 它是盐，一个空串会让两个账号的链根落到同一个可预测的盐上，
        // 而链本身照样"能算"，坏得很安静。
        if (!OtpVerifier.IsWellFormedSeed(newR))
            throw new ArgumentException("新链种子必须是 32 位 Base32 字符", nameof(newR));
        if (length < 2)
            throw new ArgumentOutOfRangeException(nameof(length), "链长至少为 2");
        if (next.K != length - 1)
            throw new ArgumentException("新链的 k 必须等于 N-1（新链从满配额开始）", nameof(next));
        if (OtpVerifier.TryDecode(next.V)?.Length != OtpVerifier.RootLength)
            throw new ArgumentException("新链头必须是 32 字节的 Base64", nameof(next));

        var filter = Builders<OtpChain>.Filter.Eq(c => c.UserId, userId)
                     & Builders<OtpChain>.Filter.Eq(c => c.R, expectedR);
        var update = Builders<OtpChain>.Update
            .Set(c => c.R, newR)
            .Set(c => c.V, next.V)
            .Set(c => c.K, next.K)
            .Set(c => c.Length, length)
            .Set(c => c.KdfIterations, kdfIterations)
            .Inc(c => c.Generation, 1);

        var updated = await _chains.FindOneAndUpdateAsync(
            filter, update, new FindOneAndUpdateOptions<OtpChain> { ReturnDocument = ReturnDocument.After });

        return updated is not null;
    }

    /// <summary>
    /// 用**新的明文口令**整条重建链：换种子、重算链头、<c>k</c> 回到 N-1、代数 +1。
    ///
    /// ── 与 <see cref="RenewAsync"/> 的分工（别混） ────────────────
    ///   · `RenewAsync`：**口令没变**，只换盐（续期）。新种子与新链头由**客户端**算好递上来 ——
    ///     因为续期发生在登录过程中，服务端手里没有明文口令；
    ///   · `RebuildAsync`：**口令变了**（改密 / 重置 / 人工恢复）。服务端此刻**就有新明文**
    ///     （它是请求体里的 `newPassword`），所以种子与链头都自己算，客户端什么都不必做。
    ///
    /// 这个区别决定了本方法**不接收**任何来客提供的种子或链头：能自己算的东西不该让别人递，
    /// 否则就要重复一遍 `RenewAsync` 里那套"只验形状、验不了内容"的妥协。
    ///
    /// ── 为什么必须存在 ────────────────────────────────────────────
    /// 链根由口令派生。口令一改，旧链就绑在一个**已经没人知道**的口令上：
    /// OTP 登录必然失败，而口令登录又是通的 —— 用户会以为"系统只是不让我刷脸/用新登录方式"，
    /// 直到 P8 移除口令路径才发现自己被锁死。所以改密**必须**同时重建链。
    ///
    /// ⚠️ 并发：两个改密请求同时重建，后写的覆盖先写的。这是可接受的 ——
    ///    两者用的是**同一个新口令**，差别只在盐；抢输的一方手里那组参数作废，
    ///    客户端下次登录重新取一次挑战即可（不会留下"谁都进不来"的状态）。
    /// </summary>
    /// <param name="userId">账号 Id。</param>
    /// <param name="username">用户名（冗余字段，随账号改名一起刷新）。</param>
    /// <param name="password">**新的**明文口令。只在本次调用内存在，用完即弃。</param>
    public async Task<OtpChain> RebuildAsync(string userId, string username, string password)
    {
        // 空口令必须在这里挡住：它会让链根落到一个可预测的盐（口令=""），链照样"能算"。
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("重建链需要非空口令", nameof(password));

        var seed = NewSeed();
        var state = OtpVerifier.Create(password, seed, _opt.KdfIterations, _opt.Length);

        // 用 upsert 而不是"先删再插"：中间那一瞬的空窗会让并发的登录判定读到 NotEnrolled，
        // 而 NotEnrolled 对外是"用户名或密码错误"—— 用户会看到一次无从解释的失败。
        var filter = Builders<OtpChain>.Filter.Eq(c => c.UserId, userId);
        var update = Builders<OtpChain>.Update
            .Set(c => c.Username, username)
            .Set(c => c.R, seed)
            .Set(c => c.Algorithm, OtpVerifier.ChainAlgorithm)
            .Set(c => c.Kdf, OtpVerifier.KdfName)
            .Set(c => c.KdfIterations, _opt.KdfIterations)
            .Set(c => c.Length, _opt.Length)
            .Set(c => c.V, state.V)
            .Set(c => c.K, state.K)
            .Set(c => c.CreatedAt, DateTime.UtcNow)
            // 代数在"新建"时会从 0 变成 1（upsert 对不存在的文档也适用 Inc），
            // 于是"第几代"这个数在重建路径与续期路径上语义一致。
            .Inc(c => c.Generation, 1);

        var written = await _chains.FindOneAndUpdateAsync(
            filter, update,
            new FindOneAndUpdateOptions<OtpChain> { ReturnDocument = ReturnDocument.After, IsUpsert = true });

        // upsert 后必然有文档；返回 null 只可能是驱动异常，让它炸在明处。
        return written ?? throw new InvalidOperationException("重建链失败：写入后读不到文档");
    }

    /// <summary>链的展示用状态（剩余格数 / 代数）。供 <c>/api/auth/otp/status</c> 使用。</summary>
    public async Task<(int K, int Length, int Generation)?> StatusAsync(string userId)
    {
        var chain = await FindAsync(userId);
        return chain is null ? null : (chain.K, chain.Length, chain.Generation);
    }

    /// <summary>按 userId 真删（管理员重置 / 本人重置链）。返回删除条数。</summary>
    public async Task<long> DeleteByUserIdAsync(string userId)
    {
        var result = await _chains.DeleteManyAsync(c => c.UserId == userId);
        return result.DeletedCount;
    }

    // ── IUserDataPurger：账号注销时由用户管理域遍历调用 ──
    // 排在"删除账号"之前执行（调用方保证）：清理失败 ⇒ 请求失败、账号仍在，
    // 于是不会出现"人已经不在了、链还挂在库里"这种查都没法查的孤儿记录。
    // 链本身不含生物特征，但它是**该账号的认证凭据状态**：
    // 留着它等于给一条已注销的 userId 保留可推进的链，没有任何正当用途。

    /// <inheritdoc />
    public Task<long> PurgeByUsernameAsync(string username) =>
        DeleteByUsernameAsync(username);

    /// <summary>按用户名真删（注销路径手里只有用户名）。返回删除条数。</summary>
    public async Task<long> DeleteByUsernameAsync(string username)
    {
        var result = await _chains.DeleteManyAsync(c => c.Username == username);
        return result.DeletedCount;
    }

    // ── 链种子 ────────────────────────────────────────────────

    /// <summary>
    /// 生成新链种子：20 字节 CSPRNG → Base32（32 字符，不带填充）。
    ///
    /// 用 CSPRNG 而不是"随机字符串"：R 是链的盐，可预测的盐等于没有盐 ——
    /// 攻击者可以预先为常见口令算好整条链的字典（正因为 R 是明文可读的）。
    /// Base32 是为了人工核对时不受大小写与易混字符（0/O、1/l）干扰，
    /// 也便于将来"电话报读链号"这种运维场景。
    /// </summary>
    public static string NewSeed()
    {
        Span<byte> bytes = stackalloc byte[20];
        RandomNumberGenerator.Fill(bytes);
        return ToBase32(bytes);
    }

    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private static string ToBase32(ReadOnlySpan<byte> data)
    {
        var chars = new char[(data.Length * 8 + 4) / 5];
        int buffer = 0, bits = 0, index = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                chars[index++] = Base32Alphabet[(buffer >> (bits - 5)) & 0x1F];
                bits -= 5;
            }
        }

        if (bits > 0)
            chars[index++] = Base32Alphabet[(buffer << (5 - bits)) & 0x1F];

        return new string(chars, 0, index);
    }
}
