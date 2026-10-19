using AuthServer.Models;
using MongoDB.Driver;

namespace AuthServer.Services.FaceId;

/**
 * 纯人脸登录模板的存取。
 *
 * 三条边界（与 2FA 的 FaceTemplateStore 同源，但**代码独立**）：
 *   ① **模板永不进审计、永不导出。** 本类不提供任何"列出全部模板"的方法，
 *      只给引擎返回解密后的特征。生物特征一旦进审计，哈希链就成了永久、
 *      可复制、且**删不掉**（删了断链）的泄露源。
 *   ② **注销必须真删。** 人脸不可撤销，账号都不在了还留着向量是纯粹的多余暴露面。
 *   ③ **"读不出来" ≠ "对不上"。** 解密失败属于本机故障（密钥换了、密文被改动），
 *      必须与"这张脸不像"分开报告。
 *
 * 第四条是本模块特有的：
 *   ④ **模型身份不符的模板直接作废。** 不同特征空间的向量算出的余弦是个合法数字，
 *      却没有任何判别意义（见 FaceIdModelIdentity 的注释）。所以加载时按
 *      <see cref="FaceIdModelIdentity.ModelId"/> 过滤，并把"有多少张被作废"如实报给上层，
 *      由它决定这是"需要重新录入"还是"正常"。
 */
public sealed class FaceIdTemplateStore : IUserDataPurger
{
    private readonly MongoDbService _db;
    private readonly FaceIdTemplateCrypto _crypto;
    private readonly FaceIdOptions _opt;
    private readonly FaceIdModelIdentity _model;

    public FaceIdTemplateStore(MongoDbService db, FaceIdTemplateCrypto crypto,
        FaceIdOptions opt, FaceIdModelIdentity model)
    {
        _db = db;
        _crypto = crypto;
        _opt = opt;
        _model = model;
    }

    private IMongoCollection<FaceIdTemplate> Collection => _db.FaceIdTemplates;

    /// <summary>加密密钥是否可用。false ⇒ 所有模板都读不出来（不是"对不上"）。</summary>
    public bool KeyAvailable => _crypto.Available;

    /// <summary>当前模型身份（状态接口会下发，便于界面上显示"模板录制于哪个模型"）。</summary>
    public string ModelId => _model.ModelId;

    public async Task<long> CountAsync(string userId) =>
        await Collection.CountDocumentsAsync(t => t.UserId == userId);

    public async Task<bool> HasAnyAsync(string userId) => await CountAsync(userId) > 0;

    /// <summary>最近一次录入时刻（UTC）。未录入返回 null。</summary>
    public async Task<DateTime?> LastEnrolledAtAsync(string userId)
    {
        var last = await Collection.Find(t => t.UserId == userId)
            .Sort(Builders<FaceIdTemplate>.Sort.Descending(t => t.CreatedAt))
            .Limit(1)
            .FirstOrDefaultAsync();
        return last?.CreatedAt;
    }

    /// <summary>
    /// 模板总体情况：总数、当前模型可用数、模型不符（作废）数。
    ///
    /// 为什么状态接口需要这三个数而不是一个布尔：
    ///   "没录过"与"录过但模型换了"对用户意味着完全不同的下一步 ——
    ///   前者要引导去录入，后者要明确告诉他"旧的作废了，请重新录"，
    ///   而不是让他对着一个永远失败的人脸登录猜原因。
    /// </summary>
    public async Task<(long Total, long Usable, long ForeignModel)> StatusAsync(string userId)
    {
        var docs = await Collection.Find(t => t.UserId == userId)
            .Project(t => new { t.ModelId })
            .ToListAsync();
        long usable = docs.Count(d => _model.Matches(d.ModelId));
        return (docs.Count, usable, docs.Count - usable);
    }

    /// <summary>
    /// 追加一张模板，并在超出上限时淘汰最旧的那张。
    ///
    /// 写入前先清掉**模型身份不符**的旧模板：它们已经不可用，占着名额只会
    /// 让新录入的模板把"还能用的那张"挤掉 —— 那是一种"越录越登不上"的荒谬状态。
    ///
    /// 上限是**安全参数**而不是性能参数：模板越多，"总有一张碰巧命中"的概率越大。
    /// 本模块是唯一登录因子，所以默认只留 3 张（详见 FaceIdTemplate 的注释）。
    /// </summary>
    public async Task<(long Count, long PurgedForeign, long Evicted)> AddAsync(
        string userId, string username, double[] feature)
    {
        long purged = 0;
        var foreign = await Collection.Find(t => t.UserId == userId && t.ModelId != _model.ModelId)
            .Project(t => t.Id)
            .ToListAsync();
        if (foreign.Count > 0)
        {
            var del = await Collection.DeleteManyAsync(
                Builders<FaceIdTemplate>.Filter.In(t => t.Id, foreign));
            purged = del.DeletedCount;
        }

        var (cipher, nonce, tag) = _crypto.Encrypt(feature, Aad(userId));
        await Collection.InsertOneAsync(new FaceIdTemplate
        {
            UserId = userId,
            Username = username,
            Cipher = cipher,
            Nonce = nonce,
            Tag = tag,
            Dim = feature.Length,
            ModelId = _model.ModelId,
            Version = 1,
            CreatedAt = DateTime.UtcNow
        });

        long evicted = 0;
        var count = await CountAsync(userId);
        if (count > _opt.MaxTemplates)
        {
            var stale = await Collection.Find(t => t.UserId == userId)
                .Sort(Builders<FaceIdTemplate>.Sort.Ascending(t => t.CreatedAt))
                .Limit((int)(count - _opt.MaxTemplates))
                .Project(t => t.Id)
                .ToListAsync();
            if (stale.Count > 0)
            {
                var del = await Collection.DeleteManyAsync(
                    Builders<FaceIdTemplate>.Filter.In(t => t.Id, stale));
                evicted = del.DeletedCount;
            }
        }
        return (await CountAsync(userId), purged, evicted);
    }

    /// <summary>
    /// 读出该账号**当前模型可用**的模板特征。
    /// 模型不符的跳过（计入 <c>foreign</c>）；解密失败的跳过（计入 <c>unreadable</c>）。
    /// 这两个计数必须分开：前者是"该重新录"，后者是"本机密钥/密文出事了"。
    /// </summary>
    public async Task<(List<double[]> Features, int Foreign, int Unreadable)> LoadFeaturesAsync(string userId)
    {
        var docs = await Collection.Find(t => t.UserId == userId).ToListAsync();
        var features = new List<double[]>(docs.Count);
        int foreign = 0, unreadable = 0;

        foreach (var doc in docs)
        {
            if (!_model.Matches(doc.ModelId)) { foreign++; continue; }
            if (doc.Dim != _model.Dim) { unreadable++; continue; }

            var feature = _crypto.Decrypt(doc.Cipher, doc.Nonce, doc.Tag, doc.Dim, Aad(userId));
            if (feature is null) unreadable++;
            else features.Add(feature);
        }
        return (features, foreign, unreadable);
    }

    /// <summary>删除某账号的全部模板（本人删除 / 管理员重置 / 注销）。返回删除条数。</summary>
    public async Task<long> DeleteByUserIdAsync(string userId)
    {
        var result = await Collection.DeleteManyAsync(t => t.UserId == userId);
        return result.DeletedCount;
    }

    /// <summary>按用户名清理（注销账号时用）。理由同 2FA：注销路径手里只有用户名。</summary>
    public async Task<long> DeleteByUsernameAsync(string username)
    {
        var result = await Collection.DeleteManyAsync(t => t.Username == username);
        return result.DeletedCount;
    }

    /// <summary>附加认证数据：把密文绑定到账号，使模板不可跨账号搬运。</summary>
    private static string Aad(string userId) => "AuthBaselineFaceIdTemplate|" + userId;

    // ── IUserDataPurger：账号注销时由用户管理域遍历调用 ──
    // 刻意通过接口登记，而不是让 UserAdminController 直接引用本类：
    // 账号域不该认识"人脸模板"这种细节，否则每加一个生物特征模块都要改用户管理。

    /// <inheritdoc />
    public string Name => "FaceIdTemplates";

    /// <inheritdoc />
    public Task<long> PurgeByUsernameAsync(string username) => DeleteByUsernameAsync(username);
}
