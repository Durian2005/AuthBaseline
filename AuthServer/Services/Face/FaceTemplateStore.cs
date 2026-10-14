using AuthServer.Models;
using MongoDB.Driver;

namespace AuthServer.Services.Face;

/**
 * 人脸模板的存取。
 *
 * 三条边界写在这里，因为它们必须和"写入"发生在同一个地方才守得住：
 *
 *   ① **模板永不进审计、永不导出。** 本类只返回解密后的特征数组给引擎用，
 *      不提供任何"列出全部模板"或"导出"的方法。生物特征一旦进了审计日志，
 *      哈希链就成了一个永久、可复制的生物特征泄露源 —— 而且**删不掉**（删了就断链）。
 *
 *   ② **注销 / 重置必须真删，不留孤儿。** 生物特征不像口令那样"改了就能撤销"，
 *      账号都注销了还留着向量，是纯粹的多余暴露面。
 *
 *   ③ **认证失败与"读不出来"必须分开。** 密钥丢失或密文被改动 ⇒ 解密返回 null，
 *      这属于**本机故障**，不能被当成"这个人脸对不上"（那会把用户锁在门外，
 *      而且把一个环境问题伪装成一次认证失败，掩盖了真正的事故）。
 */
public sealed class FaceTemplateStore
{
    private readonly MongoDbService _db;
    private readonly FaceTemplateCrypto _crypto;
    private readonly FaceOptions _opt;

    public FaceTemplateStore(MongoDbService db, FaceTemplateCrypto crypto, FaceOptions opt)
    {
        _db = db;
        _crypto = crypto;
        _opt = opt;
    }

    private IMongoCollection<FaceTemplate> Collection => _db.FaceTemplates;

    /// <summary>加密密钥是否可用。false ⇒ 所有模板都读不出来（不是"对不上"）。</summary>
    public bool KeyAvailable => _crypto.Available;

    public async Task<long> CountAsync(string userId) =>
        await Collection.CountDocumentsAsync(t => t.UserId == userId);

    public async Task<bool> HasAnyAsync(string userId) => await CountAsync(userId) > 0;

    /// <summary>最近一次录入时刻（UTC）。未录入返回 null。</summary>
    public async Task<DateTime?> LastEnrolledAtAsync(string userId)
    {
        var last = await Collection.Find(t => t.UserId == userId)
            .Sort(Builders<FaceTemplate>.Sort.Descending(t => t.CreatedAt))
            .Limit(1)
            .FirstOrDefaultAsync();
        return last?.CreatedAt;
    }

    /// <summary>
    /// 追加一张模板，并在超出上限时淘汰最旧的那张。
    ///
    /// 为什么允许一人多模板：同一个人在不同光线/姿态下差异不小，多留几张能把误拒率压下来。
    /// 为什么又要设上限：模板越多，"总有一张碰巧命中"的概率越大（FAR 随模板数上升）。
    /// 所以上限是**安全参数**，不是性能参数 —— 不要为了"识别更准"随手调大。
    /// </summary>
    public async Task<long> AddAsync(string userId, string username, double[] feature)
    {
        var (cipher, nonce, tag) = _crypto.Encrypt(feature, Aad(userId));
        await Collection.InsertOneAsync(new FaceTemplate
        {
            UserId = userId,
            Username = username,
            Cipher = cipher,
            Nonce = nonce,
            Tag = tag,
            Dim = feature.Length,
            Version = 1,
            CreatedAt = DateTime.UtcNow
        });

        // 超限淘汰：按录入时间升序删到不超过上限。
        var count = await CountAsync(userId);
        if (count > _opt.MaxTemplates)
        {
            var stale = await Collection.Find(t => t.UserId == userId)
                .Sort(Builders<FaceTemplate>.Sort.Ascending(t => t.CreatedAt))
                .Limit((int)(count - _opt.MaxTemplates))
                .ToListAsync();
            if (stale.Count > 0)
            {
                await Collection.DeleteManyAsync(
                    Builders<FaceTemplate>.Filter.In(t => t.Id, stale.Select(s => s.Id)));
            }
        }
        return await CountAsync(userId);
    }

    /// <summary>
    /// 读出该账号**全部可用**的模板特征。解不出来的会被跳过（并在返回值里报告条数），
    /// 由调用方决定这算"故障"还是"正常"。
    /// </summary>
    public async Task<(List<double[]> Features, int Unreadable)> LoadFeaturesAsync(string userId)
    {
        var docs = await Collection.Find(t => t.UserId == userId).ToListAsync();
        var features = new List<double[]>(docs.Count);
        int unreadable = 0;

        foreach (var doc in docs)
        {
            var feature = _crypto.Decrypt(doc.Cipher, doc.Nonce, doc.Tag, doc.Dim, Aad(userId));
            if (feature is null) unreadable++;
            else features.Add(feature);
        }
        return (features, unreadable);
    }

    /// <summary>
    /// 用人脸探针比对该账号的全部模板，返回最高相似度与可用模板数。
    /// 没有任何可用模板时 <c>Best</c> 为 null —— 这个区别必须保留：
    /// "没有可比的东西"和"比了但不像"是两件完全不同的事。
    /// </summary>
    public async Task<(double? Best, int Usable, int Unreadable)> TryVerifyAsync(
        string userId, double[] probe, IFaceEngine engine)
    {
        var (features, unreadable) = await LoadFeaturesAsync(userId);
        double? best = null;
        foreach (var feature in features)
        {
            double sim = engine.Similarity(probe, feature);
            if (best is null || sim > best.Value) best = sim;
        }
        return (best, features.Count, unreadable);
    }

    /// <summary>删除某账号的全部模板（本人删除 / 管理员重置）。返回删除条数。</summary>
    public async Task<long> DeleteByUserIdAsync(string userId)
    {
        var result = await Collection.DeleteManyAsync(t => t.UserId == userId);
        return result.DeletedCount;
    }

    /// <summary>
    /// 按用户名清理（注销账号时用）。
    ///
    /// 为什么按用户名而不是 userId：注销路径手里只有用户名（用户是自己登进来注销的，
    /// 未必带着 Id），而模板表冗余存了 username 正是为了这条路径少一次查询 ——
    /// 少一次查询就少一处可能失败的地方，而"漏删模板"是这里最不能接受的失败。
    /// </summary>
    public async Task<long> DeleteByUsernameAsync(string username)
    {
        var result = await Collection.DeleteManyAsync(t => t.Username == username);
        return result.DeletedCount;
    }

    /// <summary>附加认证数据：把密文绑定到账号，使模板不可跨账号搬运。</summary>
    private static string Aad(string userId) => "AuthBaselineFaceTemplate|" + userId;
}
