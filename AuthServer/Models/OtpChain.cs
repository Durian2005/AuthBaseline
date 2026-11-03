using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthServer.Models;

/**
 * 一次性口令（哈希链）的链状态 —— 一个账号一条，独立集合 `OtpChains`。
 *
 * ── 为什么必须独立于 Users ─────────────────────────────────────
 * `Users` 集合被大量整篇 `ReplaceOneAsync` 覆盖（登录成功、失败计数、解锁、冻结、角色变更）。
 * 链状态一旦挂进那个文档，任何一次"读出来 → 改别的字段 → 整篇写回"都会把 `k` 写回请求开头读到的旧值：
 * **静默回滚一格，等于开出一个可重放的窗口**，而且不报任何错、日志里什么都看不到。
 * 独立集合后，链只被一条带条件的 `FindOneAndUpdate` 推进，物理上不存在"别处的覆盖"。
 *
 * ── 为什么不存任何口令派生物 ───────────────────────────────────
 * 这里只有 <see cref="V"/>（链头迭代值）与 <see cref="R"/>（公开种子）。
 * 两者都不是秘密：V 是单向哈希的输出，拿到它推不出上一格，更推不出口令；
 * 而"能不能离线猜口令"由 PBKDF2 的迭代次数（<see cref="KdfIterations"/>）兜底，
 * 不是靠把 V 藏起来 —— 藏起来的加密在拖库场景里毫无意义（密钥也在同一台机器上）。
 *
 * ⚠️ V 是**明文**存、并且**必须**能和提交值直接比对。任何"加密 V"的改造都会让
 *    链推进需要解密、续期需要重加密，收益为零而失败面变大。
 */
public class OtpChain
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    /// <summary>所属账号的 <see cref="User.Id"/>。**唯一索引**建在这个字段上。</summary>
    [BsonElement("userId")]
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// 用户名（冗余）。注销账号那条路径手里只有用户名（
    /// 见 <see cref="Services.IUserDataPurger.PurgeByUsernameAsync"/>），
    /// 冗余一份可以省掉一次查询 —— 而"注销后留下孤儿数据"是最不能接受的失败。
    /// </summary>
    [BsonElement("username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// 公开链种子（Base32 文本）。可明文下发，本身不是秘密；
    /// 它的作用是让两条链即便口令相同也互不相干（等价于盐）。
    /// </summary>
    [BsonElement("r")]
    public string R { get; set; } = string.Empty;

    /// <summary>链算法名（当前恒为 <c>SHA256</c>）。记录在案是为了将来能整体升级。</summary>
    [BsonElement("algorithm")]
    public string Algorithm { get; set; } = Services.Otp.OtpVerifier.ChainAlgorithm;

    /// <summary>口令派生函数名（当前恒为 <c>PBKDF2-HMACSHA256</c>）。</summary>
    [BsonElement("kdf")]
    public string Kdf { get; set; } = Services.Otp.OtpVerifier.KdfName;

    /// <summary>
    /// 建链时使用的 PBKDF2 迭代次数。**与链绑定**而不是读当前配置：
    /// 将来把全局迭代次数调高，老链仍要按它自己的次数派生，否则同一个口令会算出不同的链根，
    /// 表现为"所有人都登不上"。升级只能走"登录成功后主动重建链"这条路。
    /// </summary>
    [BsonElement("kdfIterations")]
    public int KdfIterations { get; set; }

    /// <summary>链长 N。它决定的是**续期失败时的缓冲深度**，不是"能用多久"。</summary>
    [BsonElement("length")]
    public int Length { get; set; }

    /// <summary>当前验证基准（Base64，32 字节）。判定式是 <c>H(提交值) == V</c>。</summary>
    [BsonElement("v")]
    public string V { get; set; } = string.Empty;

    /// <summary>期望下标：本次应当提交 <c>x_k</c>。每次成功核销减一，减到 0 即配额用尽。</summary>
    [BsonElement("k")]
    public int K { get; set; }

    /// <summary>第几代链。只在续期时 +1，用于回答"这条链换过几次"。</summary>
    [BsonElement("generation")]
    public int Generation { get; set; } = 1;

    /// <summary>链的**出生**时刻（续期不重置它：那会让"这个账号用这条链多久了"失去意义）。</summary>
    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
