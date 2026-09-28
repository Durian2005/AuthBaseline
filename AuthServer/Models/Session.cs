using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthServer.Models;

/// <summary>
/// 会话票据（服务端不透明随机票据）。
///
/// 为什么必须引入它 —— 这是实验二「02 看不到」的技术前提：
///   改造前管理员接口靠请求里的 adminUsername 判断身份，
///   而 adminUsername 是**客户端可控的声明**，不是凭证。
///   任何人带上 ?adminUsername=admin 就能读走全部审计日志。
///
/// 票据的四个关键性质：
///   1. 不透明：32 字节密码学随机数，攻击者无法从用户名推导；
///   2. 服务端持有：可随时吊销（登出、被禁用、权限变更）；
///   3. 滑动过期：有操作就续期，长时间无操作自动失效；
///   4. **库里只存哈希**：即便数据库被读走，里面的值也不能直接当凭证用。
///
/// 刻意不自包含任何权限断言（不像 JWT 把 isAdmin 签进去）：
/// 每次校验都重新查库确认当前身份，因此"权限被转让后旧票据立刻失去管理员能力"。
/// </summary>
public class Session
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// 票据的**哈希**（无盐 SHA-256，Base64Url）—— 库里不存票据本体。
    ///
    /// 改造前这里叫 <c>ticket</c>，存的是票据明文：任何能读到库的人都可以
    /// 把库里的值直接塞进 <c>Authorization: Bearer</c> 冒用登录态，**不需要破解**。
    /// 改成哈希之后，"能读库"与"能冒用会话"被拆开了 ——
    /// 服务端收到明文票据后自己折算一次哈希即可 O(1) 命中，读库者却无法反推回明文。
    ///
    /// ⚠️ 这里**刻意不加盐**，与口令的处理正好相反：票据是 32 字节密码学随机数（256 位熵），
    /// 盐要防的"预计算表""相同输入跨记录比对"都不成立，加盐却会让索引等值查询退化成
    /// 全表慢哈希。完整理由见 <see cref="Services.TicketHasher"/>。
    ///
    /// ⚠️ 该字段上有唯一索引（<c>uniq_ticket_hash</c>）—— 老索引 <c>uniq_ticket</c> 建在
    /// 已被移除的明文字段上，必须删除：字段缺失时 MongoDB 一律视作 null，
    /// 唯一约束会让第二个会话就插不进去。
    /// </summary>
    [BsonElement("ticketHash")]
    public string TicketHash { get; set; } = string.Empty;

    /// <summary>票据归属的账号（用户名统一小写）。</summary>
    [BsonElement("username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>签发时的用户 Id，便于关联审计。</summary>
    [BsonElement("userId")]
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// 签发时的管理员快照（改造前字段）。**仅用于审计留痕，不用于鉴权判定**。
    /// 鉴权一律实时查库，避免"签发时是管理员、现在已被降级"的授权残留。
    /// 角色分离改造后由 RoleAtIssue 取代，保留此字段以兼容老会话文档。
    /// </summary>
    [BsonElement("isAdminAtIssue")]
    public bool IsAdminAtIssue { get; set; }

    /// <summary>
    /// 签发时的角色快照。同样**只做审计留痕，不参与鉴权** ——
    /// 每次请求都会重新查库取当前角色，所以"角色被撤销后旧票据立刻失去对应能力"。
    /// </summary>
    [BsonElement("roleAtIssue")]
    [BsonRepresentation(BsonType.String)]
    public UserRole RoleAtIssue { get; set; } = UserRole.User;

    [BsonElement("issuedAt")]
    public DateTime IssuedAt { get; set; } = DateTime.UtcNow;

    /// <summary>最近一次使用时刻，滑动续期的基准。</summary>
    [BsonElement("lastSeenAt")]
    public DateTime LastSeenAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 绝对过期时刻。每次通过校验会顺延为 now + 滑动窗口。
    /// 该字段上建 TTL 索引，过期票据由 MongoDB 自动清理，无需定时任务。
    /// </summary>
    [BsonElement("expiresAt")]
    public DateTime ExpiresAt { get; set; }

    /// <summary>被吊销的时刻；非空表示票据已失效（登出或强制下线）。</summary>
    [BsonElement("revokedAt")]
    public DateTime? RevokedAt { get; set; }

    /// <summary>吊销原因，便于审计追溯"为什么这个会话没了"。</summary>
    [BsonElement("revokedReason")]
    public string RevokedReason { get; set; } = string.Empty;
}

/// <summary>
/// 哈希链的链尾锚点。
///
/// 为什么要单独一个集合存链尾：
///   写入时需要读"上一条的哈希"再算本条哈希，若每次都去查最后一条记录，
///   在分片场景下要跨多个集合找最大值，且高并发下读写窗口更长。
///   把链尾锚点独立成一个固定文档，读改写都在同一文档上完成，配合串行锁即可保证不分叉。
///
/// 同时它是"整段被删"检测的依据：锚点的 seq 与各分片实际最大 seq 不一致，
/// 说明有记录被删掉了（链式哈希本身只能发现单条被改，发现不了尾部整段消失）。
/// </summary>
public class AuditChainHead
{
    /// <summary>固定文档 Id，全局唯一锚点。</summary>
    [BsonId]
    public string Id { get; set; } = "head";

    /// <summary>链上最后一条记录的 seq。</summary>
    [BsonElement("seq")]
    public long Seq { get; set; }

    /// <summary>链上最后一条记录的 selfHash。</summary>
    [BsonElement("lastHash")]
    public string LastHash { get; set; } = new string('0', 64);

    /// <summary>链尾所在分片，便于快速定位当前活跃集合。</summary>
    [BsonElement("shard")]
    public string Shard { get; set; } = string.Empty;

    /// <summary>链上累计写入条数（含所有分片），用于增长趋势观测。</summary>
    [BsonElement("totalCount")]
    public long TotalCount { get; set; }

    [BsonElement("updatedAt")]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
