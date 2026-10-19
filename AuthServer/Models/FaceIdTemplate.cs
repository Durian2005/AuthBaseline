using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthServer.Models;

/**
 * 纯人脸登录（FaceId）的特征模板 —— 账号级的**可选**第二登录方式。
 *
 * 与 <see cref="FaceTemplate"/>（人脸 2FA）是**两个独立的集合**：
 *   两套模板的分辨能力来自不同的特征空间（ArcFace vs SFace），
 *   共用一个集合只会让"这张模板属于哪条链路"变成一个必须靠字段猜的问题；
 *   而且删除任一模块时，另一个模块的模板不受牵连（模块删除友好的直接体现）。
 *
 * 与 2FA 模板同样的三条设计（理由同 FaceTemplate 的注释，不重复论证）：
 *   1) 只存特征、不存照片；
 *   2) **可逆加密**（AES-256-GCM）而不是哈希 —— 比对必须还原明文；
 *   3) 一人多模板有上限（本模块默认 3 张，比 2FA 的 8 张更严，理由见下）。
 *
 * 为什么本模块的上限更小（3 而非 8）：
 *   2FA 的比对发生在"口令已经验过"之后，多几张模板的代价只是 FAR 上升；
 *   纯人脸登录是**唯一的登录因子**（用户名 + 人脸），模板数直接乘在 FAR 上。
 *   所以每多留一张，都是在用"本人少被拒一次"换"冒充者多一次机会"。
 *
 * 新增字段 `modelId`（2FA 的模板里没有）：
 *   本模块跨设备/跨模型换权重的可能性更高（模型由装机流程下载），
 *   必须让"这张模板是用哪个特征空间录的"成为可判定的字段，
 *   否则换模型后老模板会被拿去比对，得到一个合法但毫无意义的相似度。
 */
public class FaceIdTemplate
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    /// <summary>所属账号的 <see cref="User.Id"/>。</summary>
    [BsonElement("userId")]
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// 所属账号用户名（冗余）。与 2FA 同理由：注销路径手里只有用户名，
    /// 少一次查询就少一处"漏删模板"的可能。
    /// </summary>
    [BsonElement("username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>AES-GCM 密文（特征向量按 float32 小端序列化后的字节）。</summary>
    [BsonElement("cipher")]
    public byte[] Cipher { get; set; } = Array.Empty<byte>();

    /// <summary>AES-GCM nonce。每条模板独立随机，绝不复用（GCM 最致命的误用）。</summary>
    [BsonElement("nonce")]
    public byte[] Nonce { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// AES-GCM 认证标签。密文被改一个字节 ⇒ 解密直接失败，
    /// 而不是解出垃圾向量去做比对（那会把一次篡改伪装成一次"人脸不匹配"）。
    /// </summary>
    [BsonElement("tag")]
    public byte[] Tag { get; set; } = Array.Empty<byte>();

    /// <summary>特征维度（解密后校验；与 <see cref="ModelId"/> 一起构成"这张模板还能不能用"的判据）。</summary>
    [BsonElement("dim")]
    public int Dim { get; set; }

    /// <summary>
    /// 录入时的模型身份（<see cref="AuthServer.Services.FaceId.FaceIdModelIdentity.ModelId"/>）。
    /// 与当前模型不一致 ⇒ 该模板作废（跳过，不参与比对），并在状态里如实报告。
    /// </summary>
    [BsonElement("modelId")]
    public string ModelId { get; set; } = string.Empty;

    /// <summary>加密方案版本（将来换算法时区分新老密文）。</summary>
    [BsonElement("version")]
    public int Version { get; set; } = 1;

    /// <summary>录入时刻（UTC）。</summary>
    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
