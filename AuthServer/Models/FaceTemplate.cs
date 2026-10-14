using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthServer.Models;

/// <summary>
/// 人脸特征模板 —— **可选**的第二因子的凭据材料。
///
/// 三条与口令存储刻意不同的设计（答辩时会被追问，理由先写在这里）：
///
/// 1. **只存特征，不存照片。** 特征是从对齐后的人脸图上算出的定长向量，
///    它还原不成一张能看的照片。存照片则相反：库一旦被拿走，
///    等于拿走了这个人**永久可用**的生物特征。
///
/// 2. **加密存储，而不是哈希。** 这是与口令最本质的差异 ——
///    口令是"验的时候重算一遍再比对"，所以可以单向哈希（BCrypt + pepper）；
///    人脸必须"解密出向量 → 算余弦相似度"，**必须能还原明文**，
///    因此只能做静态加密（AES-GCM）。它防的是"库文件被拿走"，
///    **防不了**"进程被注入 / 调试器附加" ——
///    文档与答辩口径都不许写成"不可逆保护"。
///
/// 3. **一人多模板。** 同一个人在不同光线 / 姿态下差异不小，多留几张能把
///    误拒率压下来；但模板越多，"总有一张碰巧命中"的概率也越大，
///    所以上限取 8（与参考项目 FaceLogin 一致），超出淘汰最旧的。
///
/// 生物特征不可撤销，是本功能最重的代价：
/// 口令泄露 → 改一个口令即可撤销；人脸泄露 → **改不了脸**。
/// 因此模板不进审计、不导出、注销账号时必须一并清除（见 UserAdminController）。
/// </summary>
public class FaceTemplate
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    /// <summary>所属账号的 <see cref="User.Id"/>。索引建在这一列上。</summary>
    [BsonElement("userId")]
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// 所属账号用户名。与 userId 冗余存一份，是为了让"注销账号时按用户名清理"
    /// 这条路径不必先查 Users —— 少一次查询，也少一处失败的可能。
    /// </summary>
    [BsonElement("username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>AES-GCM 密文（特征向量的原始字节）。</summary>
    [BsonElement("cipher")]
    public byte[] Cipher { get; set; } = Array.Empty<byte>();

    /// <summary>AES-GCM nonce。**每条模板独立随机生成，绝不复用** —— nonce 复用是 GCM 最致命的误用。</summary>
    [BsonElement("nonce")]
    public byte[] Nonce { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// AES-GCM 认证标签。它的价值在于：密文被改动一个字节，解密会**直接失败**，
    /// 而不是解出一段垃圾向量再拿去做比对（那样会得到一个"看起来很低"的相似度，
    /// 被误判成"人脸不匹配"，把一次篡改伪装成一次正常的认证失败）。
    /// </summary>
    [BsonElement("tag")]
    public byte[] Tag { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// 特征维度。随模板一同存储、解密后校验 ——
    /// 换了模型（维度变了）时，老模板会在这里被判为不可用，
    /// 而不是把一段长度不对的字节硬喂进比对函数。
    /// </summary>
    [BsonElement("dim")]
    public int Dim { get; set; }

    /// <summary>加密方案版本。将来换算法时用它区分新老密文，做平滑迁移。</summary>
    [BsonElement("version")]
    public int Version { get; set; } = 1;

    /// <summary>该模板的录入时刻（UTC）。</summary>
    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
