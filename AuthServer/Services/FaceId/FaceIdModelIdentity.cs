using System.Security.Cryptography;

namespace AuthServer.Services.FaceId;

/**
 * 特征模型的身份 —— 模板与它绑定，换了模型就作废。
 *
 * 为什么需要一个**显式**的模型身份，而不是"反正都是 512 维，长度对上就能比"：
 *   ArcFace（w600k_r50）与假引擎、以及将来可能替换的任意模型，输出的 512 维向量
 *   处在**完全不同的特征空间**。两个不同空间的向量算出的余弦相似度没有任何意义，
 *   但它是一个合法的数字 —— 于是"换模型后老模板还能登录"不会报错，
 *   只会表现为"这个人有时能进、有时进不去"，这是最难归因的一类故障。
 *
 * 身份怎么算：
 *   · 假引擎 → `stub:<dim>`（假引擎的特征来自用户名哈希，与真模型空间无关）
 *   · 真引擎 → `cv:<权重文件名>:<sha256 前 16 位>:<dim>`
 *     取哈希而不是只看文件名：换一个同名但不同批次的权重，是最常见的"静默换模型"方式。
 *
 * ⚠️ 哈希在**启动时算一次**（174MB ≈ 数百毫秒）。这是刻意的代价：
 *    模型文件不在仓库里、由装机流程下载，只核对文件名等于没有核对。
 */
public sealed class FaceIdModelIdentity
{
    /// <summary>用于模板匹配的身份串。空模型（引擎不可用）时仍给出一个确定值。</summary>
    public string ModelId { get; }

    /// <summary>特征维度（模板解密后校验用）。</summary>
    public int Dim { get; }

    /// <summary>给人读的一行说明，启动日志里打印。</summary>
    public string Description { get; }

    public FaceIdModelIdentity(FaceIdOptions opt)
    {
        Dim = opt.EmbeddingDim <= 0 ? 512 : opt.EmbeddingDim;

        if (opt.UseStubEngine)
        {
            // 假引擎：身份里必须带 stub 前缀，防止"用假引擎录的模板"在真引擎下被误认为可用。
            ModelId = $"stub:{Dim}";
            Description = $"假引擎 · {Dim} 维";
            return;
        }

        var path = opt.ResolveRecognizer();
        var name = Path.GetFileName(path);
        if (!File.Exists(path))
        {
            // 模型缺失时引擎本来就不可用（fail closed）。这里仍给一个可区分的身份，
            // 避免"文件缺失"与"文件被换成同名旧版"混成同一种状态。
            ModelId = $"cv:{name}:missing:{Dim}";
            Description = $"{name} · 文件缺失";
            return;
        }

        var fingerprint = Fingerprint(path);
        ModelId = $"cv:{name}:{fingerprint}:{Dim}";
        Description = $"{name} · sha256:{fingerprint} · {Dim} 维";
    }

    /// <summary>模板里记的模型身份是否与当前模型一致。</summary>
    public bool Matches(string? stored) =>
        !string.IsNullOrEmpty(stored) && string.Equals(stored, ModelId, StringComparison.Ordinal);

    /// <summary>权重文件的 sha256 前 16 位（大写十六进制）。失败返回 "unreadable"。</summary>
    private static string Fingerprint(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            var hash = SHA256.HashData(stream);
            return Convert.ToHexString(hash)[..16];
        }
        catch (Exception ex)
        {
            // 读不动权重（权限/占用）时不要抛：引擎加载模型那一步会给出更准确的原因，
            // 而这里抛出去只会把一个"可选模块"的问题升级成启动失败。
            Console.WriteLine($"[FaceId] ⚠️ 无法计算权重指纹：{ex.Message}");
            return "unreadable";
        }
    }
}
