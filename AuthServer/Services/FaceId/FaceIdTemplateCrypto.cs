using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AuthServer.Services.FaceId;

/**
 * 纯人脸登录模板的静态加密（AES-256-GCM）。
 *
 * 与 <see cref="AuthServer.Services.Face.FaceTemplateCrypto"/> 是两套**独立**实现，
 * 密钥文件也**分开**（`faceid.key` vs `face.key`），刻意不做共用：
 *   ① 模块边界：删掉 2FA 时，本模块的模板仍然解得开；
 *   ② 事故边界：某一把密钥被误删/损坏，只影响一个模块，而不是两条链路一起降级。
 * 重复的 ~60 行换这两条，值得。
 *
 * 与 2FA 相同的那条关键结论（答辩要分开讲）：
 *   口令 = 不可逆存储（BCrypt + pepper）；
 *   人脸 = **可逆**存储但加密（AES-GCM）。
 * 防护边界是"库文件被拿走"，**不是**"进程被注入/调试器附加"。
 *
 * 密钥丢了会怎样：模板全读不出来 ⇒ 已录入的账号在纯人脸登录这条路上失效，
 * 但口令登录不受影响（本模块本来就是可选的第二种登录方式）。
 * 因此这里**不**像 pepper 那样拒绝启动 —— 可选能力的密钥缺失不该拖垮整个系统；
 * 但必须显式降级 + 留痕（见 FaceIdTemplateStore.KeyAvailable 的调用点）。
 */
public sealed class FaceIdTemplateCrypto
{
    private const string DataDirName = "AuthBaselineData";
    private const string KeyFileName = "faceid.key";
    private const int KeySize = 32;       // AES-256
    private const int TagSize = 16;
    private const int NonceSize = 12;     // GCM 推荐 96 bit

    /// <summary>
    /// DPAPI 的附加熵。与 2FA 的 `ABFace` **刻意不同**：
    /// 附加熵是"把这份密文绑定到这个用途"的标记，两把密钥若用同一份熵，
    /// 万一两个文件互换位置，解密仍然成功 —— 那会让"密钥分模块"这件事只剩字面意义。
    /// </summary>
    private static readonly byte[] Entropy =
        { (byte)'A', (byte)'B', (byte)'F', (byte)'I', (byte)'D', (byte)'1' };

    private readonly byte[]? _key;

    public FaceIdTemplateCrypto()
    {
        try
        {
            _key = LoadOrCreateKey();
            Console.WriteLine($"[FaceId] 模板加密密钥已就绪 · {KeyPath}");
        }
        catch (Exception ex)
        {
            _key = null;
            Console.WriteLine($"[FaceId] ⚠️ 模板加密密钥不可用：{ex.Message} —— "
                + "已录入的账号本机将无法用纯人脸登录（降级为口令登录，不影响口令链路）");
        }
    }

    /// <summary>密钥是否可用。false 表示**所有**模板都读不出来。</summary>
    public bool Available => _key is not null;

    public static string KeyPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        DataDirName, KeyFileName);

    private static byte[] LoadOrCreateKey()
    {
        var path = KeyPath;
        if (File.Exists(path))
        {
            var blob = File.ReadAllBytes(path);
            var plain = ProtectedData.Unprotect(blob, Entropy, DataProtectionScope.CurrentUser);
            if (plain.Length != KeySize)
                throw new CryptographicException($"密钥长度异常（{plain.Length} 字节，期望 {KeySize}）");
            return plain;
        }

        var key = RandomNumberGenerator.GetBytes(KeySize);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // 先写临时文件再原子替换：中途掉电不会留下半截密文把已有密钥毁掉。
        var tmp = path + ".tmp";
        File.WriteAllBytes(tmp, ProtectedData.Protect(key, Entropy, DataProtectionScope.CurrentUser));
        File.Move(tmp, path, overwrite: true);
        return key;
    }

    /// <summary>把特征向量加密成 (密文, nonce, tag)。</summary>
    /// <param name="aad">附加认证数据：把密文绑定到账号，使模板**不能跨账号搬运**。</param>
    public (byte[] Cipher, byte[] Nonce, byte[] Tag) Encrypt(double[] feature, string aad)
    {
        if (_key is null) throw new InvalidOperationException("FaceId 模板加密密钥不可用");
        if (feature.Length == 0) throw new ArgumentException("特征向量为空", nameof(feature));

        var plain = new byte[feature.Length * sizeof(float)];
        for (int i = 0; i < feature.Length; i++)
            BinaryPrimitives.WriteSingleLittleEndian(plain.AsSpan(i * sizeof(float)), (float)feature[i]);

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSize];
        using var gcm = new AesGcm(_key, TagSize);
        gcm.Encrypt(nonce, plain, cipher, tag, System.Text.Encoding.UTF8.GetBytes(aad));
        CryptographicOperations.ZeroMemory(plain);
        return (cipher, nonce, tag);
    }

    /// <summary>
    /// 解密。**失败返回 null**，不抛异常、更不返回"一段垃圾向量" ——
    /// 认证标签没过却硬拿去比对，会得到"看起来很低"的相似度，
    /// 于是密文篡改被伪装成一次正常的人脸不匹配。
    /// </summary>
    public double[]? Decrypt(byte[] cipher, byte[] nonce, byte[] tag, int dim, string aad)
    {
        if (_key is null) return null;
        if (dim <= 0 || cipher.Length != dim * sizeof(float)
            || nonce.Length != NonceSize || tag.Length != TagSize) return null;

        try
        {
            var plain = new byte[cipher.Length];
            using var gcm = new AesGcm(_key, TagSize);
            gcm.Decrypt(nonce, cipher, tag, plain, System.Text.Encoding.UTF8.GetBytes(aad));

            var feature = new double[dim];
            for (int i = 0; i < dim; i++)
                feature[i] = BinaryPrimitives.ReadSingleLittleEndian(plain.AsSpan(i * sizeof(float)));

            // 解出来的浮点必须有限：加密前的特征本来就有限，若这里出现 NaN/Inf，
            // 说明密文/密钥的对应关系已经不对了，宁可判"读不出来"也不要污染相似度。
            foreach (var v in feature)
                if (!double.IsFinite(v)) return null;

            CryptographicOperations.ZeroMemory(plain);
            return feature;
        }
        catch (CryptographicException)
        {
            return null;   // 密钥不符 / 密文被改动 / 跨账号搬运
        }
    }
}
