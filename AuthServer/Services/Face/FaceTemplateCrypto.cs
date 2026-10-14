using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AuthServer.Services.Face;

/**
 * 人脸模板的静态加密（AES-256-GCM）。
 *
 * ── 为什么人脸**不能**像口令那样做单向哈希 ──────────────────────────
 * 口令的验证方式决定了它可以哈希：验的时候把用户输入重算一遍，比对两个哈希。
 * 全程不需要还原原文。
 * 人脸的验证方式是**算余弦相似度**，必须把存下来的向量还原成明文才能算 ——
 * 所以人脸只能做**可逆**的静态加密。这两件事在答辩里必须分开讲：
 *
 *     口令：不可逆存储（BCrypt + pepper）
 *     人脸：可逆存储但加密（AES-GCM）
 *
 * ⚠️ 因此它的防护边界必须说清楚：**防的是"库文件被拿走"，防不了"进程被注入/调试器附加"**。
 *    文档与答辩口径都不许写成"人脸也是哈希，不可逆"。
 *
 * ── 密钥放哪、丢了会怎样 ────────────────────────────────────────
 * 密钥落 `%LOCALAPPDATA%\AuthBaselineData\face.key`，内容为 DPAPI(CurrentUser) 密文
 * —— 与 pepper.dat 同一手法、同一目录。
 *
 * 但与 pepper 有一个**刻意不同**的失败处理：
 *   pepper 丢了 ⇒ 全部口令不可验证 ⇒ 必须拒绝启动（见 PepperProvider 的注释）。
 *   人脸密钥丢了 ⇒ 只影响一个**可选**因子。此时若也拒绝启动，等于让人脸模块
 *   把整个系统拖下线；若静默失败，用户会看到一个永远过不去的第二因子而完全不知道为什么。
 *   ⇒ 采取第三条路：**明确降级 + 留痕**（见 FaceTemplateStore.IsKeyUnavailable）。
 *     代价必须承认：**密钥丢失 = 这些账号退回单因子**，且这件事会记在审计里。
 */
public sealed class FaceTemplateCrypto
{
    private const string DataDirName = "AuthBaselineData";
    private const string KeyFileName = "face.key";
    private const int KeySize = 32;       // AES-256
    private const int TagSize = 16;
    private const int NonceSize = 12;     // GCM 推荐 96 bit
    private static readonly byte[] Entropy = { (byte)'A', (byte)'B', (byte)'F', (byte)'a', (byte)'c', (byte)'e' };

    private readonly byte[]? _key;

    public FaceTemplateCrypto()
    {
        try
        {
            _key = LoadOrCreateKey();
            Console.WriteLine($"[Face] 模板加密密钥已就绪 · {KeyPath}");
        }
        catch (Exception ex)
        {
            _key = null;
            Console.WriteLine($"[Face] ⚠️ 模板加密密钥不可用：{ex.Message} —— "
                + "已录入人脸的账号本机将无法通过人脸验证（会降级为单因子并留痕）");
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
        // 先写临时文件再原子替换：中途掉电不会留下半截密文，把已有密钥毁掉。
        var tmp = path + ".tmp";
        File.WriteAllBytes(tmp, ProtectedData.Protect(key, Entropy, DataProtectionScope.CurrentUser));
        File.Move(tmp, path, overwrite: true);
        return key;
    }

    /// <summary>把特征向量加密成 (密文, nonce, tag)。</summary>
    /// <param name="aad">附加认证数据：绑定到某个账号，使密文**不能跨账号搬运**。</param>
    public (byte[] Cipher, byte[] Nonce, byte[] Tag) Encrypt(double[] feature, string aad)
    {
        if (_key is null) throw new InvalidOperationException("模板加密密钥不可用");

        var plain = new byte[feature.Length * sizeof(float)];
        for (int i = 0; i < feature.Length; i++)
            BinaryPrimitives.WriteSingleLittleEndian(plain.AsSpan(i * sizeof(float)), (float)feature[i]);

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);   // 每条模板独立随机 —— nonce 复用是 GCM 最致命的误用
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSize];
        using var gcm = new AesGcm(_key, TagSize);
        gcm.Encrypt(nonce, plain, cipher, tag, System.Text.Encoding.UTF8.GetBytes(aad));
        CryptographicOperations.ZeroMemory(plain);
        return (cipher, nonce, tag);
    }

    /// <summary>
    /// 解密。**失败返回 null 而不是抛异常，更不返回"一段垃圾向量"**。
    ///
    /// 这条边界很重要：GCM 的认证标签没通过时，如果硬把解出来的字节当成特征去做比对，
    /// 会得到一个"看起来很低"的相似度，于是**一次密文篡改被伪装成一次正常的人脸不匹配**
    /// —— 攻击者可以靠"反复篡改直到不报错"来试探。认证失败必须显式区分。
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
            CryptographicOperations.ZeroMemory(plain);
            return feature;
        }
        catch (CryptographicException)
        {
            return null;   // 密钥不符 / 密文被改动 / 跨账号搬运
        }
    }
}
