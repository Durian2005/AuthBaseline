using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services.Otp;

/**
 * 挑战签名：密钥保管 + HMAC-SHA256 原语。
 *
 * ── 它防的是「小数攻击」────────────────────────────────────────
 * S/KEY 的经典攻击：中间人截获服务端下发的挑战，把**迭代值 / 期望下标 k 改小**，
 * 客户端于是算出一个更靠前的格 `x_k'`；攻击者拿到后正向哈希 `k - k'` 次，
 * 既得到本次可用的 `x_k`，还顺带握住后续若干格 —— 可以在很长一段时间里冒充用户。
 *
 * ── 为什么服务端自己验不了，必须客户端验 ───────────────────────
 * 攻击者提交的 `x_k` 是**真的**（它自己正向算出来的），`H(x_k) == v` 完全成立。
 * 服务端没有任何信息能分辨"这一格是客户端按被篡改的 k 算的"还是"按真 k 算的"。
 * 所以防御点只能在客户端：它在动笔算之前，必须确认 `k` 确实是服务端签发的。
 *
 * ── 为什么是对称密钥，而不是签名密钥对 ─────────────────────────
 * 非对称方案要求公钥**不可替换地**内置进客户端二进制 —— 而本仓库是公开的，
 * 私钥无处安放（每次安装现生成则公钥又变不了）。客户端与 sidecar 同机，
 * 共享一份本机配对密钥是最小代价的做法。
 *
 * ── 这份密钥不是「用户的秘密」──────────────────────────────────
 * 它只服务于「本机客户端 ↔ 本机 sidecar」这一对：重装或换机时在新机器上重新生成，
 * 客户端读到的也是新密钥，自动一致。因此不破坏「客户端不存任何用户秘密、换机可用」。
 */
public sealed class OtpChallengeKey
{
    /// <summary>DPAPI 附加熵。与 2FA / FaceId 的密钥**刻意不同**：三类密钥不可互相顶替。</summary>
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("AuthBaseline.OtpChallenge.v1");

    private const int KeyLength = 32;

    private readonly byte[] _key;

    /// <summary>密钥文件位置（DPAPI·CurrentUser 封装）。Rust 侧读的是同一个文件。</summary>
    public static string KeyPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "AuthBaselineData", "otp-challenge.key");

    public OtpChallengeKey() : this(null) { }

    /// <summary>
    /// 测试用：直接给定密钥，**不落盘**。
    /// 单测若走默认构造会真的去建 DPAPI 文件 —— 那既污染开发机，也让用例依赖操作系统。
    /// </summary>
    public OtpChallengeKey(byte[]? keyOverride)
    {
        if (keyOverride is not null)
        {
            if (keyOverride.Length != KeyLength)
                throw new ArgumentException($"配对密钥必须是 {KeyLength} 字节", nameof(keyOverride));
            _key = keyOverride.ToArray();
            return;
        }

        _key = LoadOrCreate();
    }

    /// <summary>启动日志用：只打印指纹，绝不打印密钥本体。</summary>
    public string Fingerprint => Convert.ToHexString(SHA256.HashData(_key))[..16].ToLowerInvariant();

    /// <summary>签名一张挑战。payload 见 <see cref="Payload"/>。</summary>
    public string Sign(string username, string r, int k, int n) => Sign(_key, username, r, k, n);

    /// <summary>纯函数版本，供单测与将来可能的多密钥场景使用。</summary>
    public static string Sign(byte[] key, string username, string r, int k, int n)
    {
        using var hmac = new HMACSHA256(key);
        var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(Payload(username, r, k, n)));
        return Base64Url(mac);
    }

    /// <summary>
    /// 签名覆盖的字符串：<c>hex(SHA256(username)) | r | k | n</c>。
    ///
    /// 用户名**先取摘要**再拼接，是为了消除分隔符歧义：用户名若含 <c>|</c> 或换行，
    /// 直接拼会让 <c>("a|b", "c")</c> 与 <c>("a", "b|c")</c> 得到同一段输入。
    /// 摘要定长 64 个 hex 字符，不存在这个问题。Rust 侧必须逐字复现这一段。
    /// </summary>
    public static string Payload(string username, string r, int k, int n)
    {
        var nameDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(username))).ToLowerInvariant();
        return $"{nameDigest}|{r}|{k}|{n}";
    }

    /// <summary>Base64Url（去填充）。与挑战 token 同一套编码，见 <see cref="OtpChallengeStore"/>。</summary>
    internal static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// 读现有密钥；不存在则生成并原子落盘。
    ///
    /// 写临时文件再 <c>Move</c>：直接写目标路径时若是半截崩溃，留下的坏文件会让**下次启动**
    /// 直接失败，且用户看到的只是"登录不了"。原子替换把这个窗口收成零。
    /// </summary>
    private static byte[] LoadOrCreate()
    {
        var path = KeyPath;
        if (File.Exists(path))
        {
            var blob = File.ReadAllBytes(path);
            var plain = ProtectedData.Unprotect(blob, Entropy, DataProtectionScope.CurrentUser);
            if (plain.Length != KeyLength)
                throw new InvalidOperationException(
                    $"挑战签名密钥长度异常（{plain.Length} 字节，期望 {KeyLength}）：{path}");
            return plain;
        }

        var dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);

        var key = RandomNumberGenerator.GetBytes(KeyLength);
        var protectedBlob = ProtectedData.Protect(key, Entropy, DataProtectionScope.CurrentUser);
        var tmp = path + ".tmp";
        File.WriteAllBytes(tmp, protectedBlob);
        File.Move(tmp, path, overwrite: true);

        return key;
    }
}
