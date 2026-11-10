using System.Linq;
using AuthServer.Services.Otp;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// 挑战签名的回归（防「小数攻击」）。
///
/// 这些用例钉住的不是"某个函数能跑"，而是**一条协议契约**：客户端与 Rust 侧
/// 必须算出逐字节相同的 MAC。一旦两边分叉，表现是"所有挑战都被判成伪造" ——
/// 登录全线失败，而服务端日志里只有一片 401，看不出根因。
///
/// 所以在两个语言里放同一组固定向量是本文件存在的主要理由：
/// 期望值由 Python 的 `hmac.new(key, payload, sha256)` 独立算出，
/// C# 与 Rust 各断言一次，任何一侧改动了编码方式都会在这里立刻断掉。
/// </summary>
public class OtpChallengeKeyTests
{
    /// <summary>0x00..0x1F：与 Rust 侧 `(0u8..32).collect()` 完全一致。</summary>
    private static readonly byte[] FixedKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    private const string Seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    /// <summary>固定向量：payload 与 proof 都必须与 Rust / Python 逐字相同。</summary>
    [Fact(DisplayName = "挑战签名：与 Rust / Python 三方对齐的固定向量")]
    public void Sign_MatchesCrossImplementationVector()
    {
        Assert.Equal(
            "2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90"
            + "|" + Seed + "|3|5",
            OtpChallengeKey.Payload("alice", Seed, 3, 5));

        Assert.Equal(
            "R99WOoCTqdTQTwMrI-C2LExKsKCz7ltVz2sYA7e_NyU",
            OtpChallengeKey.Sign(FixedKey, "alice", Seed, 3, 5));
    }

    /// <summary>
    /// 小数攻击的核心判据：把 <c>k</c> 改小，签名必须变。
    ///
    /// 攻击者要的正是"更靠前的一格"（<c>k</c> 更小），所以 <c>k</c> 必须在被签名
    /// 覆盖的字段里 —— 而且不是"看起来不同"，是 MAC 不同：攻击者没有配对密钥，
    /// 改完重签不出来。
    /// </summary>
    [Fact(DisplayName = "小数攻击：k 改小后签名不匹配")]
    public void Sign_ChangesWhenKIsTampered()
    {
        var genuine = OtpChallengeKey.Sign(FixedKey, "alice", Seed, 3, 5);

        Assert.NotEqual(genuine, OtpChallengeKey.Sign(FixedKey, "alice", Seed, 1, 5));
        Assert.Equal(
            "cgS7GTS11Dc6_oPq81yEibCLbhvHJhMAy0xZ5QHDv4g",
            OtpChallengeKey.Sign(FixedKey, "alice", Seed, 1, 5));
    }

    /// <summary>链长、种子、用户名同样在被签名覆盖的字段里。</summary>
    [Fact(DisplayName = "改 n / 改种子 / 换用户名都会让签名失效")]
    public void Sign_CoversEverySignedField()
    {
        var genuine = OtpChallengeKey.Sign(FixedKey, "alice", Seed, 3, 5);

        Assert.NotEqual(genuine, OtpChallengeKey.Sign(FixedKey, "alice", Seed, 3, 9));
        Assert.NotEqual(genuine,
            OtpChallengeKey.Sign(FixedKey, "alice", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXQ", 3, 5));
        Assert.NotEqual(genuine, OtpChallengeKey.Sign(FixedKey, "bob", Seed, 3, 5));
    }

    /// <summary>换一把密钥就签不出同一张挑战 —— 否则"本机配对密钥"等于没有。</summary>
    [Fact(DisplayName = "换密钥即无法复现签名")]
    public void Sign_DependsOnKey()
    {
        var other = FixedKey.ToArray();
        other[0] ^= 0xFF;

        Assert.NotEqual(
            OtpChallengeKey.Sign(FixedKey, "alice", Seed, 3, 5),
            OtpChallengeKey.Sign(other, "alice", Seed, 3, 5));
    }

    /// <summary>
    /// 用户名先取摘要再拼接，是为了消除分隔符歧义：
    /// 若直接拼，("a|b", "c") 与 ("a", "b|c") 会得到同一段签名输入。
    /// </summary>
    [Fact(DisplayName = "用户名含分隔符不产生签名歧义")]
    public void Payload_IsNotAmbiguousWhenUsernameContainsSeparator()
    {
        var left = OtpChallengeKey.Payload("a|b", Seed, 3, 5);
        var right = OtpChallengeKey.Payload("a", "b|c", 3, 5);

        Assert.NotEqual(left, right);
    }

    /// <summary>同一组输入必须永远得到同一个 proof（HMAC 是确定性的）。</summary>
    [Fact(DisplayName = "签名是确定性的")]
    public void Sign_IsDeterministic()
    {
        Assert.Equal(
            OtpChallengeKey.Sign(FixedKey, "alice", Seed, 3, 5),
            OtpChallengeKey.Sign(FixedKey, "alice", Seed, 3, 5));
    }

    /// <summary>
    /// 签发的挑战必须带 proof，且与用同一密钥独立算出的值一致 ——
    /// 这条把"签发"与"签名原语"绑在一起，防止将来有人改了 Issue 却忘了签名。
    /// </summary>
    [Fact(DisplayName = "签发的挑战带 proof，且与独立复算一致")]
    public void Issue_ReturnsProofMatchingIndependentComputation()
    {
        var signer = new OtpChallengeKey(FixedKey);
        var store = new OtpChallengeStore(new OtpOptions(), signer);

        var (token, proof, ttl) = store.Issue("alice", Seed, 3, 5);

        Assert.False(string.IsNullOrWhiteSpace(token));
        Assert.Equal(120, ttl);
        Assert.Equal(OtpChallengeKey.Sign(FixedKey, "alice", Seed, 3, 5), proof);
    }

    /// <summary>
    /// 假参数（无链账号）也必须签出非空 proof。
    /// 否则"proof 是否为空"就成了比 token 更好用的存在性判据，防枚举等于白做。
    /// </summary>
    [Fact(DisplayName = "假参数同样签出 proof（防枚举不被破坏）")]
    public void Issue_SignsFakeParametersToo()
    {
        var store = new OtpChallengeStore(new OtpOptions(), new OtpChallengeKey(FixedKey));

        var (_, realProof, _) = store.Issue("alice", Seed, 3, 5);
        var (_, fakeProof, _) = store.Issue("no-such-user", OtpChainStore.NewSeed(), 42, 1000);

        Assert.False(string.IsNullOrWhiteSpace(realProof));
        Assert.False(string.IsNullOrWhiteSpace(fakeProof));
        Assert.NotEqual(realProof, fakeProof);
    }
}
