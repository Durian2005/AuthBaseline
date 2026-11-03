using AuthServer.Services.Otp;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="OtpConfirmStore"/> 的纯逻辑回归。
///
/// 这张票是"票据之外的第二把钥匙"：拿到票据不等于能做敏感操作，还要有它。
/// 所以它的三条性质都得钉死 —— 一次性、三维绑定、会过期。
///
/// 另一条容易被忽略、但对本设计特别关键的性质：**验之前先删**。
/// 在 <see cref="OtpConfirmStore.Consume"/> 里，"绑定不符"与"有效"共享同一个后果：
/// 这张票没了。若改成"不符就留着"，一张票就能被拿去把六种用途挨个试一遍，
/// 而用途恰恰是它唯一的保护维度。
/// </summary>
public class OtpConfirmStoreTests
{
    private static OtpConfirmStore Store(int ttlSeconds = 120, Func<long>? clock = null) =>
        new(new OtpOptions { ConfirmTtlSeconds = ttlSeconds }, clock);

    /// <summary>签发 → 消费：绑定三维全对时通过。</summary>
    [Fact(DisplayName = "签发后消费：三维全对则通过")]
    public void IssueThenConsume_Ok()
    {
        var store = Store();
        var (token, ttl) = store.Issue("u1", OtpConfirmPurpose.FaceEnroll, "alice");

        Assert.Equal(120, ttl);
        Assert.False(string.IsNullOrWhiteSpace(token));

        Assert.Equal(OtpConfirmStatus.Ok,
            store.Consume(token, "u1", OtpConfirmPurpose.FaceEnroll, "alice"));
    }

    /// <summary>一次性：同一张票第二次消费一律不存在。</summary>
    [Fact(DisplayName = "一次性：同一张票第二次消费失败")]
    public void Consume_Twice_SecondIsNotFound()
    {
        var store = Store();
        var (token, _) = store.Issue("u1", OtpConfirmPurpose.FaceDelete, "alice");

        Assert.Equal(OtpConfirmStatus.Ok,
            store.Consume(token, "u1", OtpConfirmPurpose.FaceDelete, "alice"));
        Assert.Equal(OtpConfirmStatus.NotFound,
            store.Consume(token, "u1", OtpConfirmPurpose.FaceDelete, "alice"));
    }

    /// <summary>别人的票不能用 —— 而且一用就废，不能还给原主。</summary>
    [Fact(DisplayName = "归属不符：别人的票既不能用、也不能再还给原主")]
    public void Consume_OtherOwner_FailsAndBurns()
    {
        var store = Store();
        var (token, _) = store.Issue("u1", OtpConfirmPurpose.SetRole, "bob");

        Assert.Equal(OtpConfirmStatus.OwnerMismatch,
            store.Consume(token, "u2", OtpConfirmPurpose.SetRole, "bob"));

        // 关键：被旁人试过一次之后，原主也不能用了（验之前先删）。
        Assert.Equal(OtpConfirmStatus.NotFound,
            store.Consume(token, "u1", OtpConfirmPurpose.SetRole, "bob"));
    }

    /// <summary>用途不符：拿"录人脸"的票去删人脸必须被拒，且票作废。</summary>
    [Fact(DisplayName = "用途不符：拒绝并作废（防止一张票被逐项试错）")]
    public void Consume_WrongPurpose_FailsAndBurns()
    {
        var store = Store();
        var (token, _) = store.Issue("u1", OtpConfirmPurpose.FaceEnroll, "alice");

        Assert.Equal(OtpConfirmStatus.PurposeMismatch,
            store.Consume(token, "u1", OtpConfirmPurpose.FaceDelete, "alice"));

        Assert.Equal(OtpConfirmStatus.NotFound,
            store.Consume(token, "u1", OtpConfirmPurpose.FaceEnroll, "alice"));
    }

    /// <summary>目标不符：给 alice 的确认不能拿去操作 bob（最典型的是"提权重放"）。</summary>
    [Fact(DisplayName = "目标不符：拒绝并作废")]
    public void Consume_WrongTarget_FailsAndBurns()
    {
        var store = Store();
        var (token, _) = store.Issue("u1", OtpConfirmPurpose.SetRole, "alice");

        Assert.Equal(OtpConfirmStatus.TargetMismatch,
            store.Consume(token, "u1", OtpConfirmPurpose.SetRole, "bob"));

        Assert.Equal(OtpConfirmStatus.NotFound,
            store.Consume(token, "u1", OtpConfirmPurpose.SetRole, "alice"));
    }

    /// <summary>过期：TTL 之后即使三维全对也必须失效。</summary>
    [Fact(DisplayName = "过期：TTL 之后不再有效")]
    public void Consume_AfterTtl_IsNotFound()
    {
        long now = 1_000;
        var store = Store(ttlSeconds: 120, clock: () => now);
        var (token, _) = store.Issue("u1", OtpConfirmPurpose.CreateAccount, "newbie");

        now += 119_000;   // 还差 1 秒
        Assert.Equal(OtpConfirmStatus.Ok,
            store.Consume(token, "u1", OtpConfirmPurpose.CreateAccount, "newbie"));

        var (token2, _) = store.Issue("u1", OtpConfirmPurpose.CreateAccount, "newbie");
        now += 121_000;   // 越过 120 秒
        Assert.Equal(OtpConfirmStatus.NotFound,
            store.Consume(token2, "u1", OtpConfirmPurpose.CreateAccount, "newbie"));
    }

    /// <summary>空 / 乱码 token 一律按"不存在"处理，且不能抛异常（这是匿名可达路径的邻座）。</summary>
    [Theory(DisplayName = "空或乱码 token：一律 NotFound")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-real-token")]
    public void Consume_GarbageToken_IsNotFound(string? token)
    {
        var store = Store();
        Assert.Equal(OtpConfirmStatus.NotFound,
            store.Consume(token, "u1", OtpConfirmPurpose.FaceEnroll, "alice"));
    }

    /// <summary>未知用途在**签发时**就拒绝：签出来谁也用不上，而调用方会以为它有效。</summary>
    [Theory(DisplayName = "未知用途：签发即抛")]
    [InlineData("")]
    [InlineData("face-enroll ")]   // 尾随空格也算不同值，不做宽容匹配
    [InlineData("delete-everything")]
    public void Issue_UnknownPurpose_Throws(string purpose)
    {
        var store = Store();
        Assert.Throws<ArgumentException>(() => store.Issue("u1", purpose, "alice"));
    }

    /// <summary>token 必须是随机且足够长：可预测就等于没有这张票。</summary>
    [Fact(DisplayName = "token：两次签发不同，长度足够")]
    public void Issue_TokensAreRandomAndLong()
    {
        var store = Store();
        var (a, _) = store.Issue("u1", OtpConfirmPurpose.FaceEnroll, "alice");
        var (b, _) = store.Issue("u1", OtpConfirmPurpose.FaceEnroll, "alice");

        Assert.NotEqual(a, b);
        // 32 字节 → base64url 43 个字符（去掉填充）
        Assert.Equal(43, a.Length);
        Assert.DoesNotContain('=', a);
        Assert.DoesNotContain('+', a);
        Assert.DoesNotContain('/', a);
    }

    /// <summary>
    /// 上限：这张表可以被"有票据 + 有链值"的人主动填充，所以必须有界。
    /// 淘汰的是最早签发的那张（它最可能已经过期），最新的一张必须还在。
    /// </summary>
    [Fact(DisplayName = "上限：超出后淘汰最早的，最新的仍可用")]
    public void Issue_BeyondCap_EvictsOldest()
    {
        long now = 0;
        var store = Store(clock: () => now);

        string first = string.Empty, last = string.Empty;
        for (var i = 0; i < 513; i++)
        {
            now += 1;   // 保证 CreatedAtMs 严格递增，淘汰顺序才确定
            var (token, _) = store.Issue("u1", OtpConfirmPurpose.FaceEnroll, "alice");
            if (i == 0) first = token;
            last = token;
        }

        Assert.Equal(512, store.Count);
        Assert.Equal(OtpConfirmStatus.NotFound,
            store.Consume(first, "u1", OtpConfirmPurpose.FaceEnroll, "alice"));
        Assert.Equal(OtpConfirmStatus.Ok,
            store.Consume(last, "u1", OtpConfirmPurpose.FaceEnroll, "alice"));
    }

    /// <summary>用途白名单本身也要对：六个常量都在清单里，且没有重复。</summary>
    [Fact(DisplayName = "用途白名单：六个都在、无重复")]
    public void PurposeWhitelist_IsCompleteAndDistinct()
    {
        Assert.Equal(6, OtpConfirmPurpose.All.Length);
        Assert.Equal(6, OtpConfirmPurpose.All.Distinct(StringComparer.Ordinal).Count());

        foreach (var p in OtpConfirmPurpose.All)
            Assert.True(OtpConfirmPurpose.IsKnown(p), p);
    }
}
