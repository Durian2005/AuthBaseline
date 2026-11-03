using AuthServer.Services.Otp;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="OtpChallengeStore"/> 的纯逻辑回归。
///
/// 这个类整个活在内存里（`ConcurrentDictionary`），所以它是本项目里少数
/// "既有状态、又能离线单测"的组件 —— 不需要 Mongo、不需要起后端。
///
/// 钉住的四条语义，每一条都对应一个会被真实攻击或真实事故打到的点：
///   ① **一次性**：用过的票不能再用来试第二格（否则"错了再试"就有了免费重试通道）；
///   ② **TTL**：过期必须失效（否则"十分钟前算好的格"可以一直用）；
///   ③ **归属**：票只属于签发时那个用户名（否则 A 的票能被搬去 B）；
///   ④ **有上限**：匿名端点可以被无限刷，没有上限就是一条打爆内存的路径。
/// </summary>
public class OtpChallengeStoreTests
{
    private static OtpChallengeStore Store(int ttlSeconds = 120) =>
        new(new OtpOptions { ChallengeTtlSeconds = ttlSeconds });

    /// <summary>签发 → 消费：拿回签发时绑定的用户名，且不报错。</summary>
    [Fact(DisplayName = "签发后消费一次：返回绑定的用户名")]
    public void IssueThenConsume_ReturnsBoundUsername()
    {
        var store = Store();
        var (token, ttl) = store.Issue("alice");

        Assert.Equal(120, ttl);
        Assert.False(string.IsNullOrWhiteSpace(token));

        var (username, error) = store.Consume(token);

        Assert.Null(error);
        Assert.Equal("alice", username);
    }

    /// <summary>同一张票不能用第二次 —— 无论第一次成功还是失败。</summary>
    [Fact(DisplayName = "一次性：同一张票第二次消费失败")]
    public void Consume_Twice_SecondFails()
    {
        var store = Store();
        var (token, _) = store.Issue("alice");

        Assert.Null(store.Consume(token).Error);
        var second = store.Consume(token);

        Assert.Equal(OtpChallengeError.Invalid, second.Error);
        Assert.Null(second.Username);
    }

    /// <summary>消费后记录必须真的被删掉（探针用 PendingCount 证明"没有残留"）。</summary>
    [Fact(DisplayName = "消费即删除：PendingCount 归零")]
    public void Consume_RemovesRecord()
    {
        var store = Store();
        var (token, _) = store.Issue("alice");
        Assert.Equal(1, store.PendingCount);

        store.Consume(token);
        Assert.Equal(0, store.PendingCount);

        // 过期的那次消费同样要把它从字典里摘掉，不能留给 Prune 之外的路径。
        var expired = Store(ttlSeconds: 0);
        var (token2, _) = expired.Issue("bob");
        Assert.Equal(OtpChallengeError.Invalid, expired.Consume(token2).Error);
        Assert.Equal(0, expired.PendingCount);
    }

    /// <summary>TTL 已到 ⇒ 失效（用 TTL=0 让这条分支可确定地走到）。</summary>
    [Fact(DisplayName = "过期：TTL 到点即失效")]
    public void Consume_AfterTtl_Fails()
    {
        var store = Store(ttlSeconds: 0);
        var (token, _) = store.Issue("alice");

        var (username, error) = store.Consume(token);

        Assert.Equal(OtpChallengeError.Invalid, error);
        Assert.Null(username);
    }

    /// <summary>空 / 空白 / 乱码一律按"挑战无效"，不抛异常（外部输入）。</summary>
    [Theory(DisplayName = "畸形 token：统一回挑战无效")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-real-token")]
    public void Consume_MalformedToken_ReturnsInvalid(string? token)
    {
        var store = Store();
        var (username, error) = store.Consume(token);

        Assert.Equal(OtpChallengeError.Invalid, error);
        Assert.Null(username);
    }

    /// <summary>两账号互不串票：A 的票消费出来只能是 A。</summary>
    [Fact(DisplayName = "归属：两张票各归各的用户名")]
    public void Issue_TwoUsers_AreIndependent()
    {
        var store = Store();
        var a = store.Issue("alice").Token;
        var b = store.Issue("bob").Token;

        Assert.Equal("bob", store.Consume(b).Username);
        Assert.Equal("alice", store.Consume(a).Username);
    }

    /// <summary>前后空白容忍（前端拼串容易带空格），但内容仍须完全一致。</summary>
    [Fact(DisplayName = "token 允许前后空白")]
    public void Consume_TrimsWhitespace()
    {
        var store = Store();
        var (token, _) = store.Issue("alice");

        Assert.Equal("alice", store.Consume("  " + token + "  ").Username);
    }

    /// <summary>
    /// 未消费挑战数有上限：匿名端点被洪泛时，内存不能跟着请求数线性涨。
    /// 只断言"被压在上限内" —— 淘汰谁由签发时间决定，测试不去锁死这个细节。
    /// </summary>
    [Fact(DisplayName = "上限：洪泛签发不会让记录数无限增长")]
    public void Issue_Many_StaysBounded()
    {
        var store = Store();

        for (var i = 0; i < 1200; i++)
            store.Issue($"flood-{i}");

        Assert.True(store.PendingCount <= 512, $"未消费挑战数应被压在上限内，实际 {store.PendingCount}");
    }
}
