using AuthServer.Services.Otp;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="OtpReconfirmThrottle"/> 的纯逻辑回归。
///
/// 这个类是"再认证失败不计入登录失败计数"与"再认证不能无节流"这两条要求
/// 同时成立的地方。所以用例分成两组：
///   A 组 · 它**确实**会封（否则就是一条在线口令爆破通道）；
///   B 组 · 它**只**封这条路（封禁不影响别的、也不会因为零散失败累积误封）。
///
/// 时间一律注入假时钟，不 sleep —— 一个要等 5 分钟的用例等于没有用例。
/// </summary>
public class OtpReconfirmThrottleTests
{
    /// <summary>A 组：连续 5 次失败才封，第 4 次仍放行（留出"客户端算错一次"的余量）。</summary>
    [Fact(DisplayName = "连续失败 5 次才封：第 4 次仍放行")]
    public void FiveFailures_Blocks()
    {
        long now = 0;
        var t = new OtpReconfirmThrottle(() => now);

        for (var i = 0; i < OtpReconfirmThrottle.MaxFailures - 1; i++)
        {
            t.OnFailure("u1");
            Assert.False(t.Check("u1").Blocked, $"第 {i + 1} 次失败时不该封");
        }

        t.OnFailure("u1");
        var (blocked, retryAfter) = t.Check("u1");

        Assert.True(blocked);
        Assert.Equal((int)OtpReconfirmThrottle.Cooldown.TotalSeconds, retryAfter);
    }

    /// <summary>A 组：封禁期内剩余秒数随时间递减 —— 客户端据此显示"还需等 N 秒"。</summary>
    [Fact(DisplayName = "封禁剩余秒数随时间递减")]
    public void BlockedRemaining_CountsDown()
    {
        long now = 0;
        var t = new OtpReconfirmThrottle(() => now);

        for (var i = 0; i < OtpReconfirmThrottle.MaxFailures; i++) t.OnFailure("u1");

        now += 60_000;   // 过了 1 分钟
        var (blocked, retryAfter) = t.Check("u1");

        Assert.True(blocked);
        Assert.Equal(240, retryAfter);
    }

    /// <summary>A 组：封禁到期自动解除，无需任何清理动作。</summary>
    [Fact(DisplayName = "封禁到期自动解除")]
    public void Block_Expires()
    {
        long now = 0;
        var t = new OtpReconfirmThrottle(() => now);

        for (var i = 0; i < OtpReconfirmThrottle.MaxFailures; i++) t.OnFailure("u1");
        Assert.True(t.Check("u1").Blocked);

        now += (long)OtpReconfirmThrottle.Cooldown.TotalMilliseconds + 1;
        Assert.False(t.Check("u1").Blocked);
    }

    /// <summary>B 组：成功一次即清零 —— 已证明过自己的人不该继续背旧账。</summary>
    [Fact(DisplayName = "成功清零：4 次失败 + 成功 + 4 次失败仍不封")]
    public void Success_ResetsCounter()
    {
        long now = 0;
        var t = new OtpReconfirmThrottle(() => now);

        for (var i = 0; i < OtpReconfirmThrottle.MaxFailures - 1; i++) t.OnFailure("u1");
        t.OnSuccess("u1");
        for (var i = 0; i < OtpReconfirmThrottle.MaxFailures - 1; i++) t.OnFailure("u1");

        Assert.False(t.Check("u1").Blocked);
    }

    /// <summary>B 组：窗口过期后重新计数，零散的失败不会攒成一次误封。</summary>
    [Fact(DisplayName = "窗口过期：零散失败不累积成封禁")]
    public void Window_Expiry_ResetsCounter()
    {
        long now = 0;
        var t = new OtpReconfirmThrottle(() => now);

        for (var i = 0; i < OtpReconfirmThrottle.MaxFailures - 1; i++) t.OnFailure("u1");

        now += (long)OtpReconfirmThrottle.Window.TotalMilliseconds + 1;
        for (var i = 0; i < OtpReconfirmThrottle.MaxFailures - 1; i++) t.OnFailure("u1");

        Assert.False(t.Check("u1").Blocked);
    }

    /// <summary>B 组：封的是人，不是系统 —— 一个人被封不影响另一个人。</summary>
    [Fact(DisplayName = "按账号隔离：A 被封不影响 B")]
    public void Block_IsPerUser()
    {
        long now = 0;
        var t = new OtpReconfirmThrottle(() => now);

        for (var i = 0; i < OtpReconfirmThrottle.MaxFailures; i++) t.OnFailure("u1");

        Assert.True(t.Check("u1").Blocked);
        Assert.False(t.Check("u2").Blocked);
    }

    /// <summary>从没失败过的账号永远是放行的（不能因为"没有记录"就当"被封"）。</summary>
    [Fact(DisplayName = "未知账号：默认放行")]
    public void UnknownUser_IsNotBlocked()
    {
        var t = new OtpReconfirmThrottle(() => 0);
        Assert.False(t.Check("never-seen").Blocked);
        Assert.Equal(0, t.TrackedUsers);
    }

    /// <summary>参数自检：窗口与封禁时长都必须为正，否则节流形同虚设。</summary>
    [Fact(DisplayName = "参数：窗口与封禁时长为正")]
    public void Constants_AreSane()
    {
        Assert.True(OtpReconfirmThrottle.MaxFailures >= 3);
        Assert.True(OtpReconfirmThrottle.Window > TimeSpan.Zero);
        Assert.True(OtpReconfirmThrottle.Cooldown > TimeSpan.Zero);
    }
}
