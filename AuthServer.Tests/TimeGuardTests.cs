using AuthServer.Models;
using AuthServer.Services;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="TimeGuard"/> 的纯逻辑回归。
///
/// 这些用例不是"凭空设计的边界"，而是把 <c>tools/lockout_clock_probe.py</c> 里
/// 那 40 项端到端断言中**与 IO 无关的判定语义**抽出来固化成单测。
///
/// 为什么两套都要留（这不是重复劳动）：
///   · 探针证明的是"整条链路在真实后端上确实这么表现"—— 它需要起进程、打 HTTP、读库，
///     慢、且只能在 Windows + Mongo 的机器上跑；
///   · 单测证明的是"判定函数本身对任意输入都这么算"—— 毫秒级、可在 CI 跑，
///     而且能覆盖**探针造不出来的场景**（例如精确落在容差边界上的 2 秒背离：
///     真实拨钟不可能恰好拨 2 秒，但判定式必须对它有确定结论）。
///
/// ⚠️ 单测全部走"传入墙钟 / 运行时长"的纯函数重载，**不读系统时钟** ——
/// 否则测试结果会随机器状态漂移，尤其是 TimeGuard 自己就是拿来对抗时钟异常的。
/// </summary>
public class TimeGuardTests
{
    /// <summary>所有用例共用的墙钟锚点（锁定发生的那一刻）。</summary>
    private static readonly DateTime T0 = new(2026, 10, 17, 2, 0, 0, DateTimeKind.Utc);

    /// <summary>锁定发生时的系统运行时长（毫秒）。具体数值无关，只要求后续采样不小于它。</summary>
    private const long U0 = 500_000;

    private static readonly TimeSpan LockDuration = TimeSpan.FromSeconds(180);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(3);

    /// <summary>锁定记录的终点：锚点 + 3 分钟。</summary>
    private static DateTime LockEnd => T0 + LockDuration;

    // ────────────────────────────────────────── 一、锁定到期判定

    /// <summary>
    /// 老数据退路：没有单调锚点时必须**完全按墙钟**判定，与加固前逐字一致。
    /// 这条不是"顺手加的兼容"，而是安全边界 —— 加固不能把改造前就锁上的账号永久锁在门外。
    /// </summary>
    [Fact(DisplayName = "无单调锚点（老记录）⇒ 退回墙钟判定")]
    public void Assess_WithoutAnchors_FallsBackToWallClock()
    {
        var stillLocked = TimeGuard.Assess(LockEnd, null, null, T0.AddSeconds(30), U0 + 30_000);
        Assert.True(stillLocked.Locked);
        Assert.Equal(150, stillLocked.RemainingSeconds);
        Assert.Equal(ClockDrift.None, stillLocked.Drift);
        Assert.Equal(T0.AddSeconds(30), stillLocked.ReliableNow);

        var expired = TimeGuard.Assess(LockEnd, null, null, T0.AddSeconds(200), U0 + 200_000);
        Assert.False(expired.Locked);
        Assert.Equal(0, expired.RemainingSeconds);
    }

    /// <summary>锚点齐全、两条时间线一致 ⇒ 不报背离，按墙钟算剩余。</summary>
    [Fact(DisplayName = "两条时间线一致 ⇒ 无背离，按墙钟算剩余")]
    public void Assess_ConsistentClocks_NoDrift()
    {
        var v = TimeGuard.Assess(LockEnd, T0, U0, T0.AddSeconds(30), U0 + 30_000);
        Assert.True(v.Locked);
        Assert.Equal(150, v.RemainingSeconds);
        Assert.Equal(ClockDrift.None, v.Drift);
        Assert.Equal(0, v.DriftSeconds);
    }

    /// <summary>
    /// 核心结论：墙钟被前拨 10 分钟 ⇒ 必须**仍然锁定**，且剩余秒数按真实过去的时间算。
    /// 这是整个 TimeGuard 存在的理由，也是探针断言 13/14 的单测版。
    /// </summary>
    [Fact(DisplayName = "墙钟前拨 600 秒 ⇒ 仍锁定，剩余按单调线算")]
    public void Assess_ClockRolledForward_StaysLocked()
    {
        // 真实只过了 30 秒，但墙钟声称过了 630 秒。
        var v = TimeGuard.Assess(LockEnd, T0, U0, T0.AddSeconds(630), U0 + 30_000);

        Assert.True(v.Locked);
        Assert.Equal(ClockDrift.Forward, v.Drift);
        Assert.Equal(600, v.DriftSeconds);
        // 按墙钟读法早就该解锁了（这是"加固前"的行为，用一条断言把对照写死）。
        Assert.True(LockEnd < T0.AddSeconds(630));
        // 实际采信单调线 ⇒ 剩余 150 秒，而不是 0。
        Assert.Equal(150, v.RemainingSeconds);
        Assert.Equal(T0.AddSeconds(30), v.ReliableNow);
    }

    /// <summary>
    /// 回拨方向：本就不能解锁，但也**不能把锁定拖长**。
    /// 这条区分了"fail-closed 但不误伤" —— 回拨常见于主板电池耗尽 / 虚拟机快照回滚，
    /// 若按墙钟算，一次 3 分钟的锁定会被拖成几小时。
    /// </summary>
    [Fact(DisplayName = "墙钟回拨 3600 秒 ⇒ 仍锁定，且不把锁定拖长")]
    public void Assess_ClockRolledBackward_KeepsLockButNotLonger()
    {
        var v = TimeGuard.Assess(LockEnd, T0, U0, T0.AddSeconds(30 - 3600), U0 + 30_000);

        Assert.True(v.Locked);
        Assert.Equal(ClockDrift.Backward, v.Drift);
        Assert.Equal(-3600, v.DriftSeconds);   // 墙钟现在 - 单调线推算的现在 == -3600 秒
        Assert.Equal(150, v.RemainingSeconds); // 不是 3630
    }

    /// <summary>
    /// 重启边界：运行时长比锚点还小 ⇒ 单调线断了一截 ⇒ 退回墙钟。
    /// 此时前拨**确实可以**解锁。这是已知边界，用断言写明而不是靠注释承诺。
    /// </summary>
    [Fact(DisplayName = "运行时长回退（重启）⇒ 退回墙钟，前拨仍可解锁（已知边界）")]
    public void Assess_UptimeRegression_FallsBackAndCanBeBypassed()
    {
        var v = TimeGuard.Assess(LockEnd, T0, U0, T0.AddSeconds(600), 1_000);

        Assert.Equal(ClockDrift.None, v.Drift);
        Assert.False(v.Locked);   // 已知边界：重启后锚点失效
        Assert.Equal(0, v.RemainingSeconds);
    }

    /// <summary>
    /// 容差边界必须**确定性**：正好 2 秒不算背离，2 秒零 1 毫秒才算。
    /// 探针造不出这么精确的拨钟，只有单测能钉住。
    /// </summary>
    [Theory(DisplayName = "背离容差边界")]
    [InlineData(2, ClockDrift.None, 148)]      // 恰好 2 秒：不报背离
    [InlineData(3, ClockDrift.Forward, 150)]   // 越过 2 秒：报前拨，采信单调线
    public void Assess_DriftToleranceBoundary(int driftSeconds, ClockDrift expected, int expectedRemaining)
    {
        var v = TimeGuard.Assess(LockEnd, T0, U0, T0.AddSeconds(30 + driftSeconds), U0 + 30_000);
        Assert.Equal(expected, v.Drift);
        Assert.Equal(expectedRemaining, v.RemainingSeconds);
        Assert.True(v.Locked);
    }

    /// <summary>剩余秒数向上取整：还剩 0.4 秒时要显示 1，不能显示 0 却仍拒绝登录。</summary>
    [Fact(DisplayName = "剩余秒数向上取整（0.4 秒 ⇒ 1）")]
    public void Assess_RemainingSecondsRoundsUp()
    {
        var lockEnd = T0.AddSeconds(180).AddMilliseconds(400);
        var v = TimeGuard.Assess(lockEnd, T0, U0, T0.AddSeconds(30), U0 + 30_000);
        Assert.True(v.Locked);
        Assert.Equal(151, v.RemainingSeconds);
    }

    /// <summary>锁定终点恰好等于"现在" ⇒ 已解锁（判定式是严格小于），与加固前一致。</summary>
    [Fact(DisplayName = "锁定终点 == 现在 ⇒ 已解锁")]
    public void Assess_ExactlyAtLockEnd_IsUnlocked()
    {
        var v = TimeGuard.Assess(LockEnd, T0, U0, LockEnd, U0 + 180_000);
        Assert.False(v.Locked);
        Assert.Equal(0, v.RemainingSeconds);
    }

    /// <summary>
    /// 便利重载（直接吃 <see cref="User"/>）：<c>LockoutEnd</c> 为 null 时以"现在"代入，
    /// 结果必须是未锁定 —— 否则没锁过的账号会永久登不进来。
    /// </summary>
    [Fact(DisplayName = "用户文档无 LockoutEnd ⇒ 视为未锁定")]
    public void Assess_UserWithoutLockoutEnd_IsNotLocked()
    {
        var user = new User { Username = "u" };
        var v = TimeGuard.Assess(user, T0, U0);
        Assert.False(v.Locked);
        Assert.Equal(0, v.RemainingSeconds);
    }

    // ────────────────────────────────────────── 二、失败计数窗口

    /// <summary>没有窗口锚点 ⇒ 视为"没有进行中的窗口"，由调用方开新窗口。</summary>
    [Fact(DisplayName = "窗口无锚点 ⇒ 返回已过期（开新窗口）")]
    public void WindowExpired_WithoutAnchor_ReturnsTrue()
    {
        Assert.True(TimeGuard.WindowExpired(null, null, T0, U0, Window));
    }

    /// <summary>只有墙钟锚点（老数据）⇒ 走墙钟比较。</summary>
    [Theory(DisplayName = "窗口仅墙钟锚点时按墙钟判")]
    [InlineData(60, false)]
    [InlineData(180, true)]   // 边界：走满即过期（>=）
    [InlineData(200, true)]
    public void WindowExpired_WallClockOnly(int elapsedSeconds, bool expected)
    {
        var actual = TimeGuard.WindowExpired(T0, null, T0.AddSeconds(elapsedSeconds), U0 + 10_000_000, Window);
        Assert.Equal(expected, actual);
    }

    /// <summary>两个锚点齐全时以单调线为准：差 1 毫秒都不算走满。</summary>
    [Theory(DisplayName = "窗口按单调线判")]
    [InlineData(179_999, false)]
    [InlineData(180_000, true)]
    public void WindowExpired_UsesUptime(long elapsedMs, bool expected)
    {
        var actual = TimeGuard.WindowExpired(T0, U0, T0.AddMilliseconds(elapsedMs), U0 + elapsedMs, Window);
        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// 核心结论：墙钟被前拨 10 分钟但真实只过了 60 秒 ⇒ 窗口**不得**提前作废。
    /// 否则攻击者"每错 2 次拨一次钟"就能让账号永远锁不上。
    /// </summary>
    [Fact(DisplayName = "墙钟前拨不作废窗口（否则计数永远清零）")]
    public void WindowExpired_ClockRolledForward_DoesNotExpireWindow()
    {
        Assert.False(TimeGuard.WindowExpired(T0, U0, T0.AddSeconds(600), U0 + 60_000, Window));
    }

    /// <summary>运行时长回退（重启）⇒ 退回墙钟判定，与 Assess 的退路一致。</summary>
    [Fact(DisplayName = "窗口锚点的运行时长回退 ⇒ 退回墙钟")]
    public void WindowExpired_UptimeRegression_FallsBackToWallClock()
    {
        Assert.True(TimeGuard.WindowExpired(T0, U0, T0.AddSeconds(200), 10, Window));
        Assert.False(TimeGuard.WindowExpired(T0, U0, T0.AddSeconds(20), 10, Window));
    }

    // ────────────────────────────────────────── 三、窗口背离取证

    /// <summary>
    /// 缺锚点 / 运行时长回退时**不做**背离判断：机器一重启，两条线必然对不上，
    /// 若照样报背离，每台重启过的机器在下次失败时都会写一条假 CLOCK_ANOMALY。
    /// </summary>
    [Fact(DisplayName = "窗口背离：两个锚点都没有 ⇒ 不报背离")]
    public void WindowDrift_WithoutAnyAnchor_ReturnsNone()
    {
        var (drift, seconds, implied) = TimeGuard.WindowDrift(null, null, T0.AddSeconds(600), U0);
        Assert.Equal(ClockDrift.None, drift);
        Assert.Equal(0, seconds);
        // 没有可信单调线时，"推算出的现在"只能是墙钟现在。
        Assert.Equal(T0.AddSeconds(600), implied);
    }

    /// <summary>只有墙钟锚点、没有运行时长锚点 ⇒ 同样不报背离（否则每次都会假报）。</summary>
    [Fact(DisplayName = "窗口背离：只有墙钟锚点 ⇒ 不报背离")]
    public void WindowDrift_WithWallAnchorOnly_ReturnsNone()
    {
        var (drift, seconds, implied) = TimeGuard.WindowDrift(T0, null, T0.AddSeconds(600), U0);
        Assert.Equal(ClockDrift.None, drift);
        Assert.Equal(0, seconds);
        Assert.Equal(T0.AddSeconds(600), implied);
    }

    /// <summary>运行时长回退（重启）同样不报背离。</summary>
    [Fact(DisplayName = "窗口背离：运行时长回退 ⇒ 不报背离")]
    public void WindowDrift_UptimeRegression_ReturnsNone()
    {
        var (drift, seconds, implied) = TimeGuard.WindowDrift(T0, U0, T0.AddSeconds(600), 10);
        Assert.Equal(ClockDrift.None, drift);
        Assert.Equal(0, seconds);
        Assert.Equal(T0.AddSeconds(600), implied);
    }

    /// <summary>容差内：报 None，但仍返回单调线推算的时刻（审计需要它回显）。</summary>
    [Fact(DisplayName = "窗口背离：容差内 ⇒ 报 None 并回显单调线推算值")]
    public void WindowDrift_WithinTolerance_ReturnsNoneWithImplied()
    {
        var (drift, seconds, implied) = TimeGuard.WindowDrift(T0, U0, T0.AddSeconds(32), U0 + 30_000);
        Assert.Equal(ClockDrift.None, drift);
        Assert.Equal(0, seconds);
        Assert.Equal(T0.AddSeconds(30), implied);
    }

    /// <summary>越过容差：方向与秒数都要能直接写进审计（"被拨了多少"）。</summary>
    [Theory(DisplayName = "窗口背离：前拨 / 回拨的方向与秒数")]
    [InlineData(600, ClockDrift.Forward, 600)]
    [InlineData(-3600, ClockDrift.Backward, -3600)]
    public void WindowDrift_ReportsDirectionAndSeconds(int skew, ClockDrift expected, int expectedSeconds)
    {
        var wallNow = T0.AddSeconds(30 + skew);
        var (drift, seconds, implied) = TimeGuard.WindowDrift(T0, U0, wallNow, U0 + 30_000);
        Assert.Equal(expected, drift);
        Assert.Equal(expectedSeconds, seconds);
        Assert.Equal(T0.AddSeconds(30), implied);
    }

    /// <summary>
    /// 断言容差常量的取值，防止有人"顺手调大一点让它不报警"。
    /// 2 秒的依据写在常量注释里（实测采样偏差 0.004 秒）。
    /// </summary>
    [Fact(DisplayName = "背离容差常量 == 2 秒（防止被悄悄放宽）")]
    public void DriftTolerance_IsPinned() => Assert.Equal(2, TimeGuard.DriftToleranceSeconds);
}
