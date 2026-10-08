using AuthServer.Models;

namespace AuthServer.Services;

/// <summary>时钟背离的方向（相对"系统运行时长"这条单调线）。</summary>
public enum ClockDrift
{
    /// <summary>两条线一致，差值在容差内。</summary>
    None,

    /// <summary>墙钟快于单调线 —— 被**前拨**了。这正是"改时间提前解锁"的指纹。</summary>
    Forward,

    /// <summary>
    /// 墙钟慢于单调线 —— 被**回拨**了。
    /// 回拨不能解锁（只会把锁拖长），但会触发另一类事故：
    /// 主板电池耗尽、虚拟机快照回滚，都会让时钟停在很久以前，
    /// 若不处理，一次 3 分钟的锁定会被拖成几小时甚至几年。
    /// </summary>
    Backward
}

/// <summary>一次锁定判定的全部结论。</summary>
/// <param name="Locked">是否仍处于锁定状态。</param>
/// <param name="RemainingSeconds">按**可靠时刻**算出的剩余秒数（用于回显，不能再用墙钟算）。</param>
/// <param name="ReliableNow">本次判定实际采信的"现在"。</param>
/// <param name="Drift">两条时间线的背离方向。</param>
/// <param name="DriftSeconds">背离量（正 = 墙钟快于单调线）。</param>
public readonly record struct LockoutVerdict(
    bool Locked,
    int RemainingSeconds,
    DateTime ReliableNow,
    ClockDrift Drift,
    long DriftSeconds);

/// <summary>
/// 时钟护栏：让"账号锁定"与"失败计数窗口"都不再单纯依赖可被操纵的本机墙钟。
///
/// 本类服务两个判定 + 一处取证（前两者的加固理由完全相同 —— 墙钟可被拨动，且拨动方向对攻击者有利）：
///   1. <see cref="Assess"/>：锁定何时到期。拨快时钟 = 提前解锁；
///   2. <see cref="WindowExpired"/>：失败计数窗口是否作废。拨快时钟 = 计数清零 = 重新拿回尝试机会；
///   3. <see cref="WindowDrift"/>：窗口锚点与现在的背离量。前两个判定负责"挡住"，
///      它负责让"有人动过时钟"这件事在**未锁定阶段**也留下记录 —— 纯取证，不参与放行与否。
///
/// 背景（这一点是本类存在的全部理由）：
///   加固前判定式为 `LockoutEnd > DateTime.UtcNow`，两个操作数都受墙钟控制 ——
///   LockoutEnd 是锁定时写下的绝对时间戳，UtcNow 则每次现读 OS 时钟。
///   而后端是 Tauri 的 sidecar，与客户端**同机**运行，
///   于是"改本机时钟"就等于"改服务端时钟"，拨快 3 分钟即可立刻解开锁定。
///
/// 做法：再引入一条墙钟管不着的**单调线** —— 系统运行时长（GetTickCount64）。
///   锁定时同时记下墙钟与运行时长两个锚点：
///     uptimeImplied = 锁定时的墙钟 + (当前运行时长 - 锁定时的运行时长)
///   它是"这段时间真实过去了多久"的推算值。两条线**背离超过容差**时以单调线为准，
///   因为墙钟可以被任意拨动，而运行时长只能一秒一秒地走。
///
/// 为什么这个方向是安全的（fail-closed）：
///   取单调线只会让锁定**保持或延长**，永远不会让锁提前解除。
///   于是拨钟、NTP 跳变、休眠这些异常统统落在"更保守"的一侧 ——
///   对一次 3 分钟的锁定来说，"多锁一会儿"是可以接受的失败方向。
///
/// 本类**不保证**的事（口径别说满）：
///   1. 重启电脑后运行时长归零，锚点随之失效，判定退回墙钟 ——
///      此时拨钟仍可解锁。这是已知边界，不是疏漏；重启通常超过 3 分钟，
///      攻击者等于自己把锁耗完。
///   2. 直接改库把 lockoutEnd 搬到过去，本类拦不住（比拨钟还省事）。
///   3. 能改系统时钟的人本来就持有管理员权限（需要 SeSystemtimePrivilege），
///      而这种人能直接改库。所以本类拦的是"右键改时间"这条最廉价的路径，
///      外加把"有人动过时钟"变成一条可查的审计记录 —— 不是"不可绕过"。
/// </summary>
public static class TimeGuard
{
    /// <summary>
    /// 两条时间线差多少秒算"背离"。
    /// 实测本机墙钟与运行时长的采样偏差幅度仅 0.004 秒，取 2 秒已极其宽松；
    /// 拨钟攻击至少要拨过"剩余锁定时间"（最长 180 秒）才可能奏效，远在阈值之上。
    /// </summary>
    public const int DriftToleranceSeconds = 2;

    /// <summary>演示用开关的环境变量名。</summary>
    public const string DemoSkewEnvName = "AUTH_TIME_SKEW_SECONDS";

    private static readonly TimeSpan DemoSkew = ReadDemoSkew();

    /// <summary>演示偏移是否生效（仅用于把这件事写进审计，便于事后区分"真拨钟"与"演示模拟"）。</summary>
    public static bool DemoSkewActive => DemoSkew != TimeSpan.Zero;

    /// <summary>演示偏移秒数。</summary>
    public static long DemoSkewSeconds => (long)DemoSkew.TotalSeconds;

    /// <summary>
    /// 锁定时使用的"墙钟"。
    ///
    /// 注意它**只**服务于锁定判定，绝不能拿去给审计盖时间戳或算票据有效期 ——
    /// 那会把演示开关的副作用扩散到整条链上。
    /// </summary>
    public static DateTime WallNow() => DateTime.UtcNow + DemoSkew;

    /// <summary>
    /// 单调时间源：系统运行时长（毫秒）。
    ///
    /// 用 Environment.TickCount64 而不是 Stopwatch / QueryPerformanceCounter：
    /// 后两者的语义是**进程内**计时，跨进程、跨重启都不可比；
    /// 而锁定状态要跨请求、跨进程重启保持一致，必须是系统级、且不被墙钟影响的计数。
    /// 64 位也顺带免掉了 32 位 TickCount 每 49.7 天回绕一次的坑。
    /// </summary>
    public static long UptimeMs() => Environment.TickCount64;

    /// <summary>便利入口：直接从用户文档上取锚点。</summary>
    public static LockoutVerdict Assess(User user, DateTime wallNow, long uptimeMs)
        => Assess(user.LockoutEnd ?? wallNow, user.LockoutWallAt, user.LockoutUptimeAt, wallNow, uptimeMs);

    /// <summary>
    /// 纯函数判定：不读时钟、不碰数据库，便于直接喂"墙钟被拨快了 10 分钟"这类场景做测试 ——
    /// 否则要验证抗改钟行为就得真的去改系统时钟，而那需要管理员权限。
    /// </summary>
    public static LockoutVerdict Assess(DateTime lockoutEnd, DateTime? wallAt, long? uptimeAt,
        DateTime wallNow, long uptimeMs)
    {
        // 没有锚点：改造前锁定的老记录，或写入方没给出。
        // 退回墙钟，行为与加固前**逐字一致** —— 不能因为加固把老数据锁死在门外。
        if (wallAt is null || uptimeAt is null)
            return WallOnly(lockoutEnd, wallNow);

        // 运行时长比记录时还小 ⇒ 机器重启过，单调线断了一截，锚点不可信。
        // 同样退回墙钟。这是已知边界：重启能绕过，但重启本身就超过锁定时长。
        if (uptimeMs < uptimeAt.Value)
            return WallOnly(lockoutEnd, wallNow);

        var implied = wallAt.Value.AddMilliseconds(uptimeMs - uptimeAt.Value);
        var driftSeconds = (long)Math.Round((wallNow - implied).TotalSeconds);
        var drifted = Math.Abs(driftSeconds) > DriftToleranceSeconds;

        // 背离时以单调线为准：
        //   前拨 → 挡住提前解锁；回拨 → 不让它把锁拖成几小时。
        var reliableNow = drifted ? implied : wallNow;
        var remaining = reliableNow < lockoutEnd
            ? (int)Math.Ceiling((lockoutEnd - reliableNow).TotalSeconds)
            : 0;

        var drift = !drifted ? ClockDrift.None
            : driftSeconds > 0 ? ClockDrift.Forward : ClockDrift.Backward;

        return new LockoutVerdict(reliableNow < lockoutEnd, Math.Max(remaining, 0),
            reliableNow, drift, driftSeconds);
    }

    /// <summary>
    /// 判定"失败计数窗口"是否已经作废（纯函数：不读时钟、不碰数据库，便于直接喂场景做测试）。
    ///
    /// 语义：窗口自锚点起算 <paramref name="window"/> 这么久；已经走满 ⇒ 返回 true，
    /// 表示调用方应当把失败计数归零、并开启一个新窗口。
    ///
    /// 为什么不能用墙钟判：窗口过期 = 计数清零 = **重新拿回 3 次尝试机会**，
    /// 这是对攻击者有利的方向。若按墙钟判，拨快 3 分钟即可让窗口提前作废，
    /// 于是"每错 2 次就把钟拨快 3 分钟"能让账号永远锁不上 —— 新开一个比无窗口更糟的口子。
    /// 因此这里与 <see cref="Assess"/> 同源：优先用系统运行时长这条单调线，
    /// 且取单调线只会让窗口**保持有效**（继续累计），fail-closed。
    ///
    /// 两条已知边界（与锁定判定**逐字一致**，不额外宽松）：
    ///   1. 缺少锚点（老数据）⇒ 视为"没有进行中的窗口"，返回 true，由调用方开新窗口；
    ///   2. 运行时长比锚点还小 ⇒ 机器重启过、单调线断了一截 ⇒ 退回墙钟判定。
    /// </summary>
    public static bool WindowExpired(DateTime? windowWallAt, long? windowUptimeAt,
        DateTime wallNow, long uptimeMs, TimeSpan window)
    {
        if (windowWallAt is null)
            return true;

        if (windowUptimeAt is null || uptimeMs < windowUptimeAt.Value)
            return wallNow - windowWallAt.Value >= window;

        return TimeSpan.FromMilliseconds(uptimeMs - windowUptimeAt.Value) >= window;
    }

    /// <summary>
    /// 计算"失败计数窗口锚点"两条时间线的背离（纯函数：不读时钟、不碰数据库）。
    ///
    /// 存在的理由：窗口与锁定一样会被拨钟试探，而**未锁定状态下的拨钟过去完全不留痕** ——
    /// 留痕原先只挂在"锁定拒绝"那条分支上，而那条分支要求账号已经是 Locked。
    /// 于是攻击者在 3 次尝试之内拨钟，事后翻审计看不到任何记录。
    /// 这个纯函数让窗口判定也能问出"锚点与现在差了多少"，从而补上那一条。
    ///
    /// 与 <see cref="WindowExpired"/> 共用同一套锚点、同一套容差：
    /// 两者对"锚点可不可信"的判断必须逐字一致，否则会出现
    /// "窗口判定采信锚点、背离检测不采信"这种自相矛盾。
    ///
    /// 返回 <see cref="ClockDrift.None"/> 的三种情形：缺锚点、运行时长回退（机器重启）、
    /// 差值落在 <see cref="DriftToleranceSeconds"/> 之内。
    /// </summary>
    /// <returns>背离方向、背离秒数（正 = 墙钟快于单调线）、单调线推算出的"现在"（供审计记录回显）。</returns>
    public static (ClockDrift Drift, long DriftSeconds, DateTime UptimeImpliedNow) WindowDrift(
        DateTime? windowWallAt, long? windowUptimeAt, DateTime wallNow, long uptimeMs)
    {
        // 与 WindowExpired 同一条退路：没有可信的单调锚点时**不做**背离判断。
        // 刻意不"退回墙钟算背离" —— 机器一重启，墙钟与运行时长必然对不上，
        // 那样每台重启过的机器在下次失败时都会报一次假背离。
        if (windowWallAt is null || windowUptimeAt is null || uptimeMs < windowUptimeAt.Value)
            return (ClockDrift.None, 0, wallNow);

        var implied = windowWallAt.Value.AddMilliseconds(uptimeMs - windowUptimeAt.Value);
        var driftSeconds = (long)Math.Round((wallNow - implied).TotalSeconds);
        if (Math.Abs(driftSeconds) <= DriftToleranceSeconds)
            return (ClockDrift.None, 0, implied);

        return (driftSeconds > 0 ? ClockDrift.Forward : ClockDrift.Backward, driftSeconds, implied);
    }

    /// <summary>无单调证据时的退路：完全按墙钟判定（加固前的行为）。</summary>
    private static LockoutVerdict WallOnly(DateTime lockoutEnd, DateTime wallNow)
    {
        var remaining = lockoutEnd > wallNow
            ? (int)Math.Ceiling((lockoutEnd - wallNow).TotalSeconds)
            : 0;
        return new LockoutVerdict(lockoutEnd > wallNow, Math.Max(remaining, 0),
            wallNow, ClockDrift.None, 0);
    }

    /// <summary>
    /// 读取演示偏移。**默认关闭**：环境变量不存在或不是整数时一律为 0。
    ///
    /// 存在的理由：验收现场要演示"拨钟无效"，真去改系统时钟需要管理员提权，
    /// 而且会给那段时间写入的审计记录盖上假时间戳（链校验不查时间单调性，事后查不出来）。
    /// 用这个开关模拟墙钟偏移，效果一样而零副作用。
    /// 它**不是**生产特性，报告里必须注明；一旦被设置，写出的 CLOCK_ANOMALY
    /// 记录里会带上 demoSkewSeconds，事后能一眼区分演示与真实拨钟。
    /// </summary>
    private static TimeSpan ReadDemoSkew()
    {
        var raw = Environment.GetEnvironmentVariable(DemoSkewEnvName);
        if (string.IsNullOrWhiteSpace(raw)) return TimeSpan.Zero;
        if (!long.TryParse(raw.Trim(), out var seconds)) return TimeSpan.Zero;
        return TimeSpan.FromSeconds(seconds);
    }
}
