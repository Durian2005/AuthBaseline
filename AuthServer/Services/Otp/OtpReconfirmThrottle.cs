using AuthServer.Services;

namespace AuthServer.Services.Otp;

/**
 * 再认证失败的**独立**节流器。
 *
 * ── 为什么必须单独造一个，而不复用登录失败计数 ────────────────
 * 这两件事的失败含义不同，硬塞进同一个计数器会同时踩两个坑：
 *
 *  · **算进 `FailedLoginAttempts`** ⇒ 拿到一张票据的人（比如临时用了别人的电脑、或票据被偷）
 *    只要连点三次敏感操作、每次故意给错链值，就能把受害者的账号**锁三分钟**。
 *    这是白送的拒绝服务，而它要保护的东西（"确认是本人"）一点也没变强。
 *    现有代码在 face/enroll 处正是这么做的，理由是"否则就是无节流的在线口令猜测通道" ——
 *    那条理由是对的，但它推出的结论不该是"用登录计数器"。
 *
 *  · **完全不节流** ⇒ 那才是真的开了后门。链值不是猜出来的，是**算**出来的：
 *    攻击者从匿名的 `login/challenge` 拿到 `R`/`N`，猜一个口令 `PW'`，
 *    算 `x₀' = PBKDF2(PW', R)` 再迭代 N 次，把结果当作链值提交。
 *    命中就说明 `PW'` 就是口令。每次猜测约一次 PBKDF2（10 万次迭代，几十毫秒），
 *    不设上限就是一条**永久在线**的口令爆破通道。
 *
 * 所以正解是第三条路：**独立计数、独立惩罚，只封这一条路**。
 * 被封的人照样能登录、能改口令（改口令走另一条凭据），只是暂时做不了敏感操作。
 * 这就是设计文档 §8.3 第 2 条"再认证失败不计入登录失败计数"的完整含义 ——
 * 不是"不计数"，而是"不进那个计数器"。
 *
 * ── 时间基准 ────────────────────────────────────────────────
 * 用单调时钟（<see cref="TimeGuard.UptimeMs"/>）：节流窗口不该被系统时间调整影响。
 * 墙钟往前拨就能解除封禁的话，这个节流等于没有。
 */
public sealed class OtpReconfirmThrottle
{
    /// <summary>窗口内允许的连续失败次数。取 5 而不是 3：链值没有"手抖打错"这种失败形态，
    /// 这里的失败几乎必然是"这个客户端算错了"或"有人在猜"，给一点余量不影响防护。</summary>
    public const int MaxFailures = 5;

    /// <summary>计数窗口。窗口过期即清零，重新数。</summary>
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    /// <summary>达到上限后的封禁时长。与登录锁定同为 3 分钟起步太长、太短又会被当成无限重试。</summary>
    public static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(5);

    private sealed class State
    {
        public int Failures;
        public long WindowStartMs;
        public long BlockedUntilMs;
    }

    private readonly Dictionary<string, State> _states = new(StringComparer.Ordinal);
    private readonly Func<long> _uptimeMs;
    private readonly object _gate = new();

    public OtpReconfirmThrottle(Func<long>? uptimeMs = null)
    {
        _uptimeMs = uptimeMs ?? TimeGuard.UptimeMs;
    }

    /// <summary>
    /// 该账号此刻是否被封。被封时给出剩余秒数（供 `Retry-After` 用 ——
    /// 让客户端知道"等 3 分钟"，比让它反复撞墙更友好，也少一堆噪声日志）。
    /// </summary>
    public (bool Blocked, int RetryAfterSeconds) Check(string userId)
    {
        var now = _uptimeMs();
        lock (_gate)
        {
            if (!_states.TryGetValue(userId, out var st) || now >= st.BlockedUntilMs)
                return (false, 0);

            var remain = (int)Math.Ceiling((st.BlockedUntilMs - now) / 1000.0);
            return (true, Math.Max(1, remain));
        }
    }

    /// <summary>记一次失败。**只在"链值不符"时调用** —— 并发冲突、链畸形、未建链都不是猜测。</summary>
    public void OnFailure(string userId)
    {
        var now = _uptimeMs();
        lock (_gate)
        {
            if (!_states.TryGetValue(userId, out var st))
            {
                st = new State { WindowStartMs = now };
                _states[userId] = st;
            }

            // 窗口过期 ⇒ 重新开始数。注意这里**不清** blockedUntil：封禁期刚过时
            // 窗口可能也已经过期，此时应当从 1 重新数，而不是立刻又被封一次。
            if (now - st.WindowStartMs > (long)Window.TotalMilliseconds)
            {
                st.WindowStartMs = now;
                st.Failures = 0;
            }

            st.Failures++;

            if (st.Failures >= MaxFailures)
            {
                st.BlockedUntilMs = now + (long)Cooldown.TotalMilliseconds;
                st.Failures = 0;
                st.WindowStartMs = now;
            }
        }
    }

    /// <summary>
    /// 成功一次就清零。
    ///
    /// 为什么成功要清零而不是"扣一分"：链值验证成功是**极强**的证据 ——
    /// 它需要知道口令（或持有已算好的那一格），不是猜得出来的。
    /// 已经证明过自己的人不该继续背着之前的失败计数。
    /// </summary>
    public void OnSuccess(string userId)
    {
        lock (_gate)
        {
            if (_states.Remove(userId)) { /* 清掉即可，无需保留痕迹：痕迹在审计里 */ }
        }
    }

    /// <summary>当前被记录状态的账号数。仅用于单测与诊断。</summary>
    public int TrackedUsers
    {
        get { lock (_gate) { return _states.Count; } }
    }
}
