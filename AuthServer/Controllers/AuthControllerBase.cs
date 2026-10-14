using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthServer.Controllers;

/**
 * 认证相关控制器的共享基类：票据鉴权、审计写入、用户响应映射、口令复杂度。
 *
 * 为什么拆出基类而不是把一个 1800 行的 AuthController 直接切成三个独立类：
 *   守卫（RequireXxxAsync）、审计写入（_auditWriter）、用户响应映射（ToUserResponse）
 *   这三件事被三个域**同时**依赖。若各自复制一份，权限判定就会有三份实现，
 *   日后改一处漏两处，恰好会破坏"职责分离"这条演示主线。
 *   放进基类后：**权限判定仍然只有一条出口**，而每个子类只暴露自己域的接口。
 *
 * 与 AuditController 的分工：本基类只服务 api/auth 下的三个控制器；
 * 审计数据接口有独立的权限模型（AuditRead），刻意不共享这份守卫。
 */
public abstract class AuthControllerBase : ControllerBase
{
    protected readonly MongoDbService _db;
    protected readonly AuditWriter _auditWriter;
    protected readonly SessionService _sessions;
    protected readonly PepperProvider _pepper;
    /// <summary>
    /// 沉睡判定阈值（天）。构造时从配置读一次并缓存 ——
    /// 判定会在每次返回用户列表时对每个账号跑一遍，不宜每次都去解析配置。
    /// </summary>
    protected readonly int _dormantThresholdDays;
    protected const int MaxFailedAttempts = 3;
    protected static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(3);
    /// <summary>
    /// 失败计数的统计窗口：**只统计这么长时间之内**的失败。
    ///
    /// 与 <see cref="LockoutDuration"/> 取值相同、语义完全不同 ——
    /// 那个是"锁上之后关多久"，这个是"多久之内的失败才算数"。
    /// 刻意写成两个常量而不是复用一个：它们只是巧合同值，
    /// 将来完全可能分别调整（例如窗口放宽到 5 分钟而锁定时长不动）。
    /// </summary>
    protected static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(3);

    protected AuthControllerBase(MongoDbService db, AuditWriter auditWriter,
        SessionService sessions, PepperProvider pepper, IConfiguration configuration)
    {
        _db = db;
        _auditWriter = auditWriter;
        _sessions = sessions;
        _pepper = pepper;
        _dormantThresholdDays = DormantAccountService.ReadThreshold(configuration);
    }

    // 密码复杂度校验：至少8位，包含大小写字母和数字
    protected static bool IsPasswordComplex(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
            return false;
        if (!Regex.IsMatch(password, @"[A-Z]"))
            return false;
        if (!Regex.IsMatch(password, @"[a-z]"))
            return false;
        if (!Regex.IsMatch(password, @"[0-9]"))
            return false;
        return true;
    }

    protected static string Norm(string? username) => username?.Trim().ToLowerInvariant() ?? string.Empty;

    protected UserResponse ToUserResponse(User u) => new()
    {
        Id = u.Id,
        Username = u.Username,
        Status = u.Status.ToString(),
        Role = u.Role.ToString(),
        RoleLabel = UserRoles.Label(u.Role),
        // 邮箱一律脱敏后返回，管理员能看到"有没有绑、绑没绑好"，但拿不到完整地址
        Email = EmailUtil.Mask(u.Email),
        EmailVerified = u.EmailVerified,
        FailedLoginAttempts = u.FailedLoginAttempts,
        LockoutEnd = u.LockoutEnd,
        CreatedAt = u.CreatedAt,
        LastLoginAt = u.LastLoginAt,
        // 沉睡相关字段统一在这里派生，前端不再自己算"差多少天"，
        // 避免"后端按 90 天判、前端按 30 天显示"这类口径分歧。
        DormantDays = DormantAccountService.DaysSince(
            DormantAccountService.Baseline(u), TimeGuard.WallNow()),
        Dormant = DormantAccountService.IsDormant(u, TimeGuard.WallNow(), _dormantThresholdDays),
        Frozen = u.Status == UserStatus.Disabled,
        DormantProtected = UserRoles.IsDormantProtected(u.Role),
        // 由角色派生：只有能管用户的两种角色才为 true。
        // 审计管理员在此为 false —— 他看日志，但管不了任何账号。
        IsAdmin = UserRoles.CanManageUsers(u.Role)
    };

    /* ==================== 时钟护栏的调用侧 ==================== */

    /**
     * 锁定拒绝的统一出口。
     *
     * 为什么要把这段抽出来：三个入口（登录 / 改密 / 重置口令）的锁定拒绝必须**逐字一致**。
     * 一旦各写各的，剩余秒数就可能有的按墙钟算、有的按单调线算，
     * 界面会出现"显示还剩 0 秒却仍然拒绝"这种自相矛盾 —— 而那恰好是
     * 一个正在被拨动的时钟最典型的表现。
     * 统一出口后，"判定用哪条时间线"这件事只有 TimeGuard 一个地方说了算。
     */
    protected async Task<IActionResult> LockoutRejectionAsync(User user, LockoutVerdict verdict,
        string action, string statusBefore, object requestLog, string target,
        string messagePrefix, int httpStatus)
    {
        var resp = new ApiResponse
        {
            Success = false,
            Code = BusinessCode.AccountLocked,
            Message = $"{messagePrefix}{verdict.RemainingSeconds} 秒后再试",
            Data = new { LockoutEnd = user.LockoutEnd, RemainingSeconds = verdict.RemainingSeconds }
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore, requestLog, resp, statusBefore,
            target, AuditResult.Failed, AuditReason.AccountLocked);
        return StatusCode(httpStatus, resp);
    }

    /**
     * 发现时钟背离时留一条审计。
     *
     * 加固前，靠拨钟解开锁定是**完全静默**的：锁定到期走登录里的"自动恢复"分支，
     * 而那个分支不写任何日志。于是事后翻审计，看不出这个账号曾被"用改时间的方式"放进去过。
     * 有了这条记录，"有人动过时钟"本身成为可检索的事件。
     *
     * 两个刻意的取舍：
     *   1. 同一次锁定只记一条（靠 lockoutDriftLogged 收敛）。时钟被拨动后不会自己回来，
     *      否则之后每一次尝试都会被判为背离，把审计刷成一屏重复告警 ——
     *      真正的事件反而被淹掉。
     *   2. 只翻标志位用 UpdateOne，不整篇 ReplaceOne：本分支不改动用户文档的其它内容，
     *      没必要多写一遍。
     */
    protected async Task LogClockDriftIfAnyAsync(User user, LockoutVerdict verdict, string trigger, string target)
    {
        if (verdict.Drift == ClockDrift.None || user.LockoutDriftLogged) return;

        await LogClockAnomalyAsync(user, verdict.Drift, verdict.DriftSeconds, verdict.ReliableNow,
            trigger, target, verdict.RemainingSeconds);

        user.LockoutDriftLogged = true;
        await _db.Users.UpdateOneAsync(u => u.Id == user.Id,
            Builders<User>.Update.Set(u => u.LockoutDriftLogged, true));
    }

    /**
     * 时钟背离留痕的**底层出口**：锁定判定与失败计数窗口共用同一段写入。
     *
     * 为什么再抽一层：两个判定发现的背离，事后必须能在审计里以**同一种形状**出现 ——
     * 同样的字段名、同样的原因码、同样带 demoSkewSeconds。
     * 各写一份的后果是"改了一处的字段名、另一处还是旧的"，而审计字段一旦分裂，
     * 按字段检索就会漏掉一半 —— 这恰恰是审计这种设施最不能出的错。
     *
     * remainingSeconds 只有锁定判定能给（窗口判定没有"还剩多少秒解锁"这个概念），
     * 传 null 表示"这条不是锁定判定产生的"。
     */
    private async Task LogClockAnomalyAsync(User user, ClockDrift drift, long driftSeconds,
        DateTime uptimeImpliedNow, string trigger, string target, int? remainingSeconds)
    {
        var forward = drift == ClockDrift.Forward;
        await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.ClockAnomaly, user.Status.ToString(),
            new
            {
                Trigger = trigger,
                WallNow = TimeGuard.WallNow(),
                // 单调线推算出的"现在"：与墙钟的差就是被拨动的量
                UptimeImpliedNow = uptimeImpliedNow,
                DriftSeconds = driftSeconds,
                // 演示开关若开着，记录里留个痕，事后能区分"演示模拟"与"真实拨钟"
                DemoSkewSeconds = TimeGuard.DemoSkewActive ? TimeGuard.DemoSkewSeconds : 0
            },
            new { Code = BusinessCode.ClockAnomaly, Drift = drift.ToString(), RemainingSeconds = remainingSeconds },
            user.Status.ToString(), target, AuditResult.Failed,
            forward ? AuditReason.ClockRolledForward : AuditReason.ClockRolledBackward);
    }

    /**
     * 清除锁定时钟锚点。**只由 ResetFailedAttempts 调用**，故为 private：
     * 清零涉及 5 个字段，多一个调用方就多一处漏清的机会。
     *
     * 与 lockoutEnd 的清除必须同步：
     * 锚点若留在文档里而锁定已结束，下一次锁定虽然会覆盖它们，
     * 但"锁定已解除却仍带着锁定锚点"这个中间状态会让任何按字段排查的人把结论带偏。
     * 让 lockoutEnd 为 null 与三个锚点为 null 保持等价，是最省心的不变式。
     */
    private static void ClearLockoutAnchor(User user)
    {
        user.LockoutWallAt = null;
        user.LockoutUptimeAt = null;
        user.LockoutDriftLogged = false;
    }

    /* ==================== 失败计数窗口的调用侧 ==================== */

    /**
     * 记一次口令失败，并回答"累计是否已达到锁定阈值"。
     *
     * 为什么窗口判定要住在这里、而不是让登录接口自己算：
     *   "窗口有多长"（FailureWindow）与"窗口过期了没有"（TimeGuard.WindowExpired）
     *   是同一件事的两半。摊到调用方去写，将来多一个会累计失败的入口
     *   （例如改密时校验旧口令），就会出现第二份窗口语义，两份迟早会走偏。
     *
     * 顺序是本方法的全部要点，而且有两层：
     *   1. **先判窗口过期，再累加**。
     *      已过期 ⇒ 上一串失败不再算数：计数归零、清掉旧锚点，本次成为新窗口的第 1 次。
     *      未过期 ⇒ 直接累加，**锚点保持不动**。
     *        一旦每次失败都把锚点刷成"现在"，窗口就会被无限续期，
     *        "3 分钟内 3 次"会退化成"只要不停手就永远锁不上"。
     *   2. **背离检测必须排在更前面**（在锚点被改写或清空之前）。
     *      搬完锚点再算背离，读到的是"锚点与现在一致"，拨钟反而查不出来。
     *
     * 它同时是"未锁定状态下拨钟"的**唯一留痕点**：
     *   锁定之后再拨钟走的是 TimeGuard.Assess 那条路（那里靠 lockoutDriftLogged 收敛），
     *   而锁定**之前**的拨钟过去完全静默 —— 攻击者在 3 次尝试之内拨钟不留任何痕迹。
     *   这里刻意不引入新的去重字段：一轮窗口内最多产生 2 条（第 1 次没有锚点可比，
     *   第 3 次就已经锁定），速率不超过 LOGIN_FAILED 本身，淹没不了审计。
     */
    protected async Task<bool> RegisterFailedAttemptAsync(User user, DateTime wallNow, long uptimeMs, string target)
    {
        var hasWindow = user.FailedLoginAttempts > 0;

        // 背离检测放在最前，理由见方法说明第 2 条。
        //
        // 两个方向都记（与锁定判定的口径逐字一致）：
        //   前拨 —— 对攻击者有利的指纹，即"想靠改时间把窗口作废、重新拿回 3 次机会"；
        //   回拨 —— 对攻击者无利，但典型成因是主板电池耗尽 / 虚拟机快照回滚，
        //          这类故障本身就该在审计里留一笔。
        // 只记前拨会让"有人动过时钟"这件事在审计里缺一半。
        //
        // 注意拨钟**不改变本次尝试的结果**：既不加罚、也不放过。
        // 取证与裁决分开 —— 能拨钟的人本来就持有管理员权限，
        // 给他加罚只是误伤普通人（详见 docs/reports/AUDIT-VERIFY-REPORT.md）。
        if (hasWindow)
        {
            var (drift, driftSeconds, uptimeImpliedNow) = TimeGuard.WindowDrift(
                user.FailedWindowWallAt, user.FailedWindowUptimeAt, wallNow, uptimeMs);
            if (drift != ClockDrift.None)
                await LogClockAnomalyAsync(user, drift, driftSeconds, uptimeImpliedNow,
                    "FAILED_ATTEMPT_WINDOW", target, null);
        }

        if (hasWindow &&
            TimeGuard.WindowExpired(user.FailedWindowWallAt, user.FailedWindowUptimeAt,
                wallNow, uptimeMs, FailureWindow))
        {
            user.FailedLoginAttempts = 0;
            ClearAttemptWindow(user);
        }

        if (user.FailedLoginAttempts == 0)
        {
            user.FailedWindowWallAt = wallNow;
            user.FailedWindowUptimeAt = uptimeMs;
        }

        user.FailedLoginAttempts++;
        return user.FailedLoginAttempts >= MaxFailedAttempts;
    }

    /** 清除"失败计数窗口"的两个锚点。**只由 ResetFailedAttempts 调用**。 */
    private static void ClearAttemptWindow(User user)
    {
        user.FailedWindowWallAt = null;
        user.FailedWindowUptimeAt = null;
    }

    /**
     * 记一次**应当计次**的验证失败（口令错 / 人脸判错 / 二次口令错），
     * 并处理由此可能触发的锁定。返回值：未触发锁定为 null，触发则为给用户看的锁定话术。
     *
     * 为什么把这段抽出来：登录第二因子与"删除/更换人脸时的二次口令"是两条独立路径，
     * 但"累加 → 达到阈值就锁定 → 落库"这三步必须逐字一致。
     * 各写一份的后果是两条路径的锁定锚点写法可能不同，
     * 而锚点一旦不同，"锁定到底什么时候到期"就会出现两套答案。
     *
     * ⚠️ 只接受**已经判定为计次**的失败。计次与否由调用方按
     * <c>FaceCodes.IsCounted</c> / 口令校验结果决定，本方法不做二次判断 ——
     * 判断只应有一个出口，否则"到底谁说了算"迟早会变成两处不一致。
     */
    protected async Task<string?> ApplyCountedFailureAsync(User user)
    {
        // 两个时间读数只取一次：分两次读会拿到两个不同步的"现在"，
        // 让本该同起点的"窗口锚点"与"锁定锚点"对不上。
        var failWallNow = TimeGuard.WallNow();
        var failUptimeMs = TimeGuard.UptimeMs();

        var thresholdReached = await RegisterFailedAttemptAsync(user, failWallNow, failUptimeMs, user.Username);

        string? lockMessage = null;
        if (thresholdReached)
        {
            user.Status = UserStatus.Locked;
            // 锁定时同时记下两个锚点：墙钟 + 系统运行时长（理由见 Login 里的同类注释）。
            user.LockoutEnd = failWallNow.Add(LockoutDuration);
            user.LockoutWallAt = failWallNow;
            user.LockoutUptimeAt = failUptimeMs;
            // 新一轮锁定：把"已就时钟背离告警过"的标记归零。
            user.LockoutDriftLogged = false;
            lockMessage = $"连续输错 {MaxFailedAttempts} 次，账号已锁定 {LockoutDuration.TotalMinutes} 分钟";
        }

        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
        return lockMessage;
    }

    /**
     * 失败计数 + 锁定状态 + 两套时间锚点的**统一清除出口**。
     *
     * 为什么必须收成一个方法：清零原先散在 5 处（登录成功 / 登录时发现锁定已到期 /
     * 发码时发现锁定已到期 / 重置口令成功 / 管理员解锁的两条分流），每处手写三行。
     * 引入"失败计数窗口"后，一次清零牵动的字段从 2 个变成 5 个，
     * 再散着写一定会漏 —— 而漏掉的后果不是"少清一个字段"这么轻：
     * 计数清了而窗口锚点还挂着，下一次失败会被判成"旧窗口仍在有效期内",
     * 于是这个用户被提前锁掉。收成一出口后，新增字段只需改这一处。
     */
    protected static void ResetFailedAttempts(User user)
    {
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        ClearLockoutAnchor(user);
        ClearAttemptWindow(user);
    }

    /* ==================== 会话票据鉴权 ==================== */

    /** 从 Authorization: Bearer <ticket> 中取出票据。 */
    protected string? ReadTicket()
    {
        var raw = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(raw)) return null;
        const string prefix = "Bearer ";
        return raw.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? raw[prefix.Length..].Trim()
            : null;
    }

    /**
     * 受保护接口的统一入口守卫，按所需访问级别分两个入口。
     *
     * 为什么拆成两个而不是一个带 bool 的：
     *   "是不是管理员"这种二元判断已经不足以描述本系统的权限边界 ——
     *   用户管理员能管用户但不能任免角色，审计管理员能看日志但管不了账号。
     *   每个接口显式声明自己要哪一级，声明错了在验收时会立刻暴露。
     *
     * 审计读取那一级（AuditRead）不在这里：审计数据接口有独立的权限模型，
     * 由 AuditController 自带的守卫处理，刻意不与本基类合并。
     *
     * 鉴权失败时**本身也要留下审计记录** —— 这是实验二「02 看不到」的关键证据：
     * 光有拒绝响应不够，必须证明系统把这次越权尝试也记下来了。
     */

    /// <summary>
    /// 需要"已登录"即可（账号自助：查询 / 录入 / 删除自己的人脸）。
    ///
    /// 为什么这些自助接口也要票据，而不是像改口令那样"报用户名 + 验旧口令"：
    ///   人脸自助操作的对象是**票据所代表的那个人**，而"我是谁"这件事
    ///   只能由票据回答。若改成从请求体里读用户名，就必须再额外证明
    ///   "你就是那个用户" —— 而人脸录入本来就没有旧口令可验（首次录入时还没有），
    ///   等于把这条通道的入口敞开。走票据则天然闭合。
    /// </summary>
    protected Task<(User? User, IActionResult? Deny)> RequireAuthenticatedAsync(string action, string target = "")
        => RequireAsync(AccessLevel.Authenticated, action, target);

    /// <summary>需要用户管理能力（Admin / UserAdmin）：审核、解锁、删除普通用户。</summary>
    protected Task<(User? Admin, IActionResult? Deny)> RequireUserAdminAsync(string action, string target = "")
        => RequireAsync(AccessLevel.UserAdmin, action, target);

    /// <summary>需要角色任免能力（仅 Admin）：创建账号、变更他人角色。</summary>
    protected Task<(User? Admin, IActionResult? Deny)> RequireAdminAsync(string action, string target = "")
        => RequireAsync(AccessLevel.Admin, action, target);

    protected async Task<(User? Operator, IActionResult? Deny)> RequireAsync(
        AccessLevel level, string action, string target)
    {
        var ticket = ReadTicket();
        var auth = await _sessions.ValidateAsync(ticket, level);

        if (!auth.Success)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = auth.ReasonCode,
                Message = auth.Message
            };
            var statusBefore = auth.User?.Status.ToString() ?? "N/A";
            await _auditWriter.WriteAsync(
                auth.User?.Id ?? "anonymous",
                auth.User?.Username ?? "anonymous",
                action, statusBefore,
                // 保留被尝试访问的接口与原始查询串：越权尝试最常见的形态就是
                // "在 URL 里声明自己是管理员"（如 ?adminUsername=admin），
                // 留住原始请求形态，才能证明拦截的究竟是哪一类伪冒手法。
                // Role 一并记下，"管理员来够审计数据"这类越界才能被单独筛出来。
                new
                {
                    AttemptedTarget = target,
                    Reason = auth.ReasonCode,
                    Role = auth.User is null ? "anonymous" : auth.User.Role.ToString(),
                    Path = Request.Path.Value,
                    Query = Request.QueryString.Value
                },
                resp, statusBefore, target, AuditResult.Failed, auth.ReasonCode);
            return (null, StatusCode(auth.HttpStatus, resp));
        }

        return (auth.User, null);
    }
}
