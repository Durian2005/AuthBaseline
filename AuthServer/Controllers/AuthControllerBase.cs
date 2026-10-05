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

        var forward = verdict.Drift == ClockDrift.Forward;
        await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.ClockAnomaly, user.Status.ToString(),
            new
            {
                Trigger = trigger,
                WallNow = TimeGuard.WallNow(),
                // 单调线推算出的"现在"：与墙钟的差就是被拨动的量
                UptimeImpliedNow = verdict.ReliableNow,
                DriftSeconds = verdict.DriftSeconds,
                // 演示开关若开着，记录里留个痕，事后能区分"演示模拟"与"真实拨钟"
                DemoSkewSeconds = TimeGuard.DemoSkewActive ? TimeGuard.DemoSkewSeconds : 0
            },
            new { Code = BusinessCode.ClockAnomaly, Drift = verdict.Drift.ToString(), RemainingSeconds = verdict.RemainingSeconds },
            user.Status.ToString(), target, AuditResult.Failed,
            forward ? AuditReason.ClockRolledForward : AuditReason.ClockRolledBackward);

        user.LockoutDriftLogged = true;
        await _db.Users.UpdateOneAsync(u => u.Id == user.Id,
            Builders<User>.Update.Set(u => u.LockoutDriftLogged, true));
    }

    /**
     * 清除锁定时钟锚点。
     *
     * 与 lockoutEnd 的清除**必须同步**（凡置 null 处都要调一次）：
     * 锚点若留在文档里而锁定已结束，下一次锁定虽然会覆盖它们，
     * 但"锁定已解除却仍带着锁定锚点"这个中间状态会让任何按字段排查的人把结论带偏。
     * 让 lockoutEnd 为 null 与三个锚点为 null 保持等价，是最省心的不变式。
     */
    protected static void ClearLockoutAnchor(User user)
    {
        user.LockoutWallAt = null;
        user.LockoutUptimeAt = null;
        user.LockoutDriftLogged = false;
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
