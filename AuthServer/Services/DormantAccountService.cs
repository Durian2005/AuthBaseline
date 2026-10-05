using AuthServer.Models;

namespace AuthServer.Services;

/// <summary>
/// 沉睡（僵尸）账号判定的**唯一出口**。
///
/// 为什么把判定做成纯函数：判定的输入只有"基准时间、当前时间、阈值"三样，
/// 与数据库、时钟、HTTP 都无关。纯函数化之后，"拨到 100 天前"这类场景
/// 可以直接喂参数验证，不必真的去改系统时钟或等 90 天。
///
/// 判定与处置**刻意分离**：
///   本服务只回答"这个账号算不算沉睡"（<see cref="IsDormant"/>），
///   **不修改任何状态**。沉睡的账号仍然可以正常登录 ——
///   把"检测"与"失效"合并，会让一次误判直接变成"用户进不来"，代价太大。
///   真正让账号不能登录的是"冻结"（<c>Status = Disabled</c>），而那必须由人点击。
/// </summary>
public static class DormantAccountService
{
    /// <summary>配置节名。</summary>
    public const string ConfigSection = "Dormant";

    /// <summary>默认阈值（天）。与设计稿一致：90 天。</summary>
    public const int DefaultDormantDays = 90;

    /// <summary>
    /// 判定基准时间：优先用最后一次成功登录，没有则退回创建时间。
    ///
    /// 为什么要这个回退：老数据没有 <c>lastLoginAt</c>，而创建时间虽然不等同于
    /// "最后活跃"，但一个"创建了很久、且从未登录过"的账号恰恰是沉睡的典型；
    /// 回退到它比"因为字段为空就跳过"更符合治理意图，也不会漏判。
    /// </summary>
    public static DateTime Baseline(User user) => user.LastLoginAt ?? user.CreatedAt;

    /// <summary>距基准时间的天数（向下取整，负数归零）。</summary>
    public static int DaysSince(DateTime baseline, DateTime now) =>
        Math.Max(0, (int)(now - baseline).TotalDays);

    /// <summary>是否达到（超过）阈值。</summary>
    public static bool IsDormant(User user, DateTime now, int thresholdDays)
    {
        if (user is null) return false;
        // Pending：还没通过审核，谈不上"沉睡"；Disabled：已被冻结，另行归类。
        if (user.Status is UserStatus.Pending or UserStatus.Disabled) return false;
        return DaysSince(Baseline(user), now) >= thresholdDays;
    }

    /// <summary>
    /// 是否为**可被冻结**的沉睡候选：既达到阈值，又不受角色保护。
    ///
    /// 注意它<b>不含</b>自我豁免 —— 那是"操作者相对目标"的关系，
    /// 取决于谁在操作，不属于账号自身的属性。自我豁免由
    /// <c>UserRoles.CanBeManagedBy</c> 在处置接口里把关。
    /// </summary>
    public static bool IsFreezeCandidate(User user, DateTime now, int thresholdDays) =>
        IsDormant(user, now, thresholdDays) && !UserRoles.IsDormantProtected(user.Role);

    /// <summary>从配置读阈值；缺失或非正数时回落默认值（不允许"阈值为 0"意外冻结所有人）。</summary>
    public static int ReadThreshold(IConfiguration configuration)
    {
        var raw = configuration.GetValue<int?>($"{ConfigSection}:DormantDays");
        if (raw is null || raw.Value <= 0) return DefaultDormantDays;
        return raw.Value;
    }
}
