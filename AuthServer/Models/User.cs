using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthServer.Models;

public enum UserStatus
{
    Pending,    // 待审核
    Enabled,    // 启用
    Locked,     // 锁定
    Disabled    // 禁用（可选）
}

/// <summary>
/// 账号角色。四者**互斥** —— 一个账号同一时刻只能处于其中一种。
///
/// 为什么用单一枚举而不是 IsAdmin + IsAuditAdmin 两个布尔位：
/// 两个布尔位能表达"既管用户又看日志"这种兼任组合，而系统要求
/// **管账号的人看不到日志、看日志的人管不了账号**。用枚举后，
/// 兼任状态在数据结构上根本无法表示，不必靠额外校验去堵 ——
/// 非法状态不可表达，比事后检查可靠。
///
/// 由此还白得一条保证：管理员看不到审计日志不是因为"某处拦了他"，
/// 而是因为他的 Role 压根不是 AuditAdmin —— 看日志的判定条件本身就不成立。
/// </summary>
public enum UserRole
{
    /// <summary>普通用户：自助注册，只能使用自己的账号与口令功能。</summary>
    User = 0,

    /// <summary>
    /// 管理员：管用户，并可任命 / 变更他人的角色。
    /// 首次启动播种的 admin 属于此级。**看不到审计日志。**
    /// </summary>
    Admin = 1,

    /// <summary>
    /// 用户管理员：由「管理员」创建，同样能管理用户，
    /// 但不能创建账号、不能任命审计管理员（低于 Admin）。
    /// **看不到审计日志。**
    /// </summary>
    UserAdmin = 2,

    /// <summary>
    /// 审计管理员：由「管理员」任命，**只能查看审计数据**，
    /// 不能进行任何用户管理。
    /// </summary>
    AuditAdmin = 3
}

public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    [BsonElement("username")]
    public string Username { get; set; } = string.Empty;

    [BsonElement("passwordHash")]
    public string PasswordHash { get; set; } = string.Empty;

    [BsonElement("status")]
    [BsonRepresentation(BsonType.String)]
    public UserStatus Status { get; set; } = UserStatus.Pending;

    /// <summary>
    /// 角色（互斥）。鉴权一律以本字段为准。
    /// 老数据只有 isAdmin 布尔位，启动时由 MongoDbService 一次性回填。
    /// </summary>
    [BsonElement("role")]
    [BsonRepresentation(BsonType.String)]
    public UserRole Role { get; set; } = UserRole.User;

    /// <summary>
    /// 绑定的邮箱（统一小写规范化后存储）。
    /// 老账号为 null —— 邮箱功能上线前注册的账号允许继续使用，不强制补绑。
    /// 由管理员创建的管理员 / 审计管理员账号**一律不绑邮箱**，只凭口令登录。
    /// </summary>
    [BsonElement("email")]
    public string? Email { get; set; }

    /// <summary>
    /// 邮箱是否已通过验证码验证。
    /// 只有走完"发码 → 校验"流程的邮箱才置为 true，用于找回密码链路的前置条件。
    /// </summary>
    [BsonElement("emailVerified")]
    public bool EmailVerified { get; set; } = false;

    [BsonElement("failedLoginAttempts")]
    public int FailedLoginAttempts { get; set; } = 0;

    [BsonElement("lockoutEnd")]
    public DateTime? LockoutEnd { get; set; }

    /// <summary>
    /// 锁定那一刻的**墙钟**读数。与下一个字段成对使用，用途见 TimeGuard。
    ///
    /// 为什么要存它：只存 LockoutEnd 的话，"现在到了没有"只能靠再去读一次墙钟，
    /// 而墙钟正是可以被拨动的那一个 —— 存下锁定瞬间的读数，才能反过来验证
    /// "这段时间真实过去了多久"。
    ///
    /// 兼容性：改造前锁定的老记录没有该字段（为 null），TimeGuard 会退回纯墙钟判定。
    /// </summary>
    [BsonElement("lockoutWallAt")]
    [BsonIgnoreIfNull]
    public DateTime? LockoutWallAt { get; set; }

    /// <summary>
    /// 锁定那一刻的**系统运行时长**（Environment.TickCount64，毫秒）。
    ///
    /// 它是墙钟之外的第二条时间线，且完全不受改时钟影响，
    /// 因此能算出"这段时间真实过去了多久"。取值与上一个字段配对，
    /// 单独一个没有意义。
    /// </summary>
    [BsonElement("lockoutUptimeAt")]
    [BsonIgnoreIfNull]
    public long? LockoutUptimeAt { get; set; }

    /// <summary>
    /// 本次锁定期内是否已就"时钟背离"记过一条审计。
    ///
    /// 为什么不靠"每发现一次背离就记一条"：时钟一旦被拨动，它不会自己回来，
    /// 于是之后每一次尝试都会被判为背离 —— 审计会被刷成一屏重复告警，
    /// 真正的事件反而被淹没。用这个标志把"一次事件"收敛成"一条记录"。
    ///
    /// 归零时机：每次新建锁定（锁定时一并置 false）与每次清除锁定。不可两用。
    /// </summary>
    [BsonElement("lockoutDriftLogged")]
    public bool LockoutDriftLogged { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 改造前的管理员布尔位。**已废弃，代码不再读写**，仅保留在库中以备追溯历史。
    /// 角色判定统一走 Role。
    /// </summary>
    [BsonElement("isAdmin")]
    [BsonIgnoreIfNull]
    public bool? IsAdminLegacy { get; set; }
}

public class UserResponse
{
    public string Id { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;

    /// <summary>角色：User / Admin / UserAdmin / AuditAdmin。</summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>角色的中文显示名，避免前端到处硬编码映射。</summary>
    public string RoleLabel { get; set; } = string.Empty;

    /// <summary>脱敏后的邮箱（如 s*****@example.com）。老账号无邮箱时为空串。</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>邮箱是否已验证。管理员据此判断该账号能否走"找回密码"。</summary>
    public bool EmailVerified { get; set; }

    public int FailedLoginAttempts { get; set; }
    public DateTime? LockoutEnd { get; set; }
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// 是否具备用户管理能力（Admin / UserAdmin）。
    /// 为兼容既有前端字段而保留，值由 Role 派生。
    /// </summary>
    public bool IsAdmin { get; set; }
}

/// <summary>
/// 角色判定与展示名的唯一出口。
///
/// 集中的理由：角色一旦散落在各 Controller 里用 if 硬编码，
/// 后续再加一级角色就会出现"某个接口漏改"的权限漏洞。
/// 全部判定都从这里走，新增角色时编译器会提醒补全分支。
/// </summary>
public static class UserRoles
{
    /// <summary>所有可选角色（用于校验接口入参是否合法）。</summary>
    public static readonly UserRole[] All =
    {
        UserRole.User, UserRole.Admin, UserRole.UserAdmin, UserRole.AuditAdmin
    };

    public static string Label(UserRole role) => role switch
    {
        UserRole.Admin => "管理员",
        UserRole.UserAdmin => "用户管理员",
        UserRole.AuditAdmin => "审计管理员",
        _ => "普通用户"
    };

    /// <summary>能否解析字符串形式的角色名（接口入参校验用）。</summary>
    public static bool TryParse(string? raw, out UserRole role)
    {
        role = UserRole.User;
        if (string.IsNullOrWhiteSpace(raw)) return false;
        foreach (var r in All)
        {
            if (string.Equals(r.ToString(), raw.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                role = r;
                return true;
            }
        }
        return false;
    }

    /* ---------- 能力判定：全系统只在这里定义"谁能做什么" ---------- */

    /// <summary>能管理用户（审核 / 解锁 / 删除普通用户）。Admin 与 UserAdmin 均可。</summary>
    public static bool CanManageUsers(UserRole role) =>
        role is UserRole.Admin or UserRole.UserAdmin;

    /// <summary>
    /// 能创建账号、能任命 / 变更他人角色。**仅 Admin**。
    /// 这一条就是"新建的管理员低于 admin"的落点。
    /// </summary>
    public static bool CanAssignRoles(UserRole role) => role == UserRole.Admin;

    /// <summary>
    /// 能查看审计数据（日志 / 校验 / 分片 / 统计）。**仅 AuditAdmin**。
    /// 管理员（含初始 admin）在这里被结构性排除。
    /// </summary>
    public static bool CanReadAudit(UserRole role) => role == UserRole.AuditAdmin;

    /// <summary>两个 User 是否指向同一个账号（用户名是系统内的唯一键，Id 作为补充）。</summary>
    public static bool IsSameAccount(User a, User b)
    {
        if (!string.IsNullOrEmpty(a.Id) && !string.IsNullOrEmpty(b.Id))
            return string.Equals(a.Id, b.Id, StringComparison.Ordinal);
        return string.Equals(a.Username, b.Username, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 目标账号能否被 <paramref name="actor"/> 处置（变更角色 / 注销）。
    ///
    /// 判定必须同时看**操作者**和**目标**两个角色，不能只看目标 ——
    /// 因为同样的目标账号，在管理员手里和在用户管理员手里，
    /// 可处置范围本就不同。旧版只按目标角色一刀切，正是"管理员连审计管理员
    /// 都注销不了"的根源。
    ///
    /// 规则一：**谁都不能处置自己**。
    ///   管理员若能注销或降级自己，系统就会失去能任命角色的账号（权力真空）。
    ///   而"操作者必是管理员、且操作后依然是自己"这条自我豁免，
    ///   恰好保证了无论怎么操作，系统里恒有至少一个管理员 ——
    ///   用一条自保护规则顶掉一长串按目标角色的例外，既简单又更牢靠。
    ///
    /// 规则二：**管理员可处置除自己以外的任意账号**，含审计管理员与其它管理员。
    ///   需求原文：admin 能进行一切的账号管理，包括对审计管理员进行注销。
    ///
    /// 规则三：**用户管理员仍只能处置普通用户与用户管理员**。
    ///   他是被管理员创建出来的下级角色，够不到审计管理员与管理员 ——
    ///   否则"下级能删上级"，角色分级就形同虚设。
    /// </summary>
    public static bool CanBeManagedBy(User actor, User target)
    {
        if (actor is null || target is null) return false;

        // 规则一：自我豁免（谁都不能动自己）
        if (IsSameAccount(actor, target)) return false;

        // 规则二：管理员 —— 范围全开
        if (actor.Role == UserRole.Admin) return true;

        // 规则三：其余管理者（用户管理员）—— 只够得到下级
        return target.Role is UserRole.User or UserRole.UserAdmin;
    }
}
