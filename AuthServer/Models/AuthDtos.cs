namespace AuthServer.Models;

public class RegisterRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;

    /// <summary>注册时绑定的邮箱（邮件功能启用时必填）。</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>发送到上述邮箱的 6 位验证码，用于证明邮箱归属。</summary>
    public string Code { get; set; } = string.Empty;
}

/// <summary>
/// 发送邮箱验证码请求。
/// Purpose 必须显式声明用途（REGISTER / RESET），
/// 使注册码无法用于重置密码、重置码也无法用于注册。
/// </summary>
public class SendEmailCodeRequest
{
    public string Purpose { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

/// <summary>
/// 忘记密码：用户名 + 邮箱 → 验证码 → 直接设置新密码。
/// 刻意不做"验证码直接登录"：系统内不存在不凭口令即可建立会话的路径。
/// </summary>
public class ResetPasswordRequest
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class ChangePasswordRequest
{
    public string Username { get; set; } = string.Empty;
    public string OldPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}

public class ApproveRequest
{
    public string Username { get; set; } = string.Empty;
    public string AdminUsername { get; set; } = string.Empty;
}

public class UnlockRequest
{
    public string Username { get; set; } = string.Empty;
    public string AdminUsername { get; set; } = string.Empty;
}

public class DeleteUserRequest
{
    public string Username { get; set; } = string.Empty;
    public string AdminUsername { get; set; } = string.Empty;
}

/// <summary>
/// 沉睡（僵尸）账号治理：冻结未被使用的账号。
///
/// 语义与 <see cref="DeleteUserRequest"/> 有本质区别 ——
/// 注销是**不可逆**的，冻结只是"暂时不让登录"，随时可解冻。
/// 两者分成两个接口，是为了让"点了注销"这个动作在代码层面
/// 就不可能被误当成"治理沉睡账号"来执行。
/// </summary>
public class FreezeUserRequest
{
    public string Username { get; set; } = string.Empty;
    public string AdminUsername { get; set; } = string.Empty;

    /// <summary>
    /// 冻结原因（可空）。治理动作应当能回答"为什么把他关了"，
    /// 留一个自由填写的位置比只记一个布尔值更有用。
    /// </summary>
    public string Reason { get; set; } = string.Empty;
}

/// <summary>
/// 管理员创建账号（普通用户 / 用户管理员 / 审计管理员）。
///
/// 与自助注册的区别：**不发验证码、建号即启用**。
/// 邮箱是**可选**的：留空即只凭口令登录（代价是无法自助找回密码）；
/// 填写则登记为已验证 —— 管理员是可信主体，不额外发码（理由见 User.EmailVerified）。
/// 因此这个接口本身就是一条高权限通道，必须由管理员发起，
/// 且要求二次校验操作者口令 —— 仅凭会话不足以证明是本人操作。
/// </summary>
public class CreateAccountRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// 目标角色：User（普通用户）/ UserAdmin（用户管理员）/ AuditAdmin（审计管理员）。
    /// 刻意不接受 Admin —— 不允许管理员自我复制。
    /// </summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>
    /// 可选绑定邮箱。留空 ⇒ 账号只凭口令登录，且无法自助找回密码。
    /// 填写 ⇒ 与自助注册用同一套格式校验与唯一性校验，但**不发验证码**，
    /// 直接置 EmailVerified=true（管理员代填视为已验证）；随后即可用「忘记密码」。
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>操作者（管理员）本人的登录口令，用于二次身份确认。</summary>
    public string OperatorPassword { get; set; } = string.Empty;
}

/// <summary>
/// 变更他人角色 —— 这是"指定某位管理员为审计管理员"的落地接口。
/// 同样需要操作者二次口令：角色任免是系统内权限最高的操作。
/// </summary>
public class SetRoleRequest
{
    public string Username { get; set; } = string.Empty;

    /// <summary>目标角色：User / UserAdmin / AuditAdmin（不接受 Admin）。</summary>
    public string Role { get; set; } = string.Empty;

    public string OperatorPassword { get; set; } = string.Empty;
}

public class LoginResult
{
    public string Username { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;

    /// <summary>角色标识：User / Admin / UserAdmin / AuditAdmin。</summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>角色中文显示名。</summary>
    public string RoleLabel { get; set; } = string.Empty;

    /// <summary>
    /// 是否具备用户管理能力（Admin / UserAdmin）。审计管理员为 false。
    /// 由 Role 派生，保留是为了兼容既有前端字段。
    /// </summary>
    public bool IsAdmin { get; set; }

    /// <summary>
    /// 服务端签发的会话票据。后续管理员接口需通过
    /// `Authorization: Bearer &lt;ticket&gt;` 携带该值。
    ///
    /// 注意：这是凭证，前端只应保存在本地会话存储中，
    /// 绝不能写进审计日志或任何可被他人读取的位置。
    /// </summary>
    public string Ticket { get; set; } = string.Empty;

    /// <summary>票据过期时刻（滑动续期的当前值）。</summary>
    public DateTime ExpiresAt { get; set; }
}
