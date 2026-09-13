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
/// 管理员权限转让请求。
/// Password 为现任管理员的登录口令：转让属于特权变更，必须二次校验操作者身份，
/// 仅凭会话中的用户名不足以证明操作者本人。
/// </summary>
public class TransferAdminRequest
{
    public string AdminUsername { get; set; } = string.Empty;
    public string TargetUsername { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class LoginResult
{
    public string Username { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
}
