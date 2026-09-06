namespace AuthServer.Models;

public class RegisterRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
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
