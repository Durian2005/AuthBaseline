using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly MongoDbService _db;
    private const int MaxFailedAttempts = 3;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(3);

    public AuthController(MongoDbService db)
    {
        _db = db;
    }

    // 密码复杂度校验：至少8位，包含大小写字母和数字
    private static bool IsPasswordComplex(string password)
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

    private static string Norm(string? username) => username?.Trim().ToLowerInvariant() ?? string.Empty;

    private static UserResponse ToUserResponse(User u) => new()
    {
        Id = u.Id,
        Username = u.Username,
        Status = u.Status.ToString(),
        FailedLoginAttempts = u.FailedLoginAttempts,
        LockoutEnd = u.LockoutEnd,
        CreatedAt = u.CreatedAt,
        IsAdmin = u.IsAdmin
    };

    /** 管理员身份校验：仅当账号存在且 IsAdmin 为真时放行 */
    private async Task<User?> GetAdminAsync(string adminUsername)
    {
        var found = await _db.Users
            .Find(u => u.Username == Norm(adminUsername) && u.IsAdmin)
            .FirstOrDefaultAsync();
        return found is null ? null : found;
    }

    /**
     * 写入审计日志。
     *
     * 设计要点：
     *   - 审计是旁路记录，任何异常都不能影响主业务流程（鲁棒性要求）。
     *   - result 独立成列：登录成功与登录失败是同一个业务入口的两种结局，
     *     必须能被审计人员一眼区分。
     *   - target 记录被操作对象（注册/审核/解锁/注销/转让），便于按用户检索。
     *   - 任何分支（含越权、参数校验失败、目标不存在）都要落日志，
     *     否则"失败的操作"会在审计中凭空消失，形成盲区。
     */
    private async Task WriteAuditLogAsync(string operatorId, string operatorName, string action,
        string statusBefore, object request, object response, string statusAfter,
        string target = "", string result = AuditResult.Success)
    {
        try
        {
            await _db.AuditLogs.InsertOneAsync(new AuditLog
            {
                OperatorId = operatorId,
                OperatorName = operatorName,
                Action = action,
                StatusBefore = statusBefore,
                Request = JsonSerializer.Serialize(request),
                Response = JsonSerializer.Serialize(response),
                StatusAfter = statusAfter,
                Result = result,
                Target = target,
                Timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AuditLog] 写入失败（不影响主流程）: {ex.Message}");
        }
    }

    /** 管理员权限不足：统一返回 401，并留下"失败"审计记录 */
    private async Task<IActionResult> AdminDeniedAsync(string adminUsername, string action,
        object request, string target = "")
    {
        var resp = new ApiResponse { Success = false, Code = "UNAUTHORIZED", Message = "无管理员权限" };
        await WriteAuditLogAsync("anonymous", Norm(adminUsername), action, "N/A", request, resp, "N/A",
            target, AuditResult.Failed);
        return Unauthorized(resp);
    }

    /* ==================== 注册 ==================== */

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req)
    {
        var sanitizedUsername = Norm(req.Username);
        var requestLog = new { req.Username };

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "用户名或密码不能为空" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.Password))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "WEAK_PASSWORD",
                Message = "密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return BadRequest(resp);
        }

        var existing = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (existing != null)
        {
            var resp = new ApiResponse { Success = false, Code = "DUPLICATE_USERNAME", Message = "用户名已存在" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, resp, existing.Status.ToString(),
                sanitizedUsername, AuditResult.Failed);
            return Conflict(resp);
        }

        var user = new User
        {
            Username = sanitizedUsername,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password),
            Status = UserStatus.Pending,
            FailedLoginAttempts = 0,
            CreatedAt = DateTime.UtcNow
        };

        await _db.Users.InsertOneAsync(user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = "注册成功，等待管理员审核",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.Register, "N/A", requestLog, response, user.Status.ToString(),
            sanitizedUsername, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 登录 ==================== */

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        var sanitizedUsername = Norm(req.Username);
        // 口令绝不进入日志，请求里只保留用户名
        var requestLog = new { req.Username };

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "用户名或密码不能为空" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (user == null)
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "用户名或密码错误" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        // 锁定期间，即使正确口令也拒绝登录
        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
        {
            var remaining = (int)(user.LockoutEnd.Value - DateTime.UtcNow).TotalSeconds;
            var resp = new ApiResponse
            {
                Success = false,
                Code = "ACCOUNT_LOCKED",
                Message = $"账号已锁定，请 {remaining} 秒后再试",
                Data = new { LockoutEnd = user.LockoutEnd, RemainingSeconds = remaining }
            };
            await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, statusBefore,
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        // 如果锁定时间已过，自动恢复为启用状态
        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue && user.LockoutEnd.Value <= DateTime.UtcNow)
        {
            user.Status = UserStatus.Enabled;
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            statusBefore = UserStatus.Enabled.ToString();
        }

        if (user.Status == UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = "PENDING_APPROVAL", Message = "账号待审核，请联系管理员" };
            await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, user.Status.ToString(),
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        var passwordValid = BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash);
        if (!passwordValid)
        {
            user.FailedLoginAttempts++;
            string? message;
            string code;
            UserStatus newStatus = user.Status;
            DateTime? lockoutEnd = user.LockoutEnd;

            if (user.FailedLoginAttempts >= MaxFailedAttempts)
            {
                newStatus = UserStatus.Locked;
                lockoutEnd = DateTime.UtcNow.Add(LockoutDuration);
                user.Status = newStatus;
                user.LockoutEnd = lockoutEnd;
                message = $"连续输错 {MaxFailedAttempts} 次密码，账号已锁定 {LockoutDuration.TotalMinutes} 分钟";
                code = "ACCOUNT_LOCKED";
            }
            else
            {
                message = $"密码错误，还剩 {MaxFailedAttempts - user.FailedLoginAttempts} 次机会";
                code = "INVALID_CREDENTIALS";
            }

            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            var resp = new ApiResponse
            {
                Success = false,
                Code = code,
                Message = message,
                Data = new { FailedAttempts = user.FailedLoginAttempts, LockoutEnd = lockoutEnd }
            };
            await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, user.Status.ToString(),
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        // 登录成功，重置失败计数
        if (user.FailedLoginAttempts > 0)
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
        }

        var successResp = new ApiResponse<LoginResult>
        {
            Success = true,
            Code = "OK",
            Message = "登录成功",
            Data = new LoginResult
            {
                Username = user.Username,
                Status = user.Status.ToString(),
                IsAdmin = user.IsAdmin
            }
        };
        await WriteAuditLogAsync(user.Id, user.Username, AuditAction.LoginSuccess, statusBefore, requestLog, successResp, user.Status.ToString(),
            sanitizedUsername, AuditResult.Success);
        return Ok(successResp);
    }

    /* ==================== 管理员：审核 ==================== */

    [HttpPost("approve")]
    public async Task<IActionResult> Approve([FromBody] ApproveRequest req)
    {
        var admin = await GetAdminAsync(req.AdminUsername);
        if (admin == null) return await AdminDeniedAsync(req.AdminUsername, AuditAction.Approve, new { req.AdminUsername, req.Username }, Norm(req.Username));

        var user = await _db.Users.Find(u => u.Username == Norm(req.Username)).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = "NOT_FOUND", Message = "用户不存在" };
            await WriteAuditLogAsync(admin.Id, admin.Username, AuditAction.Approve, "N/A", new { req.AdminUsername, req.Username }, missing, "N/A",
                Norm(req.Username), AuditResult.Failed);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();
        if (user.Status != UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = "NOT_PENDING", Message = "该用户不处于待审核状态" };
            await WriteAuditLogAsync(admin.Id, admin.Username, AuditAction.Approve, statusBefore, new { req.AdminUsername, req.Username }, resp, user.Status.ToString(),
                user.Username, AuditResult.Failed);
            return BadRequest(resp);
        }

        user.Status = UserStatus.Enabled;
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = "审核通过",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync(admin.Id, admin.Username, AuditAction.Approve, statusBefore, new { req.AdminUsername, req.Username }, response, user.Status.ToString(),
            user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：解锁 ==================== */

    [HttpPost("unlock")]
    public async Task<IActionResult> Unlock([FromBody] UnlockRequest req)
    {
        var admin = await GetAdminAsync(req.AdminUsername);
        if (admin == null) return await AdminDeniedAsync(req.AdminUsername, AuditAction.Unlock, new { req.AdminUsername, req.Username }, Norm(req.Username));

        var user = await _db.Users.Find(u => u.Username == Norm(req.Username)).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = "NOT_FOUND", Message = "用户不存在" };
            await WriteAuditLogAsync(admin.Id, admin.Username, AuditAction.Unlock, "N/A", new { req.AdminUsername, req.Username }, missing, "N/A",
                Norm(req.Username), AuditResult.Failed);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();
        if (user.Status != UserStatus.Locked)
        {
            var resp = new ApiResponse { Success = false, Code = "NOT_LOCKED", Message = "该用户未被锁定" };
            await WriteAuditLogAsync(admin.Id, admin.Username, AuditAction.Unlock, statusBefore, new { req.AdminUsername, req.Username }, resp, user.Status.ToString(),
                user.Username, AuditResult.Failed);
            return BadRequest(resp);
        }

        user.Status = UserStatus.Enabled;
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = "账号已解锁",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync(admin.Id, admin.Username, AuditAction.Unlock, statusBefore, new { req.AdminUsername, req.Username }, response, user.Status.ToString(),
            user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：注销用户 ==================== */

    [HttpPost("delete-user")]
    public async Task<IActionResult> DeleteUser([FromBody] DeleteUserRequest req)
    {
        var admin = await GetAdminAsync(req.AdminUsername);
        if (admin == null) return await AdminDeniedAsync(req.AdminUsername, AuditAction.DeleteUser, new { req.AdminUsername, req.Username }, Norm(req.Username));

        var username = Norm(req.Username);
        var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = "NOT_FOUND", Message = "用户不存在" };
            await WriteAuditLogAsync(admin.Id, admin.Username, AuditAction.DeleteUser, "N/A", new { req.AdminUsername, req.Username }, missing, "N/A",
                username, AuditResult.Failed);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();

        // 禁止注销管理员账号（含注销自己），避免系统失去管理员导致无法恢复
        if (user.IsAdmin)
        {
            var denied = new ApiResponse { Success = false, Code = "CANNOT_DELETE_ADMIN", Message = "不能注销管理员账号" };
            await WriteAuditLogAsync(admin.Id, admin.Username, AuditAction.DeleteUser, statusBefore, new { req.AdminUsername, req.Username }, denied, statusBefore,
                user.Username, AuditResult.Failed);
            return BadRequest(denied);
        }

        await _db.Users.DeleteOneAsync(u => u.Id == user.Id);

        var response = new ApiResponse
        {
            Success = true,
            Code = "OK",
            Message = $"已注销用户「{user.Username}」",
            Data = new { Username = user.Username }
        };
        await WriteAuditLogAsync(admin.Id, admin.Username, AuditAction.DeleteUser, statusBefore, new { req.AdminUsername, req.Username }, response, "Deleted",
            user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：权限转让 ==================== */

    /**
     * 将管理员权限转让给另一位合法用户。
     *
     * 安全约束：
     *   1. 操作者必须是现任管理员，且需二次校验其登录口令（防止会话被冒用后直接夺权）。
     *   2. 受让方必须是"合法用户"：账号已启用（非待审核 / 锁定 / 禁用），且当前不是管理员。
     *   3. 先提升受让方、再降级自己 —— 任何一步中断都不会让系统陷入无管理员状态。
     *   4. 全过程（含每次失败）写入审计日志；请求日志中绝不记录口令。
     */
    [HttpPost("transfer-admin")]
    public async Task<IActionResult> TransferAdmin([FromBody] TransferAdminRequest req)
    {
        const string action = AuditAction.TransferAdmin;
        var targetName = Norm(req.TargetUsername);
        // 口令不入日志
        var requestLog = new { req.AdminUsername, req.TargetUsername };

        if (string.IsNullOrWhiteSpace(targetName) || string.IsNullOrWhiteSpace(req.Password))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "目标用户名与管理员口令不能为空" };
            await WriteAuditLogAsync("anonymous", Norm(req.AdminUsername), action, "N/A", requestLog, resp, "N/A",
                targetName, AuditResult.Failed);
            return BadRequest(resp);
        }

        var admin = await GetAdminAsync(req.AdminUsername);
        if (admin == null) return await AdminDeniedAsync(req.AdminUsername, action, requestLog, targetName);

        if (!BCrypt.Net.BCrypt.Verify(req.Password, admin.PasswordHash))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "管理员口令校验失败，已拒绝转让" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, $"{admin.Username}·管理员", requestLog, resp, $"{admin.Username}·管理员",
                targetName, AuditResult.Failed);
            return Unauthorized(resp);
        }

        if (targetName == admin.Username)
        {
            var resp = new ApiResponse { Success = false, Code = "CANNOT_TRANSFER_SELF", Message = "不能把权限转让给自己" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, $"{admin.Username}·管理员", requestLog, resp, $"{admin.Username}·管理员",
                targetName, AuditResult.Failed);
            return BadRequest(resp);
        }

        var target = await _db.Users.Find(u => u.Username == targetName).FirstOrDefaultAsync();
        if (target == null)
        {
            var resp = new ApiResponse { Success = false, Code = "NOT_FOUND", Message = "目标用户不存在" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, $"{admin.Username}·管理员", requestLog, resp, $"{admin.Username}·管理员",
                targetName, AuditResult.Failed);
            return NotFound(resp);
        }

        var statusBefore = target.IsAdmin ? $"{target.Username}·管理员" : target.Status.ToString();

        // 合法用户判定：只有处于启用状态的账号才具备接管管理员权限的资格
        if (target.Status != UserStatus.Enabled)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "TARGET_NOT_ELIGIBLE",
                Message = $"目标账号当前状态为「{target.Status}」，只有已启用的账号才能接管管理员权限"
            };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, statusBefore, requestLog, resp, statusBefore,
                target.Username, AuditResult.Failed);
            return BadRequest(resp);
        }

        if (target.IsAdmin)
        {
            var resp = new ApiResponse { Success = false, Code = "TARGET_ALREADY_ADMIN", Message = "该用户已经是管理员" };
            await WriteAuditLogAsync(admin.Id, admin.Username, action, statusBefore, requestLog, resp, statusBefore,
                target.Username, AuditResult.Failed);
            return BadRequest(resp);
        }

        // 先提升受让方，再撤销自己的管理员身份：任何时刻都保证系统内至少有一名管理员
        target.IsAdmin = true;
        await _db.Users.ReplaceOneAsync(u => u.Id == target.Id, target);

        admin.IsAdmin = false;
        await _db.Users.ReplaceOneAsync(u => u.Id == admin.Id, admin);

        var response = new ApiResponse
        {
            Success = true,
            Code = "OK",
            Message = $"已将管理员权限转让给「{target.Username}」，您已变为普通用户",
            Data = new { Username = target.Username, PreviousAdmin = admin.Username }
        };
        await WriteAuditLogAsync(admin.Id, admin.Username, action, $"{admin.Username}·管理员", requestLog, response, $"{target.Username}·管理员",
            target.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 修改密码 ==================== */

    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req)
    {
        var sanitizedUsername = Norm(req.Username);
        // 新旧口令都不入日志
        var requestLog = new { req.Username };

        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(req.OldPassword) || string.IsNullOrWhiteSpace(req.NewPassword))
        {
            var resp = new ApiResponse { Success = false, Code = "EMPTY_FIELDS", Message = "字段不能为空" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.ChangePassword, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.NewPassword))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = "WEAK_PASSWORD",
                Message = "新密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.ChangePassword, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return BadRequest(resp);
        }

        var user = await _db.Users.Find(u => u.Username == sanitizedUsername).FirstOrDefaultAsync();
        if (user == null)
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "用户名或旧密码错误" };
            await WriteAuditLogAsync("anonymous", sanitizedUsername, AuditAction.ChangePassword, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();

        if (!BCrypt.Net.BCrypt.Verify(req.OldPassword, user.PasswordHash))
        {
            var resp = new ApiResponse { Success = false, Code = "INVALID_CREDENTIALS", Message = "旧密码错误" };
            await WriteAuditLogAsync(user.Id, user.Username, AuditAction.ChangePassword, statusBefore, requestLog, resp, statusBefore,
                sanitizedUsername, AuditResult.Failed);
            return Unauthorized(resp);
        }

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword);
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = "OK",
            Message = "密码修改成功，旧口令立即失效",
            Data = ToUserResponse(user)
        };
        await WriteAuditLogAsync(user.Id, user.Username, AuditAction.ChangePassword, statusBefore, requestLog, response, user.Status.ToString(),
            sanitizedUsername, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 查询 ==================== */

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers([FromQuery] string adminUsername)
    {
        var admin = await _db.Users.Find(u => u.Username == Norm(adminUsername) && u.IsAdmin).FirstOrDefaultAsync();
        if (admin == null)
        {
            return Unauthorized(new ApiResponse { Success = false, Code = "UNAUTHORIZED", Message = "无管理员权限" });
        }

        var users = await _db.Users.Find(_ => true).ToListAsync();
        return Ok(new ApiResponse<List<UserResponse>>
        {
            Success = true,
            Code = "OK",
            Data = users.Select(ToUserResponse).ToList()
        });
    }

    [HttpGet("logs")]
    public async Task<IActionResult> GetLogs([FromQuery] string adminUsername)
    {
        var admin = await _db.Users.Find(u => u.Username == Norm(adminUsername) && u.IsAdmin).FirstOrDefaultAsync();
        if (admin == null)
        {
            return Unauthorized(new ApiResponse { Success = false, Code = "UNAUTHORIZED", Message = "无管理员权限" });
        }

        var logs = await _db.AuditLogs.Find(_ => true).SortByDescending(l => l.Timestamp).Limit(200).ToListAsync();
        return Ok(new ApiResponse<List<AuditLog>>
        {
            Success = true,
            Code = "OK",
            Data = logs
        });
    }
}
