using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthServer.Controllers;

/**
 * 用户管理接口：审核、解锁/解冻、冻结、注销、创建账号、变更角色、用户与沉睡清单。
 *
 * 全部依赖票据鉴权，且**两个级别刻意分开**：
 *   · RequireUserAdminAsync（Admin / UserAdmin）—— 审核、解锁、冻结、注销、看清单
 *   · RequireAdminAsync（仅 Admin）      —— 创建账号、变更他人角色
 * 用户管理员能管账号，但不能任免角色；任免角色只属于 Admin。
 * 路由前缀仍是 api/auth，与拆分前逐一对应。
 */
[ApiController]
[Route("api/auth")]
public class UserAdminController : AuthControllerBase
{
    public UserAdminController(MongoDbService db, AuditWriter auditWriter, SessionService sessions,
        PepperProvider pepper, IConfiguration configuration)
        : base(db, auditWriter, sessions, pepper, configuration)
    {
    }

    /* ==================== 管理员：审核 ==================== */

    [HttpPost("approve")]
    public async Task<IActionResult> Approve([FromBody] ApproveRequest req)
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.Approve, Norm(req.Username));
        if (deny != null) return deny;
        var requestLog = new { req.Username };

        var user = await _db.Users.Find(u => u.Username == Norm(req.Username)).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = BusinessCode.NotFound, Message = "用户不存在" };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.Approve, "N/A", requestLog, missing, "N/A",
                Norm(req.Username), AuditResult.Failed, AuditReason.NotFound);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();
        if (user.Status != UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.NotPending, Message = "该用户不处于待审核状态" };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.Approve, statusBefore, requestLog, resp, user.Status.ToString(),
                user.Username, AuditResult.Failed, AuditReason.NotPending);
            return BadRequest(resp);
        }

        user.Status = UserStatus.Enabled;
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = "审核通过",
            Data = ToUserResponse(user)
        };
        await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.Approve, statusBefore, requestLog, response, user.Status.ToString(),
            user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：解锁 / 解除冻结 ==================== */

    /**
     * 恢复账号为可登录状态。一个接口承担两种恢复，按**当前状态**分流：
     *
     *   · Locked   —— 口令连错触发的自动锁定，解开后清空失败计数；
     *   · Disabled —— 沉睡治理冻结（或人工禁用），解开即恢复登录能力。
     *
     * 为什么合并而不是新开一个 /unfreeze：
     *   两者的**效果完全相同**（让账号重新能登录），对调用方而言
     *   "把这个账号恢复" 是一个动作。分成两个接口会逼前端先判断状态再选接口，
     *   而状态可能在两跳之间变化（比如期间自动锁定到期又触发了一次），
     *   反而更容易出错。用一个接口、由服务端按当前状态决定语义，更稳。
     *
     * 但审计动作**必须分开**（UNLOCK vs DORMANT_RESTORE）：
     *   "解开了口令连错的锁"和"把沉睡治理冻结的账号放了回来"是两类事件，
     *   审计员要能单独捞出后者，评估治理效果。
     */
    [HttpPost("unlock")]
    public async Task<IActionResult> Unlock([FromBody] UnlockRequest req)
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.Unlock, Norm(req.Username));
        if (deny != null) return deny;
        var requestLog = new { req.Username };

        var user = await _db.Users.Find(u => u.Username == Norm(req.Username)).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = BusinessCode.NotFound, Message = "用户不存在" };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.Unlock, "N/A", requestLog, missing, "N/A",
                Norm(req.Username), AuditResult.Failed, AuditReason.NotFound);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();

        // 分流一：口令连错造成的锁定
        if (user.Status == UserStatus.Locked)
        {
            user.Status = UserStatus.Enabled;
            ResetFailedAttempts(user);
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

            var okResp = new ApiResponse<UserResponse>
            {
                Success = true,
                Code = BusinessCode.Ok,
                Message = "账号已解锁",
                Data = ToUserResponse(user)
            };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.Unlock, statusBefore, requestLog, okResp, user.Status.ToString(),
                user.Username, AuditResult.Success);
            return Ok(okResp);
        }

        // 分流二：沉睡治理冻结（Disabled）。
        // 处置范围同样过 CanBeManagedBy —— 解冻是"让一个账号重新能登录"，
        // 与冻结是一体两面的权限，不能一边受限一边放开。
        if (user.Status == UserStatus.Disabled)
        {
            if (!UserRoles.CanBeManagedBy(admin!, user))
            {
                var isSelf = UserRoles.IsSameAccount(admin!, user);
                var deniedResp = new ApiResponse
                {
                    Success = false,
                    Code = BusinessCode.ForbiddenTarget,
                    Message = isSelf
                        ? "不能解除自己账号的冻结。"
                        : $"当前身份「{UserRoles.Label(admin!.Role)}」不能解除"
                            + $"「{UserRoles.Label(user.Role)}」账号的冻结。"
                };
                await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DormantRestore, statusBefore,
                    requestLog, deniedResp, statusBefore, user.Username, AuditResult.Failed, AuditReason.ForbiddenTarget);
                return BadRequest(deniedResp);
            }

            user.Status = UserStatus.Enabled;
            // 冻结期间的"停用起点"清掉：账号已恢复，留着它会让人误以为还有效。
            user.DormantFrozenAt = null;
            // 顺带清空可能残留的锁定与失败计数，避免"解冻后立刻发现自己被锁着"。
            ResetFailedAttempts(user);
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

            var restored = new ApiResponse<UserResponse>
            {
                Success = true,
                Code = BusinessCode.Ok,
                Message = "账号已解除冻结，可正常登录",
                Data = ToUserResponse(user)
            };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DormantRestore, statusBefore, requestLog,
                restored, user.Status.ToString(), user.Username, AuditResult.Success);
            return Ok(restored);
        }

        // 其余状态（Pending / Enabled）没有"可解除"的东西
        var resp = new ApiResponse { Success = false, Code = BusinessCode.NotLocked, Message = "该用户未被锁定或冻结" };
        await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.Unlock, statusBefore, requestLog, resp, user.Status.ToString(),
            user.Username, AuditResult.Failed, AuditReason.NotLocked);
        return BadRequest(resp);
    }

    /* ==================== 管理员：冻结（沉睡账号治理） ==================== */

    /**
     * 冻结一个长期未使用的账号。
     *
     * 冻结 = 置为 Disabled：
     *   · 登录路径已检查该状态并直接拒绝（ACCOUNT_DISABLED），因此冻结即可生效；
     *   · 这是**可逆**操作 —— 由 Unlock 接口解除，与"注销"有本质区别。
     *
     * 三条结构性约束（缺一不可）：
     *   ① 受保护角色不得冻结（Admin / UserAdmin / AuditAdmin）——
     *      管理账号再久不登录也不是僵尸；冻结它等于拿走系统的一项能力。
     *      这条在**服务端**强制，不依赖前端隐藏按钮。
     *   ② 过 CanBeManagedBy（含自我豁免）—— 与注销同一套授权，不另起规则。
     *   ③ 立即吊销其全部票据 —— 否则"冻结"只是挡住了下次登录，
     *      手里已经拿到的票据仍能继续用，等于没冻结。
     */
    [HttpPost("freeze-user")]
    public async Task<IActionResult> FreezeUser([FromBody] FreezeUserRequest req)
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.DormantFreeze, Norm(req.Username));
        if (deny != null) return deny;
        var requestLog = new { req.Username, req.Reason };

        var username = Norm(req.Username);
        var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = BusinessCode.NotFound, Message = "用户不存在" };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DormantFreeze, "N/A", requestLog, missing, "N/A",
                username, AuditResult.Failed, AuditReason.NotFound);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();

        // 约束①：受保护角色一律不可冻结。先判角色再判关系 ——
        // 这一条与"谁在操作"无关，是账号自身的性质，必须排在最前面，
        // 免得"管理员能处置任意账号"这条更宽的规则把保护范围吞掉。
        if (UserRoles.IsDormantProtected(user.Role))
        {
            var protectedResp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.DormantProtectedRole,
                Message = $"「{UserRoles.Label(user.Role)}」属于管理角色，不参与沉睡账号冻结。"
            };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DormantFreeze, statusBefore, requestLog,
                protectedResp, statusBefore, user.Username, AuditResult.Failed, AuditReason.DormantProtectedRole);
            return BadRequest(protectedResp);
        }

        // 约束②：与注销同一套授权（含自我豁免）
        if (!UserRoles.CanBeManagedBy(admin!, user))
        {
            var isSelf = UserRoles.IsSameAccount(admin!, user);
            var deniedResp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.ForbiddenTarget,
                Message = isSelf
                    ? "不能冻结自己的账号。"
                    : $"当前身份「{UserRoles.Label(admin!.Role)}」不能冻结"
                        + $"「{UserRoles.Label(user.Role)}」账号。"
            };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DormantFreeze, statusBefore, requestLog,
                deniedResp, statusBefore, user.Username, AuditResult.Failed, AuditReason.ForbiddenTarget);
            return BadRequest(deniedResp);
        }

        // 已经是冻结态就没必要再来一次 —— 重复冻结只会往审计里灌噪声
        if (user.Status == UserStatus.Disabled)
        {
            var already = new ApiResponse { Success = false, Code = BusinessCode.AlreadyFrozen, Message = "该账号已被冻结" };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DormantFreeze, statusBefore, requestLog,
                already, statusBefore, user.Username, AuditResult.Failed, AuditReason.NotFrozen);
            return BadRequest(already);
        }

        if (user.Status != UserStatus.Enabled)
        {
            var wrongState = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.AccountNotEnabled,
                Message = "只有启用中的账号才能被冻结"
            };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DormantFreeze, statusBefore, requestLog,
                wrongState, statusBefore, user.Username, AuditResult.Failed, AuditReason.AccountNotEnabled);
            return BadRequest(wrongState);
        }

        user.Status = UserStatus.Disabled;
        user.DormantFrozenAt = DateTime.UtcNow;
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        // 约束③：冻结后立即作废其名下全部票据。
        // 吊销失败不阻断 —— 账号状态已经落库，登录路径会拦住下一次尝试，
        // 退回失败反而让人以为"没冻结成功"而反复点。
        await _sessions.RevokeAllForUserAsync(user.Username, "账号因长期未登录被冻结");

        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = $"已冻结账号「{user.Username}」，可随时解除",
            Data = ToUserResponse(user)
        };
        await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DormantFreeze, statusBefore, requestLog,
            response, user.Status.ToString(), user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：注销用户 ==================== */

    [HttpPost("delete-user")]
    public async Task<IActionResult> DeleteUser([FromBody] DeleteUserRequest req)
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.DeleteUser, Norm(req.Username));
        if (deny != null) return deny;
        var requestLog = new { req.Username };

        var username = Norm(req.Username);
        var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = BusinessCode.NotFound, Message = "用户不存在" };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DeleteUser, "N/A", requestLog, missing, "N/A",
                username, AuditResult.Failed, AuditReason.NotFound);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();

        // 处置范围随操作者身份而定（判定集中在 UserRoles.CanBeManagedBy）：
        //   · 管理员（Admin）—— 除自己以外任何账号都能注销，含审计管理员与其它管理员；
        //   · 用户管理员（UserAdmin）—— 只能注销普通用户与用户管理员，够不到上级。
        //
        // 唯一不随身份变化、也不随目标角色变化的例外是"自己"：
        // 若允许自我注销，操作者就可能把系统里最后一个管理员删掉，
        // 从而再没有人能任命角色。自我豁免同时保证了"操作者操作完仍是管理员"。
        if (!UserRoles.CanBeManagedBy(admin!, user))
        {
            var isSelf = UserRoles.IsSameAccount(admin!, user);
            var denied = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.ForbiddenTarget,
                Message = isSelf
                    ? "不能注销自己的账号。如需转让职责，请先创建另一位管理员。"
                    : $"当前身份「{UserRoles.Label(admin!.Role)}」不能注销"
                        + $"「{UserRoles.Label(user.Role)}」账号。"
            };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DeleteUser, statusBefore, requestLog, denied, statusBefore,
                user.Username, AuditResult.Failed, AuditReason.ForbiddenTarget);
            return BadRequest(denied);
        }

        await _db.Users.DeleteOneAsync(u => u.Id == user.Id);

        // 账号已被注销，其名下所有票据必须立即失效 ——
        // 否则被注销的人手里若还留着票据，仍能继续调用接口。
        await _sessions.RevokeAllForUserAsync(user.Username, "账号被管理员注销");

        var response = new ApiResponse
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = $"已注销用户「{user.Username}」",
            Data = new { Username = user.Username }
        };
        await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.DeleteUser, statusBefore, requestLog, response, "Deleted",
            user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：创建账号 ==================== */

    /// <summary>
    /// 允许被创建的两种角色。
    ///
    /// 刻意**不含 Admin**：Admin 是角色任免权的持有者，若能凭空再造一个 Admin，
    /// 就存在"管理员自我复制、稀释责任"的路径。需要有人分担任免权时，
    /// 应当由人来决定并明确留痕，而不是让程序放开这个口子。
    /// </summary>
    private static bool CanBeCreatedRole(UserRole role) =>
        role is UserRole.UserAdmin or UserRole.AuditAdmin;

    /**
     * 由管理员创建「用户管理员」或「审计管理员」账号。
     *
     * 与自助注册的本质区别：
     *   - **不绑邮箱、不发验证码**（需求明确要求）；
     *   - **建号即启用**，不走待审核；
     *   - 因此这个接口本身就是一条高权限通道 —— 一旦被冒用就能凭空造出管理员，
     *     所以必须**二次校验操作者本人的登录口令**：
     *     仅凭会话票据不足以证明是本人操作，票据被盗时攻击者不该能直接造账号。
     *
     * 校验顺序上把口令校验放在"用户名查重"之前：
     * 查重会回答"这个用户名是否存在"，属于可被利用的信息；
     * 先证明是本人，再去查库。
     */
    [HttpPost("create-account")]
    public async Task<IActionResult> CreateAccount([FromBody] CreateAccountRequest req)
    {
        const string action = AuditAction.CreateAccount;
        var targetName = Norm(req.Username);
        // 初始口令与操作者口令都不入日志
        var requestLog = new { req.Username, req.Role };

        if (string.IsNullOrWhiteSpace(targetName) || string.IsNullOrWhiteSpace(req.Password)
            || string.IsNullOrWhiteSpace(req.Role))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "用户名、初始口令与角色不能为空" };
            await _auditWriter.WriteAsync("anonymous", "anonymous", action, "N/A", requestLog, resp, "N/A",
                targetName, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        var (admin, deny) = await RequireAdminAsync(action, targetName);
        if (deny != null) return deny;
        var operatorLabel = $"{admin!.Username}·{UserRoles.Label(admin.Role)}";

        if (!UserRoles.TryParse(req.Role, out var newRole) || !CanBeCreatedRole(newRole))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.ForbiddenRole,
                Message = "只能创建「用户管理员」或「审计管理员」账号"
            };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.ForbiddenRole);
            return BadRequest(resp);
        }

        if (!IsPasswordComplex(req.Password))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.WeakPassword,
                Message = "初始密码必须至少8位，并同时包含大写字母、小写字母和数字"
            };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.WeakPassword);
            return BadRequest(resp);
        }

        // 二次口令：创建管理员是特权变更，仅凭会话不足以证明是本人操作
        if (!PasswordHasher.Verify(req.OperatorPassword, admin.PasswordHash, _pepper.Pepper).Valid)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidCredentials, Message = "管理员口令校验失败，已拒绝创建" };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        var existing = await _db.Users.Find(u => u.Username == targetName).FirstOrDefaultAsync();
        if (existing != null)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.DuplicateUsername, Message = "用户名已存在" };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.DuplicateUsername);
            return Conflict(resp);
        }

        var user = new User
        {
            Username = targetName,
            PasswordHash = PasswordHasher.Hash(req.Password, _pepper.Pepper),
            Status = UserStatus.Enabled,
            Role = newRole,
            // 管理员创建的账号一律不绑邮箱，只凭口令登录（需求明确要求）
            Email = null,
            EmailVerified = false,
            FailedLoginAttempts = 0,
            CreatedAt = DateTime.UtcNow
        };
        await _db.Users.InsertOneAsync(user);

        var newLabel = $"{user.Username}·{UserRoles.Label(newRole)}";
        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = $"已创建{UserRoles.Label(newRole)}账号「{user.Username}」，该账号无需邮箱、可直接登录",
            Data = ToUserResponse(user)
        };
        await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, response,
            newLabel, user.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 管理员：变更他人角色 ==================== */

    /**
     * 变更他人角色 —— "指定某位管理员为审计管理员"就是走这里。
     *
     * 三条硬约束：
     *   1. 只能由 Admin 发起（AccessLevel.Admin），用户管理员无权任免角色；
     *   2. 不能把任何人设为 Admin，与 create-account 同理，杜绝管理员自我复制；
     *   3. **不能变更自己** —— 若管理员能改自己的角色，他就能把自己降成审计管理员
     *      去读日志，职责分离当场失效。自我提权必须是死路。
     *
     * 除此之外，处置范围随操作者身份而定（见 UserRoles.CanBeManagedBy）：
     * 管理员可变更除自己以外任意账号的角色，含审计管理员与其它管理员。
     * SetRole 的门槛是 AccessLevel.Admin，所以实际能走到这里的操作者只有管理员，
     * 该判定当前恒真 —— 保留它是为了让规则只写一处：日后若有更低的角色
     * 获得任免权，无需回头再补目标侧的校验。
     *
     * 变更成功后立刻吊销目标账号的全部票据：
     * 旧票据虽然因"每次实时查库"而立刻失去（或获得）对应权限，
     * 但让对方重新登录、亲眼看到自己的新身份，比"权限悄悄变了"更清楚。
     */
    [HttpPost("set-role")]
    public async Task<IActionResult> SetRole([FromBody] SetRoleRequest req)
    {
        const string action = AuditAction.SetRole;
        var targetName = Norm(req.Username);
        var requestLog = new { req.Username, req.Role };

        if (string.IsNullOrWhiteSpace(targetName) || string.IsNullOrWhiteSpace(req.Role))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "目标用户名与目标角色不能为空" };
            await _auditWriter.WriteAsync("anonymous", "anonymous", action, "N/A", requestLog, resp, "N/A",
                targetName, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        var (admin, deny) = await RequireAdminAsync(action, targetName);
        if (deny != null) return deny;
        var operatorLabel = $"{admin!.Username}·{UserRoles.Label(admin.Role)}";

        if (!UserRoles.TryParse(req.Role, out var newRole))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidRole, Message = "无法识别的角色标识" };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.ForbiddenRole);
            return BadRequest(resp);
        }

        // 约束 2：不能把任何人（包括自己）设为管理员
        if (newRole == UserRole.Admin)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.ForbiddenRole,
                Message = "不能把账号设为「管理员」。如需分担用户管理，请创建「用户管理员」。"
            };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.ForbiddenRole);
            return BadRequest(resp);
        }

        // 约束 3：不能变更自己
        if (targetName == admin.Username)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.CannotSetOwnRole,
                Message = "不能变更自己的角色。如需调整职责，请由另一位管理员操作。"
            };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.ForbiddenRole);
            return BadRequest(resp);
        }

        // 二次口令：角色任免是系统内权限最高的操作
        if (!PasswordHasher.Verify(req.OperatorPassword, admin.PasswordHash, _pepper.Pepper).Valid)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidCredentials, Message = "管理员口令校验失败，已拒绝变更" };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.InvalidCredentials);
            return Unauthorized(resp);
        }

        var target = await _db.Users.Find(u => u.Username == targetName).FirstOrDefaultAsync();
        if (target == null)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.NotFound, Message = "目标用户不存在" };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.NotFound);
            return NotFound(resp);
        }

        var statusBefore = $"{target.Username}·{UserRoles.Label(target.Role)}";

        // 目标侧的统一判定：管理员除自己外皆可处置（含审计管理员与其它管理员）。
        // 自己已被上面的约束 3 提前拦下，这里兜住的是"更低身份的操作者"。
        if (!UserRoles.CanBeManagedBy(admin, target))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.ForbiddenTarget,
                Message = $"当前身份「{UserRoles.Label(admin.Role)}」不能变更"
                    + $"「{UserRoles.Label(target.Role)}」账号的角色"
            };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, statusBefore, requestLog, resp, statusBefore,
                target.Username, AuditResult.Failed, AuditReason.ForbiddenTarget);
            return BadRequest(resp);
        }

        if (target.Role == newRole)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.RoleUnchanged,
                Message = $"该账号的角色已经是「{UserRoles.Label(newRole)}」"
            };
            // 这里原先误用了 AuditReason.EmptyFields（"字段为空"），与事实不符。
            // 语义上属于"目标状态与请求状态一致，无需变更"，单独给一条码，
            // 免得审计员按 EMPTY_FIELDS 检索时捞出一堆压根没缺字段的记录。
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, statusBefore, requestLog, resp, statusBefore,
                target.Username, AuditResult.Failed, AuditReason.RoleUnchanged);
            return BadRequest(resp);
        }

        target.Role = newRole;
        await _db.Users.ReplaceOneAsync(u => u.Id == target.Id, target);

        // 角色变了，旧票据必须作废：让当事人重新登录、以新身份建立会话。
        // 虽然实时查库已让旧票据立刻失去旧权限，但明确吊销能避免
        // "界面还停留在旧身份"带来的困惑。
        await _sessions.RevokeAllForUserAsync(target.Username, "角色已变更，需重新登录");

        var statusAfter = $"{target.Username}·{UserRoles.Label(newRole)}";
        var response = new ApiResponse
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = $"已将「{target.Username}」的角色变更为「{UserRoles.Label(newRole)}」，该账号需重新登录",
            Data = new
            {
                Username = target.Username,
                Role = newRole.ToString(),
                RoleLabel = UserRoles.Label(newRole),
                ReLoginRequired = true
            }
        };
        await _auditWriter.WriteAsync(admin.Id, admin.Username, action, statusBefore, requestLog, response,
            statusAfter, target.Username, AuditResult.Success);
        return Ok(response);
    }

    /* ==================== 查询 ==================== */

    /**
     * 用户列表。
     *
     * 改造前：靠 `?adminUsername=xxx` 判断身份 —— 客户端在 URL 里声明自己是管理员即可通过。
     * 改造后：必须持有服务端签发的有效票据，且该账号**当前**仍是管理员。
     * 鉴权失败会写入一条 AUDIT_ACCESS_DENIED 事件，使越权尝试可追溯。
     */
    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.AuditAccessDenied, "users");
        if (deny != null) return deny;

        var users = await _db.Users.Find(_ => true).ToListAsync();
        return Ok(new ApiResponse<List<UserResponse>>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Data = users.Select(ToUserResponse).ToList()
        });
    }

    /**
     * 沉睡（僵尸）账号清单 —— **纯只读**。
     *
     * 为什么单独开一个接口而不是让前端在 /users 里自己筛：
     *   "多久没登录"的判定要有唯一口径（阈值、基准时间、角色豁免都在这边定），
     *   散到前端去实现，就会出现"后端按 90 天判、某个页面按 30 天显示"
     *   这种自相矛盾，而治理功能最忌讳口径不一。
     *
     * 为什么**不写审计**：这是一个被频繁调用的派生视图（用户管理页每次刷新都会拉），
     *   若每次查询都留痕，审计链会被正常的管理行为刷屏 ——
     *   正是 `lockoutDriftLogged` 那个教训要避免的形态。
     *   真正需要留痕的是**处置动作**（冻结/解冻），它们的写入频率由人控制。
     *
     * 返回分三组：
     *   · items       —— 达到阈值且可被冻结的普通账号（沉睡候选）
     *   · protectedItems —— 达到阈值但受角色保护的管理账号（只提示，不可冻结）
     *   · frozenItems —— 当前处于冻结态的账号（可解除）
     */
    [HttpGet("dormant-users")]
    public async Task<IActionResult> GetDormantUsers()
    {
        var (admin, deny) = await RequireUserAdminAsync(AuditAction.AuditAccessDenied, "dormant-users");
        if (deny != null) return deny;

        var now = TimeGuard.WallNow();
        var users = await _db.Users.Find(_ => true).ToListAsync();

        var candidates = new List<UserResponse>();
        var protectedOnes = new List<UserResponse>();
        var frozen = new List<UserResponse>();

        foreach (var u in users)
        {
            // 冻结态单独成组：它们已经处置过了，不再混进"候选"里重复出现。
            if (u.Status == UserStatus.Disabled)
            {
                frozen.Add(ToUserResponse(u));
                continue;
            }

            // Pending 不参与（还没通过审核，谈不上沉睡）。
            if (!DormantAccountService.IsDormant(u, now, _dormantThresholdDays)) continue;

            var resp = ToUserResponse(u);
            if (UserRoles.IsDormantProtected(u.Role)) protectedOnes.Add(resp);
            else candidates.Add(resp);
        }

        // 候选中剔除操作者自己（自我豁免）—— 与冻结接口保持同一口径，
        // 免得界面列出一个点了就会被后端拒绝的按钮。
        candidates = candidates
            .Where(r => !string.Equals(r.Username, admin!.Username, StringComparison.OrdinalIgnoreCase))
            .ToList();

        // 越久没登录越该优先处理：按未登录天数倒序，管理员一眼看到最陈旧的。
        candidates.Sort((a, b) => b.DormantDays.CompareTo(a.DormantDays));
        protectedOnes.Sort((a, b) => b.DormantDays.CompareTo(a.DormantDays));
        frozen.Sort((a, b) => b.DormantDays.CompareTo(a.DormantDays));

        return Ok(new ApiResponse<object>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Data = new
            {
                thresholdDays = _dormantThresholdDays,
                items = candidates,
                protectedItems = protectedOnes,
                frozenItems = frozen
            }
        });
    }
}
