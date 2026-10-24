using AuthServer.Models;
using AuthServer.Services;
using AuthServer.Services.Face;
using AuthServer.Services.FaceId;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthServer.Controllers;

/**
 * 用户管理接口：审核、解锁/解冻、冻结、注销、创建账号、变更角色、用户与沉睡清单、重置他人人脸。
 *
 * 全部依赖票据鉴权，且**两个级别刻意分开**：
 *   · RequireUserAdminAsync（Admin / UserAdmin）—— 审核、解锁、冻结、注销、看清单、重置人脸
 *   · RequireAdminAsync（仅 Admin）      —— 创建账号、变更他人角色
 * 用户管理员能管账号，但不能任免角色；任免角色只属于 Admin。
 * 「创建账号」可建普通用户 / 用户管理员 / 审计管理员（不可建 Admin）；
 * 邮箱在该接口上是**可选**的。
 * 路由前缀仍是 api/auth，与拆分前逐一对应。
 */
[ApiController]
[Route("api/auth")]
public class UserAdminController : AuthControllerBase
{
    private readonly FaceTemplateStore _faceTemplates;

    /// <summary>
    /// 纯人脸登录的模板存储。**直接注入具体类，不复用下面的 <see cref="IUserDataPurger"/> 列表**：
    /// 那是"注销 = 把这个人的一切清掉"的语义；重置只该拿掉人脸，
    /// 将来别的模块登记 purger 时，重置不该顺手把它们也清了。
    /// </summary>
    private readonly FaceIdTemplateStore _faceIdTemplates;
    /// <summary>各模块登记的个人数据清理入口（当前只有 FaceId）。见 <see cref="IUserDataPurger"/>。</summary>
    private readonly IEnumerable<IUserDataPurger> _purgers;

    public UserAdminController(MongoDbService db, AuditWriter auditWriter, SessionService sessions,
        PepperProvider pepper, IConfiguration configuration, FaceTemplateStore faceTemplates,
        FaceIdTemplateStore faceIdTemplates,        IEnumerable<IUserDataPurger> purgers)
        : base(db, auditWriter, sessions, pepper, configuration)
    {
        _faceTemplates = faceTemplates;
        _faceIdTemplates = faceIdTemplates;
        _purgers = purgers;
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

        // ── 同动作清理人脸模板（刻意排在删除账号之前）──
        //
        // 账号都不存在了还留着生物特征向量，是纯粹的残留暴露面 ——
        // 口令改了可以撤销，脸改不了，所以这类数据"能不留就不留"。
        //
        // 为什么排在删除账号**之前**：这样"模板清理失败"会让整个请求失败、
        // 账号**不被删除**，从而保证不变式"不会有账号已注销但模板还留着"（不留孤儿）。
        // 反过来（先删账号再清模板）一旦清理失败就永久留下孤立向量，
        // 而且再没有任何东西指向它，事后想清理都无从下手。
        // 反方向的残余代价只是"模板先没了、账号还在"（该账号暂时退回单因子），
        // 管理员重试一次即可自愈 —— 两种残余里这一种可恢复。
        //
        // 按用户名而不是 userId 删：模板表冗余存了 username 正是为了这条路径少一次查询，
        // 而"漏删模板"是这段代码最不能接受的失败。
        // 不用 try/catch：本机 Mongo 的失败本就该让请求失败，吞掉它才是真的危险。
        await _faceTemplates.DeleteByUsernameAsync(user.Username);

        // 其它模块（当前是纯人脸登录 FaceId）的模板同样必须真删：它们是**独立集合**，
        // 删掉 2FA 的模板不代表 FaceId 的模板也消失了。
        // 通过接口遍历而不是逐个硬编码，理由见 IUserDataPurger ——
        // 账号域不该认识每一个生物特征模块。
        // 同样排在删除账号之前：清理失败 ⇒ 整个请求失败、账号仍在，不留孤儿向量。
        foreach (var purger in _purgers)
        {
            var purged = await purger.PurgeByUsernameAsync(user.Username);
            if (purged > 0)
                Console.WriteLine($"[UserAdmin] 注销「{user.Username}」：{purger.Name} 清理 {purged} 条");
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

    /* ==================== 管理员：重置他人人脸 ==================== */

    /**
     * 重置某账号的人脸模板（换人 / 换设备 / 疑似泄露后作废，
     * 以及"录入者的摄像头损坏、第二因子无法完成时"的**指定恢复路径**）。
     *
     * 与注销、冻结同属**处置**类操作，因此走同一个权限出口
     * <c>UserRoles.CanBeManagedBy</c> —— 不新增任何规则，用户管理员够不到上级。
     *
     * 审计动作单独一条（FACE_TEMPLATE_RESET）：把别人的第二因子拿掉是本系统里
     * "管理员可对他人实施的降级"之一，必须能被一条查询单独捞出来复核。
     * 它的性质与已经承认的"SoD 可被 Admin 绕过"相同 ——
     * **可追溯，但不宣称已阻止**（详见设计文档 §九）。
     *
     * 为什么不像 create-account 那样要求操作者二次口令：
     *   与 delete-user / freeze-user 保持一致 —— 那两者也不要求。
     *   若只在这里加严，就会出现"注销账号比拿掉人脸更松"这种自相矛盾的权限阶梯。
     *
     * 2026-10-20 起**同时清理两条链路**（第二因子 + 纯人脸登录），并各写一条审计。
     *   起因：只清 2FA 时，本方法的说明与用户看到的结果都是"人脸已拿掉"，
     *   而 FaceId 模板还活着 —— 于是"人脸出问题就找管理员重置"这条恢复路径是断的：
     *   模板被冒录时，管理员清了第二因子，冒录者仍能用「用户名 + 人脸」登录。
     *   写两条记录而不是一条，是为了让 FACE_TEMPLATE_RESET 的历史口径（只代表第二因子）
     *   不被改写；哈希链按写入顺序串联，多写一条不影响可验证性。
     *   二次口令仍然**不要求**：扩展到 FaceId 之后它依旧是"降级"而不是"注销"，
     *   上面那条权限阶梯的论证不变 —— 别按"删得更多就该更严"来改。
     */
    [HttpPost("reset-face")]
    public async Task<IActionResult> ResetFace([FromBody] ResetFaceRequest req)
    {
        const string action = AuditAction.FaceTemplateReset;
        var (admin, deny) = await RequireUserAdminAsync(action, Norm(req.Username));
        if (deny != null) return deny;
        var requestLog = new { req.Username };

        var username = Norm(req.Username);
        var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
        if (user == null)
        {
            var missing = new ApiResponse { Success = false, Code = BusinessCode.NotFound, Message = "用户不存在" };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, action, "N/A", requestLog, missing, "N/A",
                username, AuditResult.Failed, AuditReason.NotFound);
            return NotFound(missing);
        }

        var statusBefore = user.Status.ToString();

        if (!UserRoles.CanBeManagedBy(admin!, user))
        {
            var isSelf = UserRoles.IsSameAccount(admin!, user);
            var denied = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.ForbiddenTarget,
                Message = isSelf
                    ? "不能重置自己的人脸。请到账号设置里自助删除（两套都要删，均需输入当前口令）。"
                    : $"当前身份「{UserRoles.Label(admin!.Role)}」不能重置"
                        + $"「{UserRoles.Label(user.Role)}」账号的人脸。"
            };
            await _auditWriter.WriteAsync(admin!.Id, admin.Username, action, statusBefore, requestLog, denied,
                statusBefore, user.Username, AuditResult.Failed, AuditReason.ForbiddenTarget);
            return BadRequest(denied);
        }

        // 两条链路一起清。管理员的心智是"把这个人的脸拿掉"，不是"清掉第二因子那一套"。
        var removed = await _faceTemplates.DeleteByUserIdAsync(user.Id);
        var faceIdRemoved = await _faceIdTemplates.DeleteByUserIdAsync(user.Id);

        var response = new ApiResponse
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = ResetFaceMessage(user.Username, removed, faceIdRemoved),
            // Removed 的语义**保持不变**：只数第二因子的那套模板。
            // 既有探针（face_second_factor_probe 的 removed == 1）与历史审计 bag 都按这个口径，
            // 把 FaceId 的张数并进来等于悄悄改了别人的读数。
            Data = new { Username = user.Username, Removed = removed, FaceIdRemoved = faceIdRemoved }
        };
        await _auditWriter.WriteAsync(admin!.Id, admin.Username, action, statusBefore, requestLog, response,
            statusBefore, user.Username, AuditResult.Success);

        // **第二条独立记录**，不并入上面那条：见方法头注释里"历史口径"那段。
        // 即使 faceIdRemoved == 0 也写 —— 审计回答的是"管理员做过这个动作"，
        // 只记非零会让"重置过、但对方本就没录"从流水里彻底消失。
        await _auditWriter.WriteAsync(admin!.Id, admin.Username, AuditAction.FaceIdTemplateReset,
            statusBefore, requestLog, response, statusBefore, user.Username, AuditResult.Success);

        return Ok(response);
    }

    /// <summary>
    /// 重置人脸的结果说明。**两套要分别说清**：旧文案只说"不再需要刷脸登录"，
    /// 而开过 FaceId 的账号当时照样能用「用户名 + 人脸」登录 —— 字面与事实不符。
    /// </summary>
    private static string ResetFaceMessage(string username, long removed, long faceIdRemoved)
    {
        if (removed == 0 && faceIdRemoved == 0)
            return $"「{username}」原本就没有录入人脸";
        if (faceIdRemoved == 0)
            return $"已重置「{username}」的人脸模板（删除 {removed} 张），该账号不再需要刷脸登录";
        if (removed == 0)
            return $"已重置「{username}」的刷脸登录（删除 {faceIdRemoved} 张），该账号不再能用「用户名 + 人脸」登录";
        return $"已重置「{username}」的人脸：第二因子删除 {removed} 张、刷脸登录删除 {faceIdRemoved} 张，"
             + "两种人脸登录都已关闭";
    }

    /* ==================== 管理员：创建账号 ==================== */

    /// <summary>
    /// 允许被创建的三种角色。
    ///
    /// 刻意**不含 Admin**：Admin 是角色任免权的持有者，若能凭空再造一个 Admin，
    /// 就存在"管理员自我复制、稀释责任"的路径。需要有人分担任免权时，
    /// 应当由人来决定并明确留痕，而不是让程序放开这个口子。
    ///
    /// 含普通用户（User）：它是最低权限角色、不带任何管理能力，
    /// 放开它不会扩大上面的自我复制面 —— 而它恰好是"想绕开邮箱验证码那条
    /// 自助注册链路、又要一个可登录账号"时唯一合适的落点。
    /// </summary>
    private static bool CanBeCreatedRole(UserRole role) =>
        role is UserRole.User or UserRole.UserAdmin or UserRole.AuditAdmin;

    /**
     * 由管理员创建「普通用户」「用户管理员」或「审计管理员」账号。
     *
     * 与自助注册的本质区别：
     *   - **不发验证码**。邮箱是**可选**的：留空即只凭口令登录（代价是无法自助
     *     找回密码）；填写则登记为已验证 —— 管理员是可信主体，不额外发码；
     *   - **建号即启用**，不走待审核；
     *   - 因此这个接口本身就是一条高权限通道 —— 一旦被冒用就能凭空造出账号，
     *     所以必须**二次校验操作者本人的登录口令**：
     *     仅凭会话票据不足以证明是本人操作，票据被盗时攻击者不该能直接造账号。
     *     这一条对三种角色一视同仁、**包括普通用户** —— 持票者可借它造出"自己的"
     *     常驻账号做持久化，并不因为角色低就该免检。
     *
     * 校验顺序上把口令校验放在"用户名 / 邮箱查重"之前：
     * 查重会回答"这个用户名或邮箱是否存在"，属于可被利用的信息；
     * 先证明是本人，再去查库。
     */
    [HttpPost("create-account")]
    public async Task<IActionResult> CreateAccount([FromBody] CreateAccountRequest req)
    {
        const string action = AuditAction.CreateAccount;
        var targetName = Norm(req.Username);
        // 邮箱可选：规范化后统一比较，脱敏后才入日志（与注册、发码的记法一致）。
        // EmailBoundBy 一并记下 —— 事后必须能区分"邮箱是管理员代填的"与
        // "本人走验证码验证过的"，否则会得出"所有账号的邮箱都已验证"这种
        // 被代填污染的错误结论。它进的是 request 这个 JSON 袋，
        // 不动 AuditLog 的列结构（列结构是哈希链的输入，不能碰）。
        var email = EmailUtil.Normalize(req.Email);
        var emailBound = !string.IsNullOrWhiteSpace(email);
        // 初始口令与操作者口令都不入日志
        var requestLog = new { req.Username, req.Role, Email = EmailUtil.Mask(req.Email),
            EmailBoundBy = emailBound ? "operator" : null };

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

        // 邮箱格式只在"填了"的前提下校验 —— 留空是合法用法（该账号只凭口令登录）。
        // 它属纯入参校验，与口令复杂度同级，所以放在"证明是本人"之前：
        // 格式写错与"这个人是不是管理员"无关，没必要先验口令再告诉他格式不对。
        if (emailBound && !EmailUtil.IsValid(email))
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.InvalidEmail,
                Message = "邮箱格式不正确；如不需要邮箱请留空"
            };
            await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                targetName, AuditResult.Failed, AuditReason.InvalidEmail);
            return BadRequest(resp);
        }

        // 二次口令：创建账号是特权变更，仅凭会话不足以证明是本人操作
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

        // 邮箱唯一性：与自助注册同一条规则（不能两个账号共用一个邮箱）。
        // 这不是洁癖 —— 共用会让「忘记密码」无法判断该把重置码发给谁，
        // 而这种歧义一旦落进库里，事后没有自动分辨的办法。
        if (emailBound)
        {
            var emailTaken = await _db.Users.Find(u => u.Email == email).FirstOrDefaultAsync();
            if (emailTaken != null)
            {
                var resp = new ApiResponse { Success = false, Code = BusinessCode.EmailAlreadyBound, Message = "该邮箱已被其它账号绑定" };
                await _auditWriter.WriteAsync(admin.Id, admin.Username, action, operatorLabel, requestLog, resp, operatorLabel,
                    targetName, AuditResult.Failed, AuditReason.EmailAlreadyBound);
                return Conflict(resp);
            }
        }

        var user = new User
        {
            Username = targetName,
            PasswordHash = PasswordHasher.Hash(req.Password, _pepper.Pepper),
            Status = UserStatus.Enabled,
            Role = newRole,
            // 邮箱可选：填了才绑，并直接视为已验证（管理员代填，理由见 User.EmailVerified）；
            // 留空即 null，账号只凭口令登录 —— 登录标识是用户名，所以照样能登。
            Email = emailBound ? email : null,
            EmailVerified = emailBound,
            FailedLoginAttempts = 0,
            CreatedAt = DateTime.UtcNow
        };
        await _db.Users.InsertOneAsync(user);

        var newLabel = $"{user.Username}·{UserRoles.Label(newRole)}";
        var response = new ApiResponse<UserResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = emailBound
                ? $"已创建{UserRoles.Label(newRole)}账号「{user.Username}」，可直接登录；邮箱已登记，可用于找回密码"
                : $"已创建{UserRoles.Label(newRole)}账号「{user.Username}」，该账号未绑邮箱、只凭口令登录，无法自助找回密码",
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

    /* ==================== 批量处置 ==================== */

    /**
     * 批量处置：对多个账号执行**同一个**动作（approve / unlock / freeze / delete / reset-face / set-role）。
     *
     * 三条设计取向，都是"批量"特有的坑：
     *
     *   ① **逐条执行、逐条留痕，不做整体事务。**
     *      批量操作最常见的失败原因是"选多了"（勾到一个自己够不到的上级，或勾到自己）。
     *      整批回滚只会让人反复试，而且事后答不出"到底哪些没做"。
     *      每个目标写一条与单条接口**逐字一致**的审计 ——
     *      所以「谁被处置了」在哈希链里仍然可以独立还原，不因为走了批量就变成一条模糊的汇总。
     *
     *   ② **权限不放宽：批量不是一条新的授权路径，它只是循环调用单条入口。**
     *      每个目标仍然各自过 RequireUserAdminAsync + CanBeManagedBy（含自我豁免）。
     *      前端把无权行置灰只是提前告知，不是安全边界 —— 手敲请求一样会被拒并留痕。
     *
     *   ③ **入口先做一次预检，一个目标都不进循环也能拒绝。**
     *      否则操作者本身没有权限时，一次误点会往审计链里刷进 N 条同样的拒绝记录，
     *      把真正的越权尝试淹掉。预检通过后，被调用的 Action 内部仍会再鉴权一次 ——
     *      重复但无害，换来的是"批量与单条行为完全一致"这个更值钱的保证。
     *
     * 为什么不做成通用的"批量编辑"（多字段一起改）：
     *   六种动作的前置校验、审计码、副作用全不相同，揉进一个函数就是六套授权规则
     *   挤在一处，判错一次即越权。这里的 switch 只**分派**，不复制任何业务逻辑。
     */
    [HttpPost("batch")]
    public async Task<IActionResult> Batch([FromBody] BatchRequest req)
    {
        // 动作名与用户名都走 Norm（Trim + 转小写）：前端传什么大小写都不影响分派，
        // 也不会因为一个多余空格就多出一条"用户不存在"。
        var action = Norm(req.Action);
        var targets = (req.Usernames ?? new List<string>())
            .Select(Norm)
            .Where(u => !string.IsNullOrEmpty(u))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (targets.Count == 0)
        {
            return BadRequest(new ApiResponse
            {
                Success = false,
                Code = BusinessCode.EmptyFields,
                Message = "请至少选择一个账号"
            });
        }

        if (!BatchAction.Known(action))
        {
            return BadRequest(new ApiResponse
            {
                Success = false,
                Code = BusinessCode.BatchUnknownAction,
                Message = $"不支持的批量动作「{req.Action}」"
            });
        }

        // 单次上限：不是为了防刷（本接口有票据鉴权），而是避免"一次全选"跑成超时 ——
        // 半途超时的话前端拿不到逐条明细，等于什么都没说清楚。
        if (targets.Count > MaxBatchTargets)
        {
            return BadRequest(new ApiResponse
            {
                Success = false,
                Code = BusinessCode.BatchTooMany,
                Message = $"一次最多处理 {MaxBatchTargets} 个账号（本次 {targets.Count} 个）"
            });
        }

        // 预检：级别由动作决定（改角色只属于 Admin）。target 传空 ——
        // 这里拒绝的是"操作者没这个权限"，不是"某个目标不可处置"，两者在审计里不该混成一条。
        var auditCode = BatchAction.AuditCodeOf(action);
        var (admin, deny) = BatchAction.RequiresAdmin(action)
            ? await RequireAdminAsync(auditCode, string.Empty)
            : await RequireUserAdminAsync(auditCode, string.Empty);
        if (deny != null) return deny;

        var items = new List<BatchItemResult>(targets.Count);
        foreach (var name in targets)
        {
            // 分派到单条入口。刻意不在这里重写业务：一旦重写，
            // "批量"与"单条"就会慢慢长出两套行为，而这正是最难发现的越权来源。
            IActionResult one = action switch
            {
                BatchAction.Approve => await Approve(new ApproveRequest { Username = name }),
                BatchAction.Unlock => await Unlock(new UnlockRequest { Username = name }),
                BatchAction.Freeze => await FreezeUser(new FreezeUserRequest { Username = name, Reason = req.Reason }),
                BatchAction.Delete => await DeleteUser(new DeleteUserRequest { Username = name }),
                BatchAction.ResetFace => await ResetFace(new ResetFaceRequest { Username = name }),
                BatchAction.SetRole => await SetRole(new SetRoleRequest
                {
                    Username = name,
                    Role = req.Role,
                    OperatorPassword = req.OperatorPassword
                }),
                _ => throw new InvalidOperationException($"未分派的批量动作：{action}")
            };

            var (ok, code, message) = ReadApiResult(one);
            items.Add(new BatchItemResult { Username = name, Success = ok, Code = code, Message = message });
        }

        var okCount = items.Count(i => i.Success);
        var failed = items.Count - okCount;
        var summary = new BatchResult { Total = items.Count, Ok = okCount, Failed = failed, Items = items };

        // 全部没做成 ⇒ 用 400 表达"这次批量没有产生任何效果"，但**明细照给** ——
        // 否则前端只能显示一句"失败"，管理员还得逐个重点一遍才知道为什么。
        if (okCount == 0)
        {
            return BadRequest(new ApiResponse<BatchResult>
            {
                Success = false,
                Code = BusinessCode.BatchAllFailed,
                Message = $"{failed} 个账号均未处理，原因见明细",
                Data = summary
            });
        }

        return Ok(new ApiResponse<BatchResult>
        {
            Success = true,
            Code = failed == 0 ? BusinessCode.Ok : BusinessCode.BatchPartial,
            Message = failed == 0 ? $"已处理 {okCount} 个账号" : $"成功 {okCount} 个，未处理 {failed} 个",
            Data = summary
        });
    }

    /// <summary>单次批量上限。超过即整体拒绝，不做"截断前 N 个"（静默丢目标比报错更坏）。</summary>
    private const int MaxBatchTargets = 200;

    /// <summary>
    /// 批量动作名的**唯一**清单。前端只认这几个字符串，后端也只分派这几个 ——
    /// 表外的名字一律 400，不做"猜一个最像的动作"。
    /// </summary>
    private static class BatchAction
    {
        public const string Approve = "approve";
        public const string Unlock = "unlock";
        public const string Freeze = "freeze";
        public const string Delete = "delete";
        public const string ResetFace = "reset-face";
        public const string SetRole = "set-role";

        public static bool Known(string action) => action
            is Approve or Unlock or Freeze or Delete or ResetFace or SetRole;

        /// <summary>改角色是唯一收窄到 Admin 的动作（后端单条接口用 RequireAdminAsync）。</summary>
        public static bool RequiresAdmin(string action) => action == SetRole;

        /// <summary>
        /// 预检用的审计码：取该动作**真实**对应的码，而不是统一成一个 BATCH。
        /// 理由是拒绝记录要能回答"他当时想做什么" —— 想注销和想解冻是两件不同的事。
        /// </summary>
        public static string AuditCodeOf(string action) => action switch
        {
            Approve => AuditAction.Approve,
            Unlock => AuditAction.Unlock,
            Freeze => AuditAction.DormantFreeze,
            Delete => AuditAction.DeleteUser,
            ResetFace => AuditAction.FaceIdTemplateReset,
            SetRole => AuditAction.SetRole,
            _ => AuditAction.DeleteUser
        };
    }

    /// <summary>
    /// 从单条入口返回的 <see cref="IActionResult"/> 里取出 (是否成功, 业务码, 话术)。
    ///
    /// 为什么不直接判 HTTP 状态：六个入口把失败分别落在 400 / 401 / 403 / 404，
    /// 而批量只关心"这一条做没做成"。单条被调用时状态码语义不变，
    /// 这里只是把两种 ApiResponse 形态统一成三元组。
    /// </summary>
    private static (bool Ok, string Code, string Message) ReadApiResult(IActionResult result)
    {
        if (result is ObjectResult obj && obj.Value != null)
        {
            switch (obj.Value)
            {
                case ApiResponse plain:
                    return (plain.Success, plain.Code, plain.Message);
                case ApiResponse<UserResponse> typed:
                    return (typed.Success, typed.Code, typed.Message);
                default:
                    // 将来若新增别的 ApiResponse<T>，用反射兜底而不是再加一臂 ——
                    // 漏一个分支的表现是"明明成功却报失败"，比慢一点糟得多。
                    var t = obj.Value.GetType();
                    if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(ApiResponse<>))
                    {
                        var ok = t.GetProperty(nameof(ApiResponse.Success))?.GetValue(obj.Value) is true;
                        var code = t.GetProperty(nameof(ApiResponse.Code))?.GetValue(obj.Value) as string ?? string.Empty;
                        var msg = t.GetProperty(nameof(ApiResponse.Message))?.GetValue(obj.Value) as string ?? string.Empty;
                        return (ok, code, msg);
                    }
                    break;
            }
        }

        // 走到这里说明返回结构变了（不是 ObjectResult 或不是 ApiResponse）。
        // 报失败而不是猜成功：批量里"把没做的事说成做了"是最坏的一种错。
        return (false, BusinessCode.Ok, "无法识别的返回结构");
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
