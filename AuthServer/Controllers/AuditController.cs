using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.Controllers;

/// <summary>
/// 审计数据接口：完整性校验、分片清单、分页查询。
///
/// 与 AuthController 分开的理由：
///   审计已经从"用户管理的一个附属查询"上升为**独立的安全控制**，
///   独立控制器让它的权限边界（一律要求管理员票据）更清晰，也便于单独测试。
/// </summary>
[ApiController]
[Route("api/audit")]
public class AuditController : ControllerBase
{
    private readonly AuditService _audit;
    private readonly SessionService _sessions;
    private readonly MongoDbService _db;
    /// <summary>审计写入的统一出口：自动补齐来源 IP / User-Agent。</summary>
    private readonly AuditWriter _auditWriter;

    public AuditController(AuditService audit, SessionService sessions, MongoDbService db,
        AuditWriter auditWriter)
    {
        _audit = audit;
        _sessions = sessions;
        _db = db;
        _auditWriter = auditWriter;
    }

    private string? ReadTicket()
    {
        var raw = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(raw)) return null;
        const string prefix = "Bearer ";
        return raw.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? raw[prefix.Length..].Trim()
            : null;
    }

    /**
     * 审计数据的统一入口守卫。
     *
     * 门槛是 AccessLevel.AuditRead —— **仅审计管理员**。管理员（含初始 admin）
     * 与用户管理员一律被拒：这不是"某处拦了他"，而是他的角色
     * 压根不满足 AuditRead 的判定条件。管账号的人因此看不到日志。
     *
     * 越权访问（无票据 / 票据无效 / 非审计管理员）**都会写入一条拒绝事件**，
     * 这是"管理员不能查看审计日志"这件事能被证明的关键：
     * 光返回 403 不够，必须同时留下"谁在什么时候试图看过审计数据"的记录。
     *
     * action 一律传 AuditAction.AuditAccessDenied —— 这里记录的是"访问被拒"这件事本身，
     * 而不是用户当时想做的那类操作。若传 AuditQuery / AuditVerify 之类，
     * 拒绝事件就和正常查询混在同一个 action 下，只能靠 result=Failed 间接区分，
     * 验收时没法一条查询列出全部越权尝试。
     */
    private async Task<(User? Auditor, IActionResult? Deny)> RequireAuditAsync(string action, string target)
    {
        var auth = await _sessions.ValidateAsync(ReadTicket(), AccessLevel.AuditRead);
        if (auth.Success) return (auth.User, null);

        var resp = new ApiResponse { Success = false, Code = auth.ReasonCode, Message = auth.Message };
        await _auditWriter.WriteAsync(new AuditEntry
        {
            OperatorId = auth.User?.Id ?? "anonymous",
            OperatorName = auth.User?.Username ?? "anonymous",
            Action = action,
            StatusBefore = auth.User?.Status.ToString() ?? "N/A",
            // 与 AuthController.RequireAdminAsync 保持一致：留住被尝试访问的接口
            // 与原始查询串。越权尝试最常见的形态就是"在 URL 里声明自己是管理员"
            // （如 ?adminUsername=admin），只记 Path 会丢掉这类伪冒手法的原始形态。
            Request = new
            {
                AttemptedTarget = target,
                Reason = auth.ReasonCode,
                Role = auth.User is null ? "anonymous" : auth.User.Role.ToString(),
                Path = Request.Path.Value,
                Query = Request.QueryString.Value
            },
            Response = resp,
            StatusAfter = auth.User?.Status.ToString() ?? "N/A",
            Target = target,
            Result = AuditResult.Failed,
            ReasonCode = auth.ReasonCode
        });
        return (null, StatusCode(auth.HttpStatus, resp));
    }

    /**
     * 完整性校验 —— 实验二「改不掉」的核心证据来源。
     *
     * 检测三类：内容被改、顺序调换 / 中间被删、尾部整段被删。
     * 返回断点序号、所在分片、发生时间，以及"期望值 vs 实际值"，
     * 使得篡改既**能被发现**，也能**被定位**。
     *
     * 校验本身也是一次高危操作（可能暴露系统遭入侵的事实），因此必须留痕。
     */
    [HttpGet("verify")]
    public async Task<IActionResult> Verify()
    {
        var (auditor, deny) = await RequireAuditAsync(AuditAction.AuditAccessDenied, "audit/verify");
        if (deny != null) return deny;

        var result = await _audit.VerifyAsync();

        // 校验发现断裂时，单独写一条"篡改告警"事件 ——
        // 这样"系统曾经检测到篡改"本身就是一条不可否认的审计记录。
        if (!result.Intact)
        {
            await _auditWriter.WriteAsync(new AuditEntry
            {
                OperatorId = auditor!.Id,
                OperatorName = auditor.Username,
                Action = AuditAction.AuditTampered,
                StatusBefore = "INTACT",
                Request = new { Checked = result.Checked },
                Response = new { result.FirstBrokenSeq, result.BrokenShard, result.BrokenReason },
                StatusAfter = "TAMPERED",
                Target = $"seq:{result.FirstBrokenSeq}",
                Result = AuditResult.Failed,
                ReasonCode = AuditReason.ChainBroken
            });
        }

        await _auditWriter.WriteAsync(new AuditEntry
        {
            OperatorId = auditor!.Id,
            OperatorName = auditor.Username,
            Action = AuditAction.AuditVerify,
            StatusBefore = "N/A",
            Request = new { },
            Response = new { result.Intact, result.Checked, result.LegacySkipped, result.FirstBrokenSeq },
            StatusAfter = result.Intact ? "INTACT" : "TAMPERED",
            Target = "audit/verify",
            Result = result.Intact ? AuditResult.Success : AuditResult.Failed,
            ReasonCode = result.Intact ? "" : AuditReason.ChainBroken
        });

        return Ok(new ApiResponse<ChainVerifyResult>
        {
            Success = true,
            Code = result.Intact ? "OK" : "CHAIN_BROKEN",
            Message = result.Detail,
            Data = result
        });
    }

    /** 分片清单：展示轮转结果与各片规模，证明"撑得住"有真实的落地形态。 */
    [HttpGet("shards")]
    public async Task<IActionResult> Shards()
    {
        var (auditor, deny) = await RequireAuditAsync(AuditAction.AuditAccessDenied, "audit/shards");
        if (deny != null) return deny;

        var shards = await _audit.ListShardsAsync();
        return Ok(new ApiResponse<object>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Data = shards
        });
    }

    /** 分页查询审计日志（完整版，支持按分片、关键词、动作、结果筛选）。 */
    [HttpGet("logs")]
    public async Task<IActionResult> Logs([FromQuery] string? shard,
        [FromQuery] string? keyword, [FromQuery] string? action, [FromQuery] string? result,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50,
        [FromQuery] bool includeArchived = true)
    {
        var (auditor, deny) = await RequireAuditAsync(AuditAction.AuditAccessDenied, "audit/logs");
        if (deny != null) return deny;

        var (items, total) = await _audit.QueryAsync(shard, keyword, action, result, page, pageSize, includeArchived);

        await _auditWriter.WriteAsync(new AuditEntry
        {
            OperatorId = auditor!.Id,
            OperatorName = auditor.Username,
            Action = AuditAction.AuditQuery,
            StatusBefore = "N/A",
            Request = new { shard, keyword, action, result, page, pageSize },
            Response = new { Returned = items.Count, Total = total },
            StatusAfter = "N/A",
            Target = shard ?? "all",
            Result = AuditResult.Success
        });

        return Ok(new ApiResponse<object>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Data = new { Items = items, Total = total, Page = page, PageSize = pageSize }
        });
    }

    /** 概览统计：总条数、失败条数、检测到的篡改告警数。 */
    [HttpGet("stats")]
    public async Task<IActionResult> Stats()
    {
        var (auditor, deny) = await RequireAuditAsync(AuditAction.AuditAccessDenied, "audit/stats");
        if (deny != null) return deny;

        var (total, failed, tampered, denied, latestDeniedSeq) = await _audit.StatsAsync();
        return Ok(new ApiResponse<object>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Data = new
            {
                Total = total,
                Failed = failed,
                TamperedAlerts = tampered,
                // 越权访问被拒：总数 + 最新一条的序号。
                // 前端靠 LatestDeniedSeq 判断是否出现了新的越权尝试，
                // 从而在不产生额外审计记录的前提下实现实时告警。
                AccessDenied = denied,
                LatestDeniedSeq = latestDeniedSeq
            }
        });
    }

    /**
     * 职责分离（SoD）绕过的检测层：把"管理员造出审计管理员再借它读日志"
     * 从原始事件还原成一条条可枚举的归因链。
     *
     * 为什么这条线索必须由系统自己算出来
     * ----------------------------------
     * 本系统的规则允许管理员创建审计管理员 —— 这是分工需要，不是漏洞；
     * 但同一个规则也允许管理员"自设口令造号 → 以它的身份登录读审计"。
     * 这条路径在接口层**无法阻止**（阻止它就等于禁止管理员建审计账号），
     * 只能做到事后可追溯。
     *
     * 而"可追溯"若只停留在库里有几条原始记录，就只是一句口号：
     * CREATE_ACCOUNT、LOGIN_SUCCESS、AUDIT_QUERY 分属三条记录，
     * 没有任何人会天天手工把它们串起来看。这里把它固化成判定规则，
     * 让"谁造就了谁、谁用谁读了几次、什么时候封的口"成为一次调用就能拿到的东西。
     *
     * 权限沿用 AccessLevel.AuditRead（仅审计管理员）
     * --------------------------------------------
     * 理由与其它审计接口一致：这是从审计数据里推导出的结论，泄漏它的风险
     * 与泄漏日志本身同级。管理员被结构性排除 —— 包括那个自己造号的人。
     *
     * ⚠️ 已知的局限（不宣称已解决）
     *   1. 被检测对象正是"有权限看这份报告的人" —— 他可以不看。
     *      因此本接口的价值在**事后取证**与**第三方复核**，
     *      不能当成实时拦截；配套的 tools/sod_trace.py 允许直接查库独立复算，
     *      不依赖本服务是否被人打开过。
     *   2. 只能证明"口令由谁设定、读取发生在封口之前"，
     *      不能证明"当时敲键盘的是谁"。
     *
     * 检测动作本身也留痕（SOD_SCAN）：谁在什么时候查过"有没有人绕过了职责分离"，
     * 与"谁查过日志"同等重要 —— 否则"查过但没说"这件事无法证明。
     */
    [HttpGet("sod")]
    public async Task<IActionResult> Sod()
    {
        var (auditor, deny) = await RequireAuditAsync(AuditAction.AuditAccessDenied, "audit/sod");
        if (deny != null) return deny;

        var logs = await _audit.LoadAllAsync();
        var result = SodAnalyzer.Analyze(logs);

        await _auditWriter.WriteAsync(new AuditEntry
        {
            OperatorId = auditor!.Id,
            OperatorName = auditor.Username,
            Action = AuditAction.SodScan,
            StatusBefore = "N/A",
            Request = new { },
            Response = new
            {
                result.Scanned,
                result.Attributed,
                result.Sealed,
                result.Dormant,
                Chains = result.Chains.Count,
                result.BatchGranters
            },
            StatusAfter = result.Attributed > 0 ? "ATTRIBUTED" : "CLEAN",
            Target = "audit/sod",
            Result = AuditResult.Success
        });

        return Ok(new ApiResponse<SodScanResult>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Data = result
        });
    }

    /**
     * 审计日志查询（兼容旧路径 api/auth/logs）。
     *
     * 旧版是 Limit(200) 硬编码 —— 写多少都只看得到最近 200 条，"撑得住"无从谈起。
     * 现在改为分页 + 跨分片，与 api/audit/logs 走同一套逻辑。
     * 保留这条路径是为了不让既有调用方失效（回归脚本 audit_e2e_test.py 会直接打它）。
     *
     * 路由写在动作上且以 / 开头 ⇒ 是**绝对路径**，不会被控制器的 api/audit 前缀接管，
     * 这也是"把旧入口收归审计域"这件事能成立的前提。
     *
     * 鉴权失败时写入的是 AUDIT_ACCESS_DENIED 而不是 AUDIT_QUERY：
     * 这里记录的是"有人试图看审计数据但被拒绝"这件事本身。
     * 若沿用 AuditQuery，拒绝事件就会和正常查询混在同一个动作下，
     * 只能靠 result=失败 间接区分，验收时无法一条查询列出全部越权尝试
     * —— 用 curl / PowerShell 直接打这个地址的被拒记录也会因此漏掉。
     */
    [HttpGet("/api/auth/logs")]
    public async Task<IActionResult> LegacyAuthLogs([FromQuery] string? shard,
        [FromQuery] string? keyword, [FromQuery] string? action, [FromQuery] string? result,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50,
        [FromQuery] bool includeArchived = true)
    {
        var (auditor, deny) = await RequireAuditAsync(AuditAction.AuditAccessDenied, "logs");
        if (deny != null) return deny;

        var (items, total) = await _audit.QueryAsync(shard, keyword, action, result, page, pageSize, includeArchived);

        await _auditWriter.WriteAsync(auditor!.Id, auditor.Username, AuditAction.AuditQuery, "N/A",
            new { shard, keyword, action, result, page, pageSize },
            new { Returned = items.Count, Total = total },
            "N/A", "logs", AuditResult.Success);

        return Ok(new ApiResponse<object>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Data = new { Items = items, Total = total, Page = page, PageSize = pageSize }
        });
    }
}