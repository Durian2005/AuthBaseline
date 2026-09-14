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

    public AuditController(AuditService audit, SessionService sessions, MongoDbService db)
    {
        _audit = audit;
        _sessions = sessions;
        _db = db;
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

    private string ClientIp()
    {
        var forwarded = Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(forwarded)) return forwarded.Split(',')[0].Trim();
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    /**
     * 审计数据的统一入口守卫。
     *
     * 越权访问（无票据 / 票据无效 / 非管理员）**都会写入一条拒绝事件**，
     * 这是"普通用户查询审计日志必须被拒绝"这件事能被证明的关键：
     * 光返回 403 不够，必须同时留下"谁在什么时候试图看过审计数据"的记录。
     */
    private async Task<(User? Admin, IActionResult? Deny)> RequireAdminAsync(string action, string target)
    {
        var auth = await _sessions.ValidateAsync(ReadTicket(), requireAdmin: true);
        if (auth.Success) return (auth.User, null);

        var resp = new ApiResponse { Success = false, Code = auth.ReasonCode, Message = auth.Message };
        await _audit.WriteAsync(new AuditEntry
        {
            OperatorId = auth.User?.Id ?? "anonymous",
            OperatorName = auth.User?.Username ?? "anonymous",
            Action = action,
            StatusBefore = auth.User?.Status.ToString() ?? "N/A",
            Request = new { AttemptedTarget = target, Path = Request.Path.Value },
            Response = resp,
            StatusAfter = auth.User?.Status.ToString() ?? "N/A",
            Target = target,
            Result = AuditResult.Failed,
            ReasonCode = auth.ReasonCode,
            SourceIp = ClientIp(),
            SourceUserAgent = Request.Headers.UserAgent.ToString()
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
        var (admin, deny) = await RequireAdminAsync(AuditAction.AuditVerify, "audit/verify");
        if (deny != null) return deny;

        var result = await _audit.VerifyAsync();

        // 校验发现断裂时，单独写一条"篡改告警"事件 ——
        // 这样"系统曾经检测到篡改"本身就是一条不可否认的审计记录。
        if (!result.Intact)
        {
            await _audit.WriteAsync(new AuditEntry
            {
                OperatorId = admin!.Id,
                OperatorName = admin.Username,
                Action = AuditAction.AuditTampered,
                StatusBefore = "INTACT",
                Request = new { Checked = result.Checked },
                Response = new { result.FirstBrokenSeq, result.BrokenShard, result.BrokenReason },
                StatusAfter = "TAMPERED",
                Target = $"seq:{result.FirstBrokenSeq}",
                Result = AuditResult.Failed,
                ReasonCode = AuditReason.ChainBroken,
                SourceIp = ClientIp(),
                SourceUserAgent = Request.Headers.UserAgent.ToString()
            });
        }

        await _audit.WriteAsync(new AuditEntry
        {
            OperatorId = admin!.Id,
            OperatorName = admin.Username,
            Action = AuditAction.AuditVerify,
            StatusBefore = "N/A",
            Request = new { },
            Response = new { result.Intact, result.Checked, result.LegacySkipped, result.FirstBrokenSeq },
            StatusAfter = result.Intact ? "INTACT" : "TAMPERED",
            Target = "audit/verify",
            Result = result.Intact ? AuditResult.Success : AuditResult.Failed,
            ReasonCode = result.Intact ? "" : AuditReason.ChainBroken,
            SourceIp = ClientIp(),
            SourceUserAgent = Request.Headers.UserAgent.ToString()
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
        var (admin, deny) = await RequireAdminAsync(AuditAction.AuditQuery, "audit/shards");
        if (deny != null) return deny;

        var shards = await _audit.ListShardsAsync();
        return Ok(new ApiResponse<object>
        {
            Success = true,
            Code = "OK",
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
        var (admin, deny) = await RequireAdminAsync(AuditAction.AuditQuery, "audit/logs");
        if (deny != null) return deny;

        var (items, total) = await _audit.QueryAsync(shard, keyword, action, result, page, pageSize, includeArchived);

        await _audit.WriteAsync(new AuditEntry
        {
            OperatorId = admin!.Id,
            OperatorName = admin.Username,
            Action = AuditAction.AuditQuery,
            StatusBefore = "N/A",
            Request = new { shard, keyword, action, result, page, pageSize },
            Response = new { Returned = items.Count, Total = total },
            StatusAfter = "N/A",
            Target = shard ?? "all",
            Result = AuditResult.Success,
            SourceIp = ClientIp(),
            SourceUserAgent = Request.Headers.UserAgent.ToString()
        });

        return Ok(new ApiResponse<object>
        {
            Success = true,
            Code = "OK",
            Data = new { Items = items, Total = total, Page = page, PageSize = pageSize }
        });
    }

    /** 概览统计：总条数、失败条数、检测到的篡改告警数。 */
    [HttpGet("stats")]
    public async Task<IActionResult> Stats()
    {
        var (admin, deny) = await RequireAdminAsync(AuditAction.AuditQuery, "audit/stats");
        if (deny != null) return deny;

        var (total, failed, tampered) = await _audit.StatsAsync();
        return Ok(new ApiResponse<object>
        {
            Success = true,
            Code = "OK",
            Data = new { Total = total, Failed = failed, TamperedAlerts = tampered }
        });
    }
}
