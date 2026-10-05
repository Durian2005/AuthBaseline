using AuthServer.Models;

namespace AuthServer.Services;

/**
 * 审计写入的统一出口。
 *
 * 为什么要有这一层：
 *   审计记录里有两项"由来源决定、调用方不该关心"的字段 —— 来源 IP 与 User-Agent。
 *   改造前 AuthController 与 AuditController **各写了一份**取值逻辑（结构相同、
 *   散在两处），一旦某天要改成读 X-Real-IP 就得改两处，漏一处就会出现
 *   "两个入口记下来的来源不一致"。
 *
 *   把取值与建条目收在这里之后，控制器只负责说明"发生了什么"，
 *   "从哪来"由本类自动补齐。
 *
 * 与 AuditService 的分工：
 *   AuditService 决定**怎么写**（哈希链、分片、并发串行化）；
 *   AuditWriter  决定**写什么**（补齐来源字段、给出统一的调用形状）。
 *
 * 同理，本类不吞异常：审计是旁路，但"旁路不阻断业务"这条保证由 AuditService
 * 内部实现（它自己不抛），本类不做额外兜底，以免掩盖真正的配置错误。
 */
public sealed class AuditWriter
{
    private readonly AuditService _audit;
    private readonly IHttpContextAccessor _http;

    public AuditWriter(AuditService audit, IHttpContextAccessor http)
    {
        _audit = audit;
        _http = http;
    }

    /** 取调用方 IP。桌面端与浏览器都经本机回环，因此优先读 X-Forwarded-For（若有代理）。 */
    public string ClientIp()
    {
        var ctx = _http.HttpContext;
        if (ctx is null) return "unknown";
        var forwarded = ctx.Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(forwarded))
            return forwarded.Split(',')[0].Trim();
        return ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private string UserAgent()
        => _http.HttpContext?.Request.Headers.UserAgent.ToString() ?? string.Empty;

    /** 写入一条审计记录。未显式给出 SourceIp / SourceUserAgent 时自动补齐。 */
    public Task WriteAsync(AuditEntry entry)
    {
        if (string.IsNullOrEmpty(entry.SourceIp)) entry.SourceIp = ClientIp();
        if (string.IsNullOrEmpty(entry.SourceUserAgent)) entry.SourceUserAgent = UserAgent();
        return _audit.WriteAsync(entry);
    }

    /**
     * 便捷重载：参数与原 AuthController.WriteAuditLogAsync 完全一致，
     * 使既有调用点可以原样迁移（来源信息由本类补齐，调用方不传）。
     */
    public Task WriteAsync(string operatorId, string operatorName, string action,
        string statusBefore, object request, object response, string statusAfter,
        string target = "", string result = AuditResult.Success, string reasonCode = "",
        string actorType = "")
    {
        return WriteAsync(new AuditEntry
        {
            OperatorId = operatorId,
            OperatorName = operatorName,
            Action = action,
            StatusBefore = statusBefore,
            Request = request,
            Response = response,
            StatusAfter = statusAfter,
            Target = target,
            Result = result,
            ReasonCode = reasonCode,
            ActorType = actorType
        });
    }
}
