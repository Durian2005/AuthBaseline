using System.Security.Cryptography;
using AuthServer.Models;
using MongoDB.Driver;

namespace AuthServer.Services;

/// <summary>鉴权结果。失败时带回原因码，供审计留痕。</summary>
public sealed class TicketAuthResult
{
    public bool Success { get; init; }
    public User? User { get; init; }
    public Session? Session { get; init; }
    public string ReasonCode { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public int HttpStatus { get; init; } = 200;
}

/// <summary>
/// 会话票据服务：签发 / 校验 / 吊销。
///
/// 这是实验二「02 看不到」的技术核心 ——
/// 把"客户端自己说我是管理员"换成"服务端签发的不可伪造票据"。
///
/// 三个必须做对的点：
///   1. 票据取自密码学安全随机源（RandomNumberGenerator），不用 Guid / Random；
///   2. 每次校验都**重新查库**确认身份与状态，不信票据里的快照 ——
///      这样权限被转让、账号被锁定后，旧票据立刻失效，不存在授权残留；
///   3. 滑动过期：有操作就续期，长期静置则自动失效。
/// </summary>
public sealed class SessionService
{
    private readonly MongoDbService _db;

    /// <summary>滑动过期窗口：2 小时无操作即失效。</summary>
    private static readonly TimeSpan SlidingWindow = TimeSpan.FromHours(2);

    public SessionService(MongoDbService db)
    {
        _db = db;
    }

    /// <summary>签发一张新票据。登录成功后调用。</summary>
    public async Task<Session> IssueAsync(User user)
    {
        var session = new Session
        {
            Ticket = GenerateTicket(),
            Username = user.Username,
            UserId = user.Id,
            IsAdminAtIssue = user.IsAdmin,
            IssuedAt = DateTime.UtcNow,
            LastSeenAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.Add(SlidingWindow)
        };
        await _db.Sessions.InsertOneAsync(session);
        return session;
    }

    /// <summary>
    /// 校验票据。
    /// requireAdmin = true 时会额外确认该用户**当前**是管理员
    /// （不是签发时是管理员），杜绝"权限已转出、旧票据仍能操作"。
    /// </summary>
    public async Task<TicketAuthResult> ValidateAsync(string? ticket, bool requireAdmin)
    {
        if (string.IsNullOrWhiteSpace(ticket))
        {
            return new TicketAuthResult
            {
                Success = false,
                ReasonCode = AuditReason.NoTicket,
                Message = "缺少访问凭证，请先登录",
                HttpStatus = 401
            };
        }

        var session = await _db.Sessions.Find(s => s.Ticket == ticket).FirstOrDefaultAsync();
        if (session is null)
        {
            return new TicketAuthResult
            {
                Success = false,
                ReasonCode = AuditReason.SessionInvalid,
                Message = "访问凭证无效",
                HttpStatus = 401
            };
        }

        if (session.RevokedAt is not null)
        {
            return new TicketAuthResult
            {
                Success = false,
                ReasonCode = AuditReason.SessionRevoked,
                Message = "访问凭证已失效，请重新登录",
                HttpStatus = 401
            };
        }

        if (session.ExpiresAt <= DateTime.UtcNow)
        {
            return new TicketAuthResult
            {
                Success = false,
                ReasonCode = AuditReason.SessionExpired,
                Message = "访问凭证已过期，请重新登录",
                HttpStatus = 401
            };
        }

        // 关键：实时查库取当前身份，不信任票据中的快照
        var user = await _db.Users.Find(u => u.Username == session.Username).FirstOrDefaultAsync();
        if (user is null)
        {
            return new TicketAuthResult
            {
                Success = false,
                ReasonCode = AuditReason.SessionInvalid,
                Message = "账号不存在或已被注销",
                HttpStatus = 401
            };
        }

        // 账号被锁定 / 待审核 / 禁用后，既有票据必须一并失效，
        // 否则"锁定账号"只是挡住了登录，手里有票据的人照样畅通无阻。
        if (user.Status != UserStatus.Enabled)
        {
            return new TicketAuthResult
            {
                Success = false,
                User = user,
                Session = session,
                ReasonCode = AuditReason.AccountNotEnabled,
                Message = $"账号当前状态为「{user.Status}」，会话已失效",
                HttpStatus = 403
            };
        }

        if (requireAdmin && !user.IsAdmin)
        {
            return new TicketAuthResult
            {
                Success = false,
                User = user,
                Session = session,
                ReasonCode = AuditReason.NotAdmin,
                Message = "无管理员权限",
                HttpStatus = 403
            };
        }

        // 滑动续期：只更新必要字段，避免整文档覆盖引发并发写冲突
        await _db.Sessions.UpdateOneAsync(
            s => s.Id == session.Id,
            Builders<Session>.Update
                .Set(s => s.LastSeenAt, DateTime.UtcNow)
                .Set(s => s.ExpiresAt, DateTime.UtcNow.Add(SlidingWindow)));

        return new TicketAuthResult { Success = true, User = user, Session = session };
    }

    /// <summary>吊销票据（登出）。</summary>
    public async Task RevokeAsync(string ticket, string reason)
    {
        await _db.Sessions.UpdateOneAsync(
            s => s.Ticket == ticket && s.RevokedAt == null,
            Builders<Session>.Update
                .Set(s => s.RevokedAt, DateTime.UtcNow)
                .Set(s => s.RevokedReason, reason));
    }

    /// <summary>吊销某账号的全部票据（权限变更 / 账号被处置时使用）。</summary>
    public async Task RevokeAllForUserAsync(string username, string reason)
    {
        await _db.Sessions.UpdateManyAsync(
            s => s.Username == username && s.RevokedAt == null,
            Builders<Session>.Update
                .Set(s => s.RevokedAt, DateTime.UtcNow)
                .Set(s => s.RevokedReason, reason));
    }

    /// <summary>
    /// 32 字节密码学安全随机数，Base64Url 编码。
    /// 不用 Guid：Guid v4 只有 122 位熵且格式可预测，不适合做会话凭证。
    /// 用 URL 安全字符集，便于放在 Authorization 头与日志里不产生转义问题。
    /// </summary>
    private static string GenerateTicket()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
