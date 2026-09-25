using System.Security.Cryptography;
using System.Text.RegularExpressions;
using AuthServer.Models;
using MongoDB.Driver;

namespace AuthServer.Services;

/// <summary>邮箱规范化的共用工具。</summary>
public static class EmailUtil
{
    private static readonly Regex EmailPattern =
        new(@"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$", RegexOptions.Compiled);

    public static string Normalize(string? email) => email?.Trim().ToLowerInvariant() ?? string.Empty;

    public static bool IsValid(string? email) =>
        !string.IsNullOrWhiteSpace(email) && EmailPattern.IsMatch(email.Trim());

    /// <summary>
    /// 邮箱脱敏，用于界面提示与审计日志：user@example.com → u*****@example.com。
    /// 固定用 5 个星号，连长度也不暴露。
    /// </summary>
    public static string Mask(string? email)
    {
        var normalized = Normalize(email);
        if (string.IsNullOrEmpty(normalized)) return string.Empty;

        var at = normalized.IndexOf('@');
        if (at <= 0) return "*****";

        var name = normalized[..at];
        var domain = normalized[at..];
        var head = name[..1];
        return $"{head}*****{domain}";
    }
}

/// <summary>发码结果。</summary>
public sealed record SendCodeResult(bool Success, string Code, string Message, EmailCode? Record = null);

/// <summary>校验结果。</summary>
public sealed record VerifyCodeResult(bool Success, string Code, string Message, EmailCode? Record = null);

/// <summary>
/// 验证码失败的业务 code → 审计原因码。
///
/// 两套码刻意分开，不要合并：
///   - Code 会出现在 HTTP 响应里，是**给用户看**的（"验证码已过期，请重新获取"）；
///   - reasonCode 只进审计库，是**给审计员筛**的（CODE_EXPIRED）。
/// 现在它们一一对应，但一旦某天为了防枚举把对外话术统一成一句，
/// 审计就会跟着丢失区分度 —— 那正是最需要留痕的时候。所以映射单独放在这里。
/// </summary>
public static class VerifyCodeReason
{
    public static string From(string code) => code switch
    {
        "CODE_INVALID" => AuditReason.CodeInvalid,
        "CODE_USED" => AuditReason.CodeUsed,
        "CODE_EXPIRED" => AuditReason.CodeExpired,
        "EMAIL_MISMATCH" => AuditReason.EmailMismatch,
        "CODE_TOO_MANY_ATTEMPTS" => AuditReason.CodeTooManyAttempts,
        "CODE_MISMATCH" => AuditReason.CodeInvalid,
        "CODE_REQUIRED" => AuditReason.CodeRequired,
        _ => AuditReason.CodeInvalid
    };
}

/// <summary>发码失败的业务 code → 审计原因码。与 VerifyCodeReason 同理，两套码不合并。</summary>
public static class SendCodeReason
{
    public static string From(string code) => code switch
    {
        "RESEND_TOO_SOON" => AuditReason.ResendTooSoon,
        "EMAIL_DISABLED" => AuditReason.EmailDisabled,
        "EMAIL_SEND_FAILED" => AuditReason.EmailSendFailed,
        _ => AuditReason.EmailSendFailed
    };
}

/// <summary>
/// 邮箱验证码服务：生成、发送、校验、限流。
///
/// 规则（与产品约定一致）：
///   - 6 位数字，取自密码学安全随机数（RandomNumberGenerator，不用 new Random()）
///   - 有效期 5 分钟
///   - 最多校验 5 次，超出即作废
///   - 同一账号同一用途 60 秒内只能发一次
///   - 只存 BCrypt 散列，校验通过立即置为已用（一次性）
///   - 记录与 (用户名, 用途) 绑定，杜绝"一码通用"
/// </summary>
public sealed class VerificationService
{
    private const int CodeLength = 6;
    private const int MaxAttempts = 5;
    private static readonly TimeSpan Validity = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ResendCooldown = TimeSpan.FromSeconds(60);

    private readonly MongoDbService _db;
    private readonly IEmailSender _sender;
    private readonly EmailOptions _options;

    public VerificationService(MongoDbService db, IEmailSender sender, EmailOptions options)
    {
        _db = db;
        _sender = sender;
        _options = options;
    }

    public string SenderName => _sender.Name;
    public bool DeliversRealMail => _sender.DeliversRealMail;

    /// <summary>
    /// 生成并发送验证码。
    /// 调用方需已完成业务前置校验（用户名是否占用、邮箱是否匹配账号等）。
    /// </summary>
    public async Task<SendCodeResult> SendAsync(string username, string email, string purpose,
        CancellationToken ct = default)
    {
        if (!_options.Enabled)
        {
            return new SendCodeResult(false, "EMAIL_DISABLED",
                "邮件服务当前未启用，请联系管理员或改用其它方式。");
        }

        var user = username.Trim().ToLowerInvariant();
        var mail = EmailUtil.Normalize(email);
        var now = DateTime.UtcNow;

        // 60 秒重发冷却：仅对"仍然有效且未使用"的验证码生效
        var latest = await FindLatestAsync(user, purpose, ct);
        if (latest is not null && latest.ConsumedAt is null && latest.ExpiresAt > now)
        {
            var elapsed = (now - latest.LastSentAt).TotalSeconds;
            if (elapsed < ResendCooldown.TotalSeconds)
            {
                var wait = (int)Math.Ceiling(ResendCooldown.TotalSeconds - elapsed);
                return new SendCodeResult(false, "RESEND_TOO_SOON",
                    $"请求过于频繁，请 {wait} 秒后再试。", latest);
            }
        }

        // 同一账号同一用途只保留一个有效验证码，旧的直接作废
        await _db.EmailCodes.DeleteManyAsync(
            Builders<EmailCode>.Filter.And(
                Builders<EmailCode>.Filter.Eq(x => x.Username, user),
                Builders<EmailCode>.Filter.Eq(x => x.Purpose, purpose)), ct);

        var code = GenerateCode();
        var record = new EmailCode
        {
            Username = user,
            Email = mail,
            Purpose = purpose,
            CodeHash = BCrypt.Net.BCrypt.HashPassword(code),
            ExpiresAt = now.Add(Validity),
            Attempts = 0,
            CreatedAt = now,
            LastSentAt = now
        };

        await _db.EmailCodes.InsertOneAsync(record, cancellationToken: ct);

        try
        {
            await _sender.SendVerificationCodeAsync(mail, code, purpose, (int)Validity.TotalMinutes, ct);
        }
        catch (Exception ex)
        {
            // 发信失败就把记录清掉，避免用户拿到一个"永远不会到达"的验证码却还在等
            await _db.EmailCodes.DeleteOneAsync(x => x.Id == record.Id, ct);
            Console.WriteLine($"[Email] 发送失败：{ex.Message}");
            return new SendCodeResult(false, "EMAIL_SEND_FAILED",
                "验证码发送失败，请稍后重试或联系管理员。");
        }

        return new SendCodeResult(true, "OK",
            $"验证码已发送，{(int)Validity.TotalMinutes} 分钟内有效。", record);
    }

    /// <summary>
    /// 校验验证码。成功即作废（一次性）。
    /// expectedEmail 非空时还要比对验证码归属的邮箱 —— 该检查放在"消耗验证码之前"，
    /// 否则用户只是把邮箱填错，验证码就已经被验掉，第二次重试会莫名提示"已使用"。
    /// </summary>
    public async Task<VerifyCodeResult> VerifyAsync(string username, string purpose, string code,
        string? expectedEmail = null, CancellationToken ct = default)
    {
        var user = username.Trim().ToLowerInvariant();
        var input = (code ?? string.Empty).Trim();

        if (string.IsNullOrWhiteSpace(input))
            return new VerifyCodeResult(false, "CODE_REQUIRED", "请输入邮箱验证码。");

        var record = await FindLatestAsync(user, purpose, ct);
        if (record is null)
            return new VerifyCodeResult(false, "CODE_INVALID", "验证码无效，请重新获取。");

        if (record.ConsumedAt is not null)
            return new VerifyCodeResult(false, "CODE_USED", "该验证码已使用，请重新获取。");

        if (record.ExpiresAt <= DateTime.UtcNow)
            return new VerifyCodeResult(false, "CODE_EXPIRED", "验证码已过期，请重新获取。");

        if (!string.IsNullOrEmpty(expectedEmail)
            && !string.Equals(record.Email, EmailUtil.Normalize(expectedEmail), StringComparison.Ordinal))
        {
            return new VerifyCodeResult(false, "EMAIL_MISMATCH", "验证码与所填邮箱不一致，请重新获取。");
        }

        if (record.Attempts >= MaxAttempts)
        {
            await ConsumeAsync(record, ct);
            return new VerifyCodeResult(false, "CODE_TOO_MANY_ATTEMPTS", "验证码错误次数过多，请重新获取。");
        }

        // 先落库计数再比对：即使中途异常，也不会出现"可以无限次尝试"的窗口
        var attempts = record.Attempts + 1;
        await _db.EmailCodes.UpdateOneAsync(
            Builders<EmailCode>.Filter.Eq(x => x.Id, record.Id),
            Builders<EmailCode>.Update.Set(x => x.Attempts, attempts),
            cancellationToken: ct);
        record.Attempts = attempts;

        if (!BCrypt.Net.BCrypt.Verify(input, record.CodeHash))
        {
            var left = MaxAttempts - attempts;
            if (left <= 0)
            {
                await ConsumeAsync(record, ct);
                return new VerifyCodeResult(false, "CODE_TOO_MANY_ATTEMPTS", "验证码错误次数过多，请重新获取。");
            }
            return new VerifyCodeResult(false, "CODE_MISMATCH", $"验证码错误，还可尝试 {left} 次。");
        }

        await ConsumeAsync(record, ct);
        return new VerifyCodeResult(true, "OK", "验证码校验通过。", record);
    }

    private async Task ConsumeAsync(EmailCode record, CancellationToken ct)
    {
        record.ConsumedAt = DateTime.UtcNow;
        await _db.EmailCodes.UpdateOneAsync(
            Builders<EmailCode>.Filter.Eq(x => x.Id, record.Id),
            Builders<EmailCode>.Update.Set(x => x.ConsumedAt, record.ConsumedAt),
            cancellationToken: ct);
    }

    private async Task<EmailCode?> FindLatestAsync(string username, string purpose, CancellationToken ct)
    {
        return await _db.EmailCodes
            .Find(Builders<EmailCode>.Filter.And(
                Builders<EmailCode>.Filter.Eq(x => x.Username, username),
                Builders<EmailCode>.Filter.Eq(x => x.Purpose, purpose)))
            .SortByDescending(x => x.CreatedAt)
            .FirstOrDefaultAsync(ct);
    }

    /// <summary>6 位数字验证码，使用密码学安全随机源。</summary>
    private static string GenerateCode()
    {
        // 上限 10^CodeLength，左闭右开，保证位数固定（含前导 0）
        var exclusiveUpper = (int)Math.Pow(10, CodeLength);
        return RandomNumberGenerator.GetInt32(0, exclusiveUpper).ToString($"D{CodeLength}");
    }
}
