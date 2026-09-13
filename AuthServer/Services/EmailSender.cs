using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace AuthServer.Services;

/// <summary>
/// 验证码邮件发送抽象。
///
/// 之所以抽象成接口而不是直接写 SMTP：开发联调和课堂演示常常没有外网，
/// 控制台实现可以让"发送验证码 → 校验 → 建号/改密"整条链路在离线环境跑通，
/// 上线只需改一行配置切到 SMTP，业务代码一行不动。
/// </summary>
public interface IEmailSender
{
    /// <summary>实现名，写入审计与启动日志，便于判断当前在用什么通道发信。</summary>
    string Name { get; }

    /// <summary>是否为真实投递。false 表示验证码只打印在服务端日志里。</summary>
    bool DeliversRealMail { get; }

    Task SendVerificationCodeAsync(string toEmail, string code, string purpose,
        int validMinutes, CancellationToken ct = default);
}

/// <summary>控制台发件器：验证码直接打印到后端日志，完全离线可用。</summary>
public sealed class ConsoleEmailSender : IEmailSender
{
    /// <summary>
    /// 桌面端以 GUI 方式启动、没有控制台窗口，只往 stdout 打印等于看不见。
    /// 因此同时落一份文件，保证"未配 SMTP 也能离线演示"这条退路真的可用。
    /// </summary>
    private static readonly string LogFile =
        Path.Combine(AppContext.BaseDirectory, "email-codes.log");

    private static readonly object FileLock = new();

    public string Name => "Console";
    public bool DeliversRealMail => false;

    public Task SendVerificationCodeAsync(string toEmail, string code, string purpose,
        int validMinutes, CancellationToken ct = default)
    {
        Console.WriteLine();
        Console.WriteLine("==================== 邮箱验证码（控制台发件器） ====================");
        Console.WriteLine($"  用途    : {EmailCodePurposeLabel(purpose)}");
        Console.WriteLine($"  收件邮箱: {toEmail}");
        Console.WriteLine($"  验证码  : {code}");
        Console.WriteLine($"  有效期  : {validMinutes} 分钟");
        Console.WriteLine($"  日志文件: {LogFile}");
        Console.WriteLine("  （当前为控制台模式，未真实投递；填入 SMTP 授权码后自动切换）");
        Console.WriteLine("===================================================================");
        Console.WriteLine();

        AppendToFile(toEmail, code, purpose, validMinutes);
        return Task.CompletedTask;
    }

    /// <summary>把验证码追加写入程序目录下的 email-codes.log，供无控制台的桌面端查看。</summary>
    private static void AppendToFile(string toEmail, string code, string purpose, int validMinutes)
    {
        try
        {
            var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 用途={EmailCodePurposeLabel(purpose)}"
                     + $" 收件邮箱={toEmail} 验证码={code} 有效期={validMinutes}分钟{Environment.NewLine}";
            lock (FileLock)
            {
                File.AppendAllText(LogFile, line);
            }
        }
        catch
        {
            // 落盘失败（例如安装目录只读）不应影响发码主流程
        }
    }

    private static string EmailCodePurposeLabel(string purpose) => purpose switch
    {
        "REGISTER" => "注册绑定邮箱",
        "RESET" => "重置密码",
        _ => purpose
    };
}

/// <summary>
/// SMTP 发件器（MailKit）。
///
/// 选 MailKit 而不是内置 System.Net.Mail.SmtpClient 的原因：
/// 465 端口要求"连接即 SSL"（隐式 SSL），而 SmtpClient.EnableSsl 只做 STARTTLS，
/// 连 465 会握手失败；MailKit 的 SslOnConnect 才是正确姿势。
/// </summary>
public sealed class SmtpEmailSender : IEmailSender
{
    private readonly EmailOptions _options;

    public SmtpEmailSender(EmailOptions options)
    {
        _options = options;
    }

    public string Name => $"SMTP({_options.SmtpHost}:{_options.SmtpPort})";
    public bool DeliversRealMail => true;

    public async Task SendVerificationCodeAsync(string toEmail, string code, string purpose,
        int validMinutes, CancellationToken ct = default)
    {
        var message = new MimeMessage();
        message.From.Add(string.IsNullOrWhiteSpace(_options.DisplayName)
            ? MailboxAddress.Parse(_options.Account)
            : new MailboxAddress(_options.DisplayName, _options.Account));
        message.To.Add(MailboxAddress.Parse(toEmail));
        message.Subject = $"【口令认证基线系统】{PurposeLabel(purpose)}验证码";

        var body = new BodyBuilder
        {
            TextBody =
                $"您的{PurposeLabel(purpose)}验证码是：{code}\n" +
                $"有效期 {validMinutes} 分钟，请勿泄露给他人。\n" +
                "如果这不是您本人的操作，请忽略本邮件。",
            HtmlBody = BuildHtml(code, purpose, validMinutes)
        };
        message.Body = body.ToMessageBody();

        using var client = new SmtpClient
        {
            Timeout = Math.Max(3, _options.TimeoutSeconds) * 1000
        };

        var socketOption = _options.UseSsl
            ? SecureSocketOptions.SslOnConnect
            : SecureSocketOptions.StartTlsWhenAvailable;

        await client.ConnectAsync(_options.SmtpHost, _options.SmtpPort, socketOption, ct);
        await client.AuthenticateAsync(_options.Account, _options.Password, ct);
        await client.SendAsync(message, ct);
        await client.DisconnectAsync(true, ct);
    }

    private static string PurposeLabel(string purpose) => purpose switch
    {
        "REGISTER" => "注册绑定邮箱",
        "RESET" => "重置密码",
        _ => "身份验证"
    };

    private static string BuildHtml(string code, string purpose, int validMinutes) => $"""
        <div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;max-width:520px;margin:0 auto;
                    padding:28px 24px;border:1px solid #e3e8ef;border-radius:12px;color:#1f2937">
          <h2 style="margin:0 0 6px;font-size:18px">口令认证基线系统</h2>
          <p style="margin:0 0 20px;color:#6b7280;font-size:13px">{PurposeLabel(purpose)}</p>
          <p style="margin:0 0 10px;font-size:14px">您正在进行的操作需要邮箱验证，验证码为：</p>
          <p style="margin:0 0 20px;font-size:30px;font-weight:700;letter-spacing:8px;color:#2563eb">{code}</p>
          <p style="margin:0;font-size:13px;color:#6b7280">
            有效期 {validMinutes} 分钟，请勿泄露给他人。若非本人操作，请忽略本邮件。
          </p>
        </div>
        """;
}
