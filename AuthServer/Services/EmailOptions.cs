namespace AuthServer.Services;

/// <summary>
/// 邮件发送配置（对应 appsettings.json 的 "Email" 节）。
///
/// 敏感字段说明：
///   Password 为邮箱 SMTP 授权码，**绝不写进代码、也不进版本库**。
///   读取优先级：环境变量 AUTHBASELINE_EMAIL_PASSWORD > 配置文件。
/// </summary>
public class EmailOptions
{
    /// <summary>邮件功能总开关。关闭时不发码，注册回退为"无需邮箱"的老流程。</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>发件实现：Console（验证码打印到日志，便于离线演示）/ Smtp（真实投递）。</summary>
    public string Provider { get; set; } = "Console";

    public string SmtpHost { get; set; } = "smtp.qq.com";

    /// <summary>465 为隐式 SSL 直连，587 为 STARTTLS；QQ 邮箱推荐 465。</summary>
    public int SmtpPort { get; set; } = 465;

    public bool UseSsl { get; set; } = true;

    /// <summary>发件邮箱完整地址，如 noreply@example.com。</summary>
    public string Account { get; set; } = string.Empty;

    /// <summary>16 位 SMTP 授权码（不是邮箱登录密码）。</summary>
    public string Password { get; set; } = string.Empty;

    public string DisplayName { get; set; } = "口令认证基线系统";

    /// <summary>SMTP 调用超时（秒）。必须设置，否则网络异常时登录/注册按钮会一直转圈。</summary>
    public int TimeoutSeconds { get; set; } = 10;

    /// <summary>配置是否齐全到足以真实发信。</summary>
    public bool IsSmtpReady =>
        Enabled &&
        string.Equals(Provider, "Smtp", StringComparison.OrdinalIgnoreCase) &&
        !string.IsNullOrWhiteSpace(Account) &&
        !string.IsNullOrWhiteSpace(Password) &&
        !string.IsNullOrWhiteSpace(SmtpHost) &&
        SmtpPort > 0;

    /// <summary>从环境变量覆盖敏感项，避免授权码落在安装目录的配置文件里被覆盖安装冲掉。</summary>
    public void ApplyEnvironmentOverrides()
    {
        var account = Environment.GetEnvironmentVariable("AUTHBASELINE_EMAIL_ACCOUNT");
        if (!string.IsNullOrWhiteSpace(account)) Account = account.Trim();

        var password = Environment.GetEnvironmentVariable("AUTHBASELINE_EMAIL_PASSWORD");
        if (!string.IsNullOrWhiteSpace(password)) Password = password.Trim();

        var provider = Environment.GetEnvironmentVariable("AUTHBASELINE_EMAIL_PROVIDER");
        if (!string.IsNullOrWhiteSpace(provider)) Provider = provider.Trim();
    }
}
