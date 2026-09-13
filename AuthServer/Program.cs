using AuthServer.Services;

namespace AuthServer;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // 本地覆盖配置：appsettings.Local.json 已在 .gitignore 中，
        // 适合放 SMTP 授权码这类"只属于本机、绝不能进版本库"的敏感项。
        builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: true);

        // Add services to the container.
        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        // 注册 MongoDB 服务
        builder.Services.AddSingleton<MongoDbService>();

        // ---- 邮箱验证码 ----
        // 授权码等敏感项支持环境变量覆盖，避免落在安装目录的配置文件里被覆盖安装冲掉。
        var emailOptions = new EmailOptions();
        builder.Configuration.GetSection("Email").Bind(emailOptions);
        emailOptions.ApplyEnvironmentOverrides();
        builder.Services.AddSingleton(emailOptions);

        // 配置不全时自动降级为控制台发件器，保证注册/找回密码链路在离线环境依然可用
        IEmailSender emailSender = emailOptions.IsSmtpReady
            ? new SmtpEmailSender(emailOptions)
            : new ConsoleEmailSender();
        builder.Services.AddSingleton(emailSender);
        builder.Services.AddSingleton<VerificationService>();

        // 允许前端跨域访问
        builder.Services.AddCors(options =>
        {
            options.AddPolicy("AllowFrontend", policy =>
            {
                policy.AllowAnyOrigin()
                      .AllowAnyHeader()
                      .AllowAnyMethod();
            });
        });

        var app = builder.Build();

        // 启动时明确告知当前发件通道，避免"以为在发真邮件、其实只打了日志"
        if (!emailOptions.Enabled)
        {
            Console.WriteLine("[Email] 邮件功能已关闭（Email:Enabled=false），注册将回退为无需邮箱。");
        }
        else if (emailSender.DeliversRealMail)
        {
            Console.WriteLine($"[Email] 发件通道：{emailSender.Name}");
        }
        else
        {
            Console.WriteLine("[Email] 发件通道：控制台（验证码打印在日志中，未真实投递）。");
            Console.WriteLine("[Email] 如需真实发信：在 appsettings.json 的 Email 节填好 Account 与 Password（授权码），或设置环境变量 AUTHBASELINE_EMAIL_PASSWORD。");
        }

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseCors("AllowFrontend");

        app.UseDefaultFiles();
        app.UseStaticFiles();

        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}
