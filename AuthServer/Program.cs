using System.Text.RegularExpressions;
using AuthServer.Services;

// 本程序集只跑 Windows：它是 Tauri 壳的桌面端 sidecar，发布目标固定为 win-x64，
// 且用到的系统能力本身就是 Windows 专有的（现在的 DPAPI，以及后续要做的证书存储）。
// 在这里声明一次平台，好过在每个调用点各写一遍 [SupportedOSPlatform]
// —— 后者还会沿调用链向外传播，把噪音扩散到无关文件里。
[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace AuthServer;

public class Program
{
    public static int Main(string[] args)
    {
        // ── 子命令必须在这里处理，早于 CreateBuilder ──
        // WebApplication.CreateBuilder(args) 会消费命令行参数（它要从里面认领 --urls 等开关），
        // 我们自己的开关若留到那之后再判断，会被当成"未知参数"，行为难以预料。
        if (PepperCli.IsPepperCommand(args))
            return PepperCli.Run(args);

        var builder = WebApplication.CreateBuilder(args);

        // 本地覆盖配置：appsettings.Local.json 已在 .gitignore 中，
        // 适合放 SMTP 授权码这类"只属于本机、绝不能进版本库"的敏感项。
        builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: true);

        // ── pepper：必须早于任何触库操作 ──
        // 放在这个位置不是随手排的，有两重语义：
        //   1) 时机：MongoDbService 虽为懒构造，但它一被构造就会执行 SeedAdmin
        //      （写入种子管理员的**口令哈希**），而写哈希需要 pepper。若 pepper 尚未就绪，
        //      种子账号就会以另一种格式落库，后续行为变得难以推测。
        //   2) 失败即终止：pepper 读不到时**拒绝启动**，而不是退化成"没有 pepper 也能验"。
        //      静默降级等于把这一整套机制变成摆设（详见 PepperProvider 的注释）。
        PepperProvider pepper;
        try
        {
            pepper = new PepperProvider(builder.Configuration);
            Console.WriteLine($"[Pepper] 已就绪 · 指纹 {pepper.Fingerprint} · 来源 {pepper.Source}");
        }
        catch (PepperUnavailableException ex)
        {
            // 桌面端的 Console 输出留不下来（stdout/stderr 被转发给无控制台的 GUI），
            // 所以额外写一份可读文件，把"白窗口"变成"可排障"。
            Console.Error.WriteLine($"[Pepper] 启动被拒绝：{ex.Message}");
            PepperProvider.WriteErrorLog(ex.ToString());
            return 1;
        }

        // ── 传输层证书：必须在 builder.Build() 之前挂到 Kestrel 上 ──
        // 与 pepper 同为"启动闸门"：证书不可用时按 RequireHttps 决定是拒绝启动还是显式退回 HTTP。
        //
        // ⚠️ Provision 可能是**阻塞**的：首次把 CA 写进 CurrentUser\Root 时 Windows 会弹一次
        //    「安全警告」，未确认就无限期等待（阶段 0 实测阻塞 12.2 秒，最长观察到 23 分钟）。
        //    这是设计已知代价，产品路径改由 NSIS 安装期写 LocalMachine\Root 规避。
        var transport = new TransportOptions();
        builder.Configuration.GetSection("Transport").Bind(transport);
        transport.ApplyEnvironmentOverrides();

        CertificateManager? certManager = null;

        if (transport.RequireHttps)
        {
            try
            {
                certManager = CertificateManager.Provision(transport.TrustStore);
                foreach (var note in certManager.Notes) Console.WriteLine($"[Cert] {note}");

                var leaf = certManager.LeafCertificate;
                builder.WebHost.ConfigureKestrel(o =>
                    o.ConfigureHttpsDefaults(h => h.ServerCertificate = leaf));

                Console.WriteLine(
                    $"[Transport] HTTPS 已启用 · {leaf.Subject} · 到期 {leaf.NotAfter:yyyy-MM-dd} " +
                    $"· 信任存储 {transport.TrustStore}");
                CertificateManager.ClearErrorLog();
            }
            catch (CertificateUnavailableException ex)
            {
                // 桌面端 Console 输出留不下来，所以必须额外写一份可读文件（同 pepper 的做法）
                Console.Error.WriteLine($"[Transport] 启动被拒绝：{ex.Message}");
                CertificateManager.WriteErrorLog(ex.ToString());
                return 1;
            }
        }
        else
        {
            // 对照实验模式：显式退回明文 HTTP。
            //
            // 这里**不去加载证书**：RequireHttps=false 的语义就是"本次跑明文"，
            // 若此时仍然挂上证书、实际走 HTTPS，这个开关就名不副实了
            // （状态栏会说"明文"而链路其实是加密的，比不加密更糟 —— 它会让验收结论失真）。
            //
            // 把 lib.rs 传进来的 `--urls https://127.0.0.1:PORT` 就地换成 http（端口不变），
            // 这样"一键退回 HTTP"真的只需要改一个配置，不必连 Rust 侧一起改。
            var urls = builder.Configuration["urls"];
            if (!string.IsNullOrWhiteSpace(urls))
            {
                var downgraded = urls.Split(';', StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => Regex.Replace(u, "^https://", "http://", RegexOptions.IgnoreCase))
                    .ToArray();
                builder.WebHost.UseUrls(downgraded);
                Console.WriteLine($"[Transport] 监听地址已降级为 {string.Join(" ", downgraded)}");
            }
            Console.WriteLine("[Transport] ⚠️ RequireHttps=false ⇒ 本次链路**无加密**，状态栏会红色常驻提示");
        }

        // Add services to the container.
        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        // 注册 pepper（单例）：MongoDbService 与 AuthController 都依赖它。
        builder.Services.AddSingleton(pepper);

        // 传输层状态：**降级运行时也必须注册** —— 否则 /api/auth/transport 在明文模式下会 500，
        // 那样"状态栏能显示明文"这件事本身就坏了，比不显示更麻烦。
        builder.Services.AddSingleton(transport);
        if (certManager is not null) builder.Services.AddSingleton(certManager);
        builder.Services.AddSingleton(new TransportInfo(
            HttpsEnabled: certManager is not null,
            RequireHttps: transport.RequireHttps,
            Subject: certManager?.LeafCertificate.Subject,
            NotAfter: certManager is null ? null : certManager.LeafCertificate.NotAfter,
            Thumbprint: certManager?.LeafCertificate.Thumbprint,
            TrustStore: certManager?.TrustStoreName));

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

        // ---- 实验二：审计服务与会话票据 ----
        // AuditService 由它统一串行化哈希链写入；SessionService 负责票据签发与校验。
        builder.Services.AddSingleton<AuditService>();
        builder.Services.AddSingleton<SessionService>();

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

        // app.Run() 会阻塞到进程关闭。写 return 0 只是为了满足 int Main 的签名；
        // 真正的失败路径（pepper 不可用）在上面已经显式返回了非 0 退出码。
        return 0;
    }
}
