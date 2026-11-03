using AuthServer.Models;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;

namespace AuthServer.Services.Otp;

/**
 * 存量账号迁移工具：把「只有口令哈希、没有链」的账号迁成「有链、没有哈希」。
 *
 * ── 为什么需要它（而不是继续靠登录时的懒迁移）────────────────────
 * P3 的迁移是把口令在登录那一刻顺手折叠成链 —— 它成立的前提是「登录会拿到明文口令」。
 * P8 把口令路径删掉之后，登录只收链值，**再也不会拿到明文**：
 * 于是任何「有哈希、无链」的账号都进不来了，而且它连自救的入口都没有
 * （`reset-password` 要邮箱验证码，种子 admin 压根没有邮箱）。
 *
 * 所以这是一条**只能由运维在本机执行**的一次性通道：
 * 它对每个账号做的仍然是"用明文口令建一条链"，与登录懒迁移完全同一件事，
 * 区别只在于触发者从"用户自己"换成了"坐在数据库旁边的人"。
 *
 * ── 两个必须成立的前提 ────────────────────────────────────────
 * ① 服务进程最好处于停止状态。不停也能跑（链是 upsert，哈希是单字段 unset），
 *    但迁移期间那个账号的登录会看到中间态（一条刚换上的新链，用户手里还是旧的）。
 * ② 口令要么从环境变量给，要么交互式输入，**刻意不支持命令行参数** ——
 *    与 pepper 导出同一条理由：argv 会留在 shell 历史与进程列表里。
 *
 * ── `--force` 是什么 ─────────────────────────────────────────
 * 默认语义是"用旧哈希校验你确实知道这个口令"，校验不过就拒绝 —— 这样它不会被
 * 误用成"谁都能改任意人的口令"的工具。加 `--force` 则跳过校验，等价于**管理员重置**：
 * 明文不再需要与旧口令一致，直接成为新口令。口令已经彻底忘掉时只能走这条。
 *
 * ── 用法 ───────────────────────────────────────────────────
 *   authserver.exe --rechain --username admin
 *   authserver.exe --rechain --username alice --force
 *   set AUTHBASELINE_RECHAIN_PASSWORD=Xxx12345   （Windows cmd）
 *   $env:AUTHBASELINE_RECHAIN_PASSWORD="Xxx12345"（PowerShell）
 */
internal static class OtpRechainCli
{
    private const string PasswordEnvVar = "AUTHBASELINE_RECHAIN_PASSWORD";

    /// <summary>识别本模块负责的子命令。</summary>
    public static bool IsCommand(string[] args) =>
        args.Length > 0 && string.Equals(args[0], "--rechain", StringComparison.Ordinal);

    public static int Run(string[] args)
    {
        string? username = null;
        var force = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--username":
                    if (i + 1 < args.Length) username = args[++i];
                    break;
                case "--force":
                    force = true;
                    break;
                default:
                    return Usage($"未知参数：{args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(username)) return Usage("必须用 --username 指定账号");

        try
        {
            IConfiguration config = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: true)
                // Local 覆盖常规配置，与 Web 主机加载顺序保持一致：
                // 否则会出现"服务连的是 A 库、工具改的是 B 库"这种最难查的错。
                .AddJsonFile("appsettings.Local.json", optional: true)
                .AddEnvironmentVariables()
                .Build();

            var otp = new OtpOptions();
            config.GetSection(OtpOptions.SectionName).Bind(otp);
            otp.ApplyEnvironmentOverrides();
            otp.Validate();

            var connectionString = config.GetValue<string>("MongoDbSettings:ConnectionString")
                                   ?? "mongodb://localhost:27017";
            var databaseName = config.GetValue<string>("MongoDbSettings:DatabaseName")
                               ?? "AuthBaselineDb";

            Console.WriteLine($"[Rechain] 目标库：{databaseName} · 链长 N={otp.Length} · PBKDF2 {otp.KdfIterations} 次");

            var database = new MongoClient(connectionString).GetDatabase(databaseName);
            var users = database.GetCollection<User>("Users");
            var chains = database.GetCollection<OtpChain>(OtpChainStore.CollectionName);

            var target = username.Trim().ToLowerInvariant();
            var user = users.Find(u => u.Username == target).FirstOrDefault();
            if (user is null)
            {
                Console.Error.WriteLine($"[Rechain] 账号不存在：{target}");
                return 3;
            }

            var password = ReadPassword();
            if (password is null) return 2;

            // 旧哈希在 ⇒ 默认拿它校验一次。这是本工具唯一"知道口令对不对"的时刻，
            // 也是它不能被当成"任意改口令"的保证。
            if (!string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                if (!force)
                {
                    PepperProvider pepper;
                    try
                    {
                        pepper = new PepperProvider(config);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[Rechain] 读取本机 pepper 失败：{ex.Message}");
                        Console.Error.WriteLine("[Rechain] 没有 pepper 就无法校验旧口令。若确实要强制重置，请加 --force。");
                        return 4;
                    }

                    var check = PasswordHasher.Verify(password, user.PasswordHash, pepper.Pepper);
                    if (!check.Valid)
                    {
                        Console.Error.WriteLine("[Rechain] 口令与库中旧哈希不符，已拒绝。");
                        Console.Error.WriteLine("[Rechain] 若这个账号的口令确实已经找不回来了，加 --force 做一次强制重置。");
                        return 5;
                    }

                    Console.WriteLine("[Rechain] 旧口令校验通过（这是迁移，不是重置）");
                }
                else
                {
                    Console.WriteLine("[Rechain] ⚠️ --force：跳过旧口令校验，给定口令将**成为新的**口令");
                }
            }
            else
            {
                Console.WriteLine("[Rechain] 该账号没有旧哈希（可能已迁移过），按「重设口令」处理");
            }

            var store = new OtpChainStore(chains, otp);
            var chain = store.RebuildAsync(user.Id, user.Username, password).GetAwaiter().GetResult();

            // 迁移完成的**判据**是哈希真的没了，而不是"链建好了"：
            // 两个都成立才算迁移成功，否则下次还得跑一遍这个工具。
            users.UpdateOne(Builders<User>.Filter.Eq(u => u.Id, user.Id),
                Builders<User>.Update.Unset(u => u.PasswordHash));

            Console.WriteLine();
            Console.WriteLine($"[Rechain] 完成：{user.Username} 已建链（第 {chain.Generation} 代，k={chain.K}/{chain.Length}），旧口令哈希已清除");
            Console.WriteLine("[Rechain] 用那个账号登录一次即可确认（登录会消耗一格，k 变成 " + (chain.K - 1) + "）");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Rechain] 失败：{ex.Message}");
            return 1;
        }
    }

    private static string? ReadPassword()
    {
        var fromEnv = Environment.GetEnvironmentVariable(PasswordEnvVar);
        if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;

        if (Console.IsInputRedirected)
        {
            Console.Error.WriteLine($"[Rechain] 非交互环境，请通过环境变量 {PasswordEnvVar} 提供口令。");
            return null;
        }

        Console.Write("[Rechain] 该账号的口令（输入不回显）：");
        var buffer = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Length > 0) buffer.Length--;
            }
            else buffer.Append(key.KeyChar);
        }
        Console.WriteLine();

        var value = buffer.ToString();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static int Usage(string? error)
    {
        if (!string.IsNullOrEmpty(error)) Console.Error.WriteLine($"[Rechain] {error}");
        Console.Error.WriteLine();
        Console.Error.WriteLine("用法：");
        Console.Error.WriteLine("  authserver.exe --rechain --username <账号> [--force]");
        Console.Error.WriteLine();
        Console.Error.WriteLine("  --force   跳过旧口令校验（= 管理员重置，给定口令成为新口令）");
        Console.Error.WriteLine($"  口令来源：环境变量 {PasswordEnvVar}，否则交互式输入");
        Console.Error.WriteLine();
        Console.Error.WriteLine("它做的是：用明文口令建一条新链 → 清除该账号的历史口令哈希。");
        Console.Error.WriteLine("P8 之后登录只认链值，所以「有哈希、无链」的账号必须先用本工具迁移一次。");
        return 2;
    }
}
