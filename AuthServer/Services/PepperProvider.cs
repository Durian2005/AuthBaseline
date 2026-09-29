using System.Security.Cryptography;
using System.Text;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AuthServer.Services;

/// <summary>
/// pepper 不可用 —— 语义是「必须拒绝启动」，而不是「降级继续」。
///
/// 为什么要专门一个异常类型：pepper 的失败模式与其它配置项不同。
/// 多数配置读不到时可以退默认值，但 pepper 一旦"猜一个默认值"或"临时生成一个"，
/// 后果不是功能降级，而是**全库账号的口令再也验不过**（不可逆）。
/// 所以这里要的是一个能被 Program 明确捕获、并终止进程的信号。
/// </summary>
public sealed class PepperUnavailableException : Exception
{
    public PepperUnavailableException(string message, Exception? inner = null)
        : base(message, inner) { }
}

/// <summary>
/// 服务端 pepper 的加载、生成与保护。
///
/// ── pepper 是什么、解决什么问题 ──────────────────────────────
/// 口令在库里存的是 bcrypt 哈希。bcrypt 自带随机盐，已经能挡住彩虹表，
/// 但它挡不住"拿着库离线爆破弱口令"：盐和哈希都在库里，攻击者手上什么都不缺。
/// pepper 是**第二份秘密，且不存在库里** —— 它藏在服务端本机（DPAPI 保护的文件里）。
/// 于是"读走数据库"不再等于"可以开始爆破"，因为缺了 pepper 连一次验证都算不出来。
///
/// ── 与"盐"的分工（这是最容易被问混的一点）────────────────────
///   盐   ：每用户独立、**与哈希同库存放**，防的是"相同口令算出相同哈希"→ 彩虹表 / 批量比对；
///   pepper：全库共用、**与哈希分离存放**，防的是"库被整体拿走"。两者不互相替代。
///   也正因如此，pepper 绝不能写进会随程序一起分发的地方 ——
///   本项目里 `appsettings.Local.json` 会被 `tauri.conf.json` 的 bundle.resources
///   打进安装包，所以它是**明令禁止**的存放位置（详见 TRANSPORT-STORAGE-SECURITY-DESIGN.md §4.2）。
///
/// ── 存放与保护 ────────────────────────────────────────────
/// 默认落 `%LOCALAPPDATA%\AuthBaselineData\pepper.dat`，内容为 DPAPI(CurrentUser) 密文。
/// ⚠️ 目录名带 `Data` 后缀是刻意的：**安装目录是 `%LOCALAPPDATA%\AuthBaseline`**
/// （NSIS 的安装路径由 `productName` 决定），所以 pepper 绝不能放进 `AuthBaseline\` ——
/// 卸载器的清理、以及"清理安装残留"这类例行操作会把整个目录当作垃圾处理掉，
/// 而 pepper 一删就是全库口令不可验证。放在**同级但不同名**的目录里，安装/卸载都碰不到它。
///
/// 选 DPAPI 而不是"自己拿一个密钥去 AES"：DPAPI 的主密钥由 Windows 绑定「本机 + 当前用户
/// 配置文件」，别的账户/别的机器拿到这份密文也解不开，且不需要我们再去管一个"加密 pepper 的密钥"
/// （那会陷入"密钥的密钥"无限递归）。
///
/// ── 代价（必须对外说清，不能只说好处）─────────────────────────
/// DPAPI 绑定本机与本用户 ⇒ 换机器 / 重装系统 / 用户配置文件损坏 ⇒ pepper 读不出来
/// ⇒ **该机全部口令都无法验证**。注意这是"锁死"而不是"泄露"。
/// 缓解手段是导出备份：`authserver.exe --pepper-export`（见 PepperCli）。
///
/// ── 加载优先级 ────────────────────────────────────────────
///   ① 环境变量 AUTHBASELINE_PEPPER（Base64，或 `hex:` 前缀的十六进制）
///      —— 供自动化测试与 CI 用，完全绕过 DPAPI 与落盘，各测试进程互不干扰；
///   ② 环境变量 AUTHBASELINE_PEPPER_FILE 指定的路径；
///   ③ 默认路径 %LOCALAPPDATA%\AuthBaselineData\pepper.dat（见 DefaultPath 上的说明）；
///   ④ 都不存在 ⇒ 首次初始化（**必须先查库，见 InitialiseFirstRun**）。
/// </summary>
public sealed class PepperProvider
{
    /// <summary>pepper 长度：32 字节 = 256 位。作为 HMAC-SHA256 的密钥，这个长度已远超需要。</summary>
    public const int PepperLength = 32;

    /// <summary>落盘文件的魔术字，用来把"这不是 pepper 文件"与"文件损坏"区分开。</summary>
    private const string FileMagic = "ABPEPPER";

    /// <summary>落盘格式版本。日后若更换保护方式，靠它做兼容分支。</summary>
    private const byte FileFormatVersion = 1;

    public const string EnvVarDirect = "AUTHBASELINE_PEPPER";
    public const string EnvVarFile = "AUTHBASELINE_PEPPER_FILE";

    /// <summary>
    /// 仅用于测试：显式指定"老位置"的 pepper 文件。
    /// 有了它，迁移逻辑才能在临时目录里被完整演练，而不必去动本机真实的老文件。
    /// </summary>
    public const string EnvVarLegacyFile = "AUTHBASELINE_PEPPER_LEGACY_FILE";

    /// <summary>放数据的目录名。刻意与 tauri.conf.json 的 productName（AuthBaseline）不同名 —— 见 DefaultPath。</summary>
    private const string DataDirName = "AuthBaselineData";

    /// <summary>
    /// 本机默认落盘位置。
    ///
    /// 放 LocalApplicationData 而不是程序目录，理由有两条：
    ///   ① 程序目录若在 Program Files 下，非管理员进程写不进去；
    ///   ② 覆盖安装会把它冲掉。
    /// 而本项目更特殊的一点是：安装目录落在 `%LOCALAPPDATA%\AuthBaseline`（NSIS 按 productName 决定），
    /// 也就是说"程序目录"**本身就在 LocalApplicationData 里面**。所以这里不能顺着直觉写成
    /// `LocalApplicationData\AuthBaseline\pepper.dat` —— 那正好落在安装目录里，
    /// 卸载器的清理与"清安装残留"的例行操作都会顺手删掉它。用同级不同名的 `...Data\` 规避。
    /// </summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        DataDirName, "pepper.dat");

    /// <summary>
    /// 早期版本（S2 首次落地时）的 pepper 位置 —— **它在安装目录里**，属于设计缺陷。
    /// 保留这个常量只为一件事：把已经落在老位置的 pepper 迁移过来（见 MigrateFromLegacyIfNeeded）。
    /// 待确认所有部署点都已迁移后，这段与常量可一并删除。
    /// </summary>
    private static string LegacyPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "AuthBaseline", "pepper.dat");

    /// <summary>
    /// 启动失败时的可读原因落点。
    ///
    /// 为什么需要它：`lib.rs` 会把 sidecar 的 stdout/stderr 转发给无控制台的 GUI 进程，
    /// 所以 Console 输出**在桌面端根本留不下**（与 [Mongo]/[Audit] 的输出同理）。
    /// 一旦 pepper 加载失败，用户看到的只是"后端没起来"，没有任何线索。
    /// 把原因写成一个文件，是把"白窗口"变成"可排障"的最小成本做法。
    /// </summary>
    public static string ErrorLogPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        DataDirName, "pepper-error.log");

    /// <summary>
    /// DPAPI 的附加熵。它本身不是秘密（跟着代码走），作用是让别的程序
    /// "恰好"解开这份密文更难 —— 它必须携带同一个值才能 Unprotect。
    /// </summary>
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("AuthBaseline/pepper/v1");

    /// <summary>pepper 本体。</summary>
    public byte[] Pepper { get; }

    /// <summary>本次 pepper 从哪来（排障用；**不含 pepper 内容**）。</summary>
    public string Source { get; }

    /// <summary>
    /// 指纹：SHA-256(pepper) 的前 8 字节十六进制。
    ///
    /// 用途：确认"换机 / 重装之后读到的是不是同一个 pepper"。
    /// 只能回答"相同 / 不同"，无法反推 pepper —— 所以可以安全地打印在日志里。
    /// </summary>
    public string Fingerprint { get; }

    public PepperProvider(IConfiguration configuration)
    {
        // ① 环境变量直接给 pepper
        var raw = Environment.GetEnvironmentVariable(EnvVarDirect);
        if (!string.IsNullOrWhiteSpace(raw))
        {
            Pepper = ParseText(raw!, $"环境变量 {EnvVarDirect}");
            Source = $"环境变量 {EnvVarDirect}";
            Fingerprint = FingerprintOf(Pepper);
            return;
        }

        // ② / ③ 本机 pepper 的位置（显式指定优先于默认）
        var path = ResolvePath();

        // ③.5 老位置搬迁（见 MigrateFromLegacyIfNeeded）
        MigrateFromLegacyIfNeeded(path);

        if (File.Exists(path))
        {
            Pepper = ReadFrom(path);
            Source = path;
            Fingerprint = FingerprintOf(Pepper);
            return;
        }

        // ④ 该位置没有 pepper ⇒ 首次初始化。必须先查库确认这不是"pepper 丢了"，见 InitialiseFirstRun。
        Pepper = InitialiseFirstRun(configuration, path);
        Source = $"{path}（本次首次生成）";
        Fingerprint = FingerprintOf(Pepper);
    }

    /// <summary>
    /// 把老位置（`%LOCALAPPDATA%\AuthBaseline\`，即安装目录内）的 pepper 搬到新位置。
    ///
    /// 为什么必须搬而不是"两边都读"：留着老副本就等于 pepper 有两份，
    /// 而老那份躺在会被卸载器/清理工具扫荡的目录里 —— 一旦它被删、新那份又恰好没生成，
    /// 判定就会退化成"本机没有 pepper"，又回到"可能静默锁死"的岔路口上。
    /// 单一权威副本比"读哪儿都行"更安全。
    ///
    /// 失败处理：老文件解不开就**直接抛**，绝不退化成"当作首次部署、生成一个新的"——
    /// 那正是本类要防的静默锁死。
    /// </summary>
    private static void MigrateFromLegacyIfNeeded(string targetPath)
    {
        var legacyOverride = Environment.GetEnvironmentVariable(EnvVarLegacyFile);
        var hasOverride = !string.IsNullOrWhiteSpace(legacyOverride);

        // 守卫：目标既不是默认位置、用户也没显式指定老位置 ⇒ 什么都不做。
        //
        // 这个守卫不是形式主义。测试与 CI 用 AUTHBASELINE_PEPPER_FILE 指向一个空临时目录来演练
        // "首次初始化"。若在那里也去顺带读本机真实的老文件，就会把**真实 pepper** 复制进测试环境，
        // 于是"首次生成"这条断言静默失效（永远看不到生成分支），而且测试反而更"绿"。
        if (targetPath != DefaultPath && !hasOverride) return;

        var legacy = hasOverride ? legacyOverride! : LegacyPath;
        if (File.Exists(targetPath) || !File.Exists(legacy)) return;

        var pepper = ReadFrom(legacy);   // 解不开会抛 PepperUnavailableException
        WriteTo(targetPath, pepper);     // 原子写 + 回读校验通过才会走到下一行
        TryDelete(legacy);               // 删不掉也无妨（同一份 pepper，留着不是灾难）

        Console.WriteLine($"[Pepper] 已把 pepper 从旧位置迁移到 {targetPath}");
    }

    /// <summary>
    /// 本机 pepper 的位置：环境变量 AUTHBASELINE_PEPPER_FILE 优先，否则用默认路径。
    ///
    /// 语义是"pepper **应该放在**这里"，而不是"这里**必须已经有** pepper" ——
    /// 该位置为空时按"尚未初始化"处理（走首次初始化，**含查库判定**），而不是直接报错。
    /// 这个区分对测试很有价值：指向一个空目录，就能在完全不触碰真实 pepper 文件的前提下，
    /// 完整演练"首次生成"与"pepper 丢失 ⇒ 拒绝启动"这两条路径。
    /// </summary>
    public static string ResolvePath()
    {
        var explicitPath = Environment.GetEnvironmentVariable(EnvVarFile);
        return string.IsNullOrWhiteSpace(explicitPath) ? DefaultPath : explicitPath!;
    }

    /// <summary>
    /// 首次初始化。**这是整个 pepper 机制里最要紧的一处判断。**
    ///
    /// 为什么不能"文件不在就生成一个"：换机器 / 重装系统 / 用户配置文件损坏 / 有人删了文件，
    /// 都会表现为"找不到 pepper"。若这时静默生成一个新的，库里的哈希全是老 pepper 算出来的，
    /// 于是**全部账号变成"口令怎么输都不对"** —— 用户只会以为是口令记错了，
    /// 而这个错误不可逆、也没有任何提示。这比直接起不来恶劣得多。
    ///
    /// 所以判据是：**库里若已存在 pepper 格式的哈希，就说明本机曾经初始化过 pepper**，
    /// 此时拒绝生成、拒绝启动，并给出恢复路径。
    /// </summary>
    private static byte[] InitialiseFirstRun(IConfiguration configuration, string path)
    {
        if (AnyPepperFormatHashInDb(configuration))
        {
            throw new PepperUnavailableException(
                "本机找不到 pepper，但数据库中已存在 pepper 格式的口令哈希。\n" +
                "⇒ 说明这台机器**曾经初始化过** pepper，现在文件丢了" +
                "（换机 / 重装系统 / 换了 Windows 账户 / 文件被删）。\n" +
                "此时绝不能重新生成 —— 那会让全部账号无法登录。\n" +
                "恢复方式（任选其一）：\n" +
                "  1) 用备份导入：authserver.exe --pepper-import <导出的封装文件>\n" +
                "  2) 设置 AUTHBASELINE_PEPPER（Base64）或 AUTHBASELINE_PEPPER_FILE 指向原 pepper");
        }

        var pepper = RandomNumberGenerator.GetBytes(PepperLength);

        // 落盘必须成功。若落盘失败却继续运行，本进程中登录触发的升级
        // 会把账号改写成"用这个内存 pepper 算出来的哈希"，而下次启动读不到它 ⇒ 全库锁死。
        WriteTo(path, pepper);
        return pepper;
    }

    /// <summary>
    /// 库中是否存在 pepper 格式（`v2$` 前缀）的口令哈希。
    ///
    /// 用 BSON 层正则直查，不用 MongoDbService：那个服务是懒构造的，
    /// 而本判断必须发生在**任何触库操作之前**（包括它构造函数里的种子管理员）。
    /// </summary>
    private static bool AnyPepperFormatHashInDb(IConfiguration configuration)
    {
        var connectionString = configuration.GetValue<string>("MongoDbSettings:ConnectionString")
            ?? "mongodb://localhost:27017";
        var databaseName = configuration.GetValue<string>("MongoDbSettings:DatabaseName")
            ?? "AuthBaselineDb";

        var settings = MongoClientSettings.FromConnectionString(connectionString);
        // 启动路径上的等待必须有上限，否则库不可达时进程会长时间挂在那里、
        // 表现为"程序点了没反应"，比明确报错更难诊断。
        settings.ServerSelectionTimeout = TimeSpan.FromSeconds(5);

        var users = new MongoClient(settings).GetDatabase(databaseName)
            .GetCollection<BsonDocument>("Users");

        try
        {
            // 正则里的 \$ 是字面量美元符；"v2$" 前缀即 pepper 格式标记（见 PasswordHasher）
            return users.Find(Builders<BsonDocument>.Filter
                    .Regex("passwordHash", new BsonRegularExpression("^v2\\$")))
                .Limit(1)
                .Any();
        }
        catch (Exception ex)
        {
            // 连不上库 ⇒ 无法区分"真的是全新部署"和"pepper 丢了但库也恰好没起"。
            // 宁可起不来，也不能赌 —— 赌错的代价是全库口令锁死。
            throw new PepperUnavailableException(
                "无法确认本机是否曾经初始化过 pepper：数据库不可达。\n" +
                $"原因：{ex.Message}\n" +
                "若这确实是全新部署，可显式提供 pepper 以跳过该判定：" +
                $"设置 {EnvVarDirect}（Base64）或 {EnvVarFile}。", ex);
        }
    }

    /* ==================== 落盘 / 读取（原子） ==================== */

    /// <summary>读取本机 pepper。供导出工具用。</summary>
    public static byte[] ReadLocalPepper()
    {
        var path = ResolvePath();
        if (!File.Exists(path))
            throw new PepperUnavailableException($"本机没有 pepper 文件：{path}");
        return ReadFrom(path);
    }

    /// <summary>把 pepper 原子写入本机位置。供导入工具用。</summary>
    public static void WriteLocalPepper(byte[] pepper) => WriteTo(ResolvePath(), pepper);

    /// <summary>
    /// 原子落盘：临时文件 → 回读校验 → 改名覆盖。
    ///
    /// 回读校验不是"多此一举"：写盘可能因磁盘满、权限、被中途杀掉而得到半截文件。
    /// 不校验就返回的话，本次运行会拿一个"其实没存下来"的 pepper 去服务请求，
    /// 等下次启动读不到它，就再也对不上了。
    /// </summary>
    public static void WriteTo(string path, byte[] pepper)
    {
        if (pepper is null || pepper.Length != PepperLength)
            throw new PepperUnavailableException($"待写入的 pepper 长度非法（应为 {PepperLength} 字节）");

        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var tmp = path + ".tmp";
        try
        {
            File.WriteAllBytes(tmp, ComposeBlob(ProtectedData.Protect(pepper, Entropy, DataProtectionScope.CurrentUser)));

            var back = ReadFrom(tmp);
            if (!CryptographicOperations.FixedTimeEquals(back, pepper))
                throw new PepperUnavailableException("pepper 写入后回读不一致 —— 已中止（磁盘空间或权限异常？）");

            File.Move(tmp, path, overwrite: true);
            TryDelete(ErrorLogPath);   // 成功了就把上次的失败标记清掉
        }
        catch (PepperUnavailableException) { TryDelete(tmp); throw; }
        catch (Exception ex)
        {
            TryDelete(tmp);
            throw new PepperUnavailableException($"pepper 落盘失败：{ex.Message}", ex);
        }
    }

    /// <summary>读取并解密一个 pepper 文件，校验魔术字、版本与长度。</summary>
    public static byte[] ReadFrom(string path)
    {
        byte[] blob;
        try { blob = File.ReadAllBytes(path); }
        catch (Exception ex)
        {
            throw new PepperUnavailableException($"无法读取 pepper 文件：{path}\n{ex.Message}", ex);
        }

        var magic = Encoding.ASCII.GetBytes(FileMagic);
        if (blob.Length <= magic.Length || !blob.AsSpan(0, magic.Length).SequenceEqual(magic))
            throw new PepperUnavailableException(
                $"这不是 pepper 文件（缺少 {FileMagic} 标识）：{path}");

        var version = blob[magic.Length];
        if (version != FileFormatVersion)
            throw new PepperUnavailableException(
                $"pepper 文件版本不支持：{version}（本程序支持 {FileFormatVersion}）：{path}");

        byte[] plain;
        try
        {
            plain = ProtectedData.Unprotect(blob.AsSpan(magic.Length + 1).ToArray(),
                Entropy, DataProtectionScope.CurrentUser);
        }
        catch (Exception ex)
        {
            throw new PepperUnavailableException(
                $"pepper 文件无法解密：{path}\n" +
                "常见原因：换了机器 / 重装了系统 / 换用另一个 Windows 账户 / 文件损坏。\n" +
                "恢复：用 --pepper-import 导入备份的 pepper，" +
                $"或设置 {EnvVarDirect} / {EnvVarFile} 指向正确的 pepper。\n" +
                $"底层错误：{ex.Message}", ex);
        }

        if (plain.Length != PepperLength)
            throw new PepperUnavailableException(
                $"pepper 长度异常：{plain.Length} 字节（应为 {PepperLength}）：{path}");

        return plain;
    }

    private static byte[] ComposeBlob(byte[] ciphertext)
    {
        var magic = Encoding.ASCII.GetBytes(FileMagic);
        var blob = new byte[magic.Length + 1 + ciphertext.Length];
        magic.CopyTo(blob, 0);
        blob[magic.Length] = FileFormatVersion;
        ciphertext.CopyTo(blob, magic.Length + 1);
        return blob;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* 清理失败不影响主流程 */ }
    }

    /* ==================== 小工具 ==================== */

    /// <summary>把启动失败的原因写成一个可读文件（桌面端 Console 输出留不下）。</summary>
    public static void WriteErrorLog(string detail)
    {
        try
        {
            var dir = Path.GetDirectoryName(ErrorLogPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(ErrorLogPath,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] pepper 初始化失败，后端已拒绝启动。\n\n{detail}\n",
                Encoding.UTF8);
        }
        catch { /* 连日志都写不了时只能放弃 */ }
    }

    /// <summary>解析文本形式的 pepper：Base64，或 `hex:` 前缀的十六进制。</summary>
    private static byte[] ParseText(string text, string source)
    {
        var t = text.Trim();
        byte[] bytes;
        try
        {
            bytes = t.StartsWith("hex:", StringComparison.OrdinalIgnoreCase)
                ? Convert.FromHexString(t[4..])
                : Convert.FromBase64String(t);
        }
        catch (FormatException)
        {
            throw new PepperUnavailableException(
                $"{source} 不是合法的 Base64（若用十六进制请加 `hex:` 前缀）");
        }

        if (bytes.Length != PepperLength)
            throw new PepperUnavailableException(
                $"{source} 的长度是 {bytes.Length} 字节，应为 {PepperLength} 字节");

        return bytes;
    }

    /// <summary>指纹：SHA-256 前 8 字节十六进制。只表明"是不是同一个"，反推不出 pepper。</summary>
    public static string FingerprintOf(byte[] pepper) =>
        Convert.ToHexString(SHA256.HashData(pepper))[..16].ToLowerInvariant();
}
