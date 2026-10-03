using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace AuthServer.Services;

/// <summary>
/// 传输层配置（appsettings.json 的 `Transport` 节）。
///
/// 只有两个开关，但这两个开关决定了"传输加密"是真的还是装的 —— 见 §3.3。
/// </summary>
public sealed class TransportOptions
{
    /// <summary>
    /// true（**默认**）：证书不可用 ⇒ 后端拒绝启动。
    /// 绝不静默降级 —— 否则"我们做了传输加密"这句话可能在演示当天不成立而没人发现。
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>
    /// CA 公钥写到哪个根存储：CurrentUser（默认，开发态，可能弹框）/ LocalMachine（安装期，需管理员）/ None（测试）。
    /// 测试脚本走"固定信任锚"（server.crt）而不依赖系统信任，所以 None 是合法且常用的取值。
    /// </summary>
    public string TrustStore { get; set; } = "CurrentUser";

    /// <summary>
    /// 环境变量覆盖，便于测试与 CI 不改配置文件就能切换形态。
    /// 环境变量优先于 appsettings —— 与 PepperProvider 的取值优先级保持一致。
    /// </summary>
    public void ApplyEnvironmentOverrides()
    {
        var req = Environment.GetEnvironmentVariable("AUTHBASELINE_REQUIRE_HTTPS");
        if (!string.IsNullOrWhiteSpace(req))
        {
            if (bool.TryParse(req, out var parsed)) RequireHttps = parsed;
            else if (req == "0") RequireHttps = false;
            else if (req == "1") RequireHttps = true;
        }

        var trust = Environment.GetEnvironmentVariable(CertificateManager.EnvVarTrust);
        if (!string.IsNullOrWhiteSpace(trust)) TrustStore = trust!;
    }
}

/// <summary>
/// 下发给前端的传输状态摘要（`GET /api/auth/transport`）。
///
/// 之所以做成一个独立对象而不是让控制器去摸 CertificateManager：
/// 降级运行（RequireHttps=false 且证书不可用）时控制器仍然必须能回答
/// "现在是明文"，而那种情况下根本不存在 CertificateManager 实例。
/// 用一个恒存在的摘要对象，就不会出现"降级时接口 500"这种更糟的故障。
/// </summary>
public sealed record TransportInfo(
    bool HttpsEnabled,
    bool RequireHttps,
    string? Subject,
    DateTimeOffset? NotAfter,
    string? Thumbprint,
    string? TrustStore);

/// <summary>
/// 证书不可用 —— 语义与 PepperUnavailableException 一致：**必须拒绝启动**，而不是"降级继续跑"。
///
/// 为什么这里也不能静默降级：本项目的页面是由后端从 wwwroot **同源提供**的
/// （见 lib.rs 的 window.navigate），所以一旦证书出问题而我们悄悄退回 HTTP，
/// "我们做了传输加密"这句话在演示当天就是不成立的，而且没有任何人会察觉。
/// 宁可启动失败并把原因写进文件，也不要一个"看起来正常"的明文链路。
/// </summary>
public sealed class CertificateUnavailableException : Exception
{
    public CertificateUnavailableException(string message, Exception? inner = null)
        : base(message, inner) { }
}

/// <summary>
/// 传输层证书（本机私有 CA + leaf）的签发、复用、轮换、信任写入与校验。
///
/// ── 为什么是"私有 CA + leaf"而不是直接自签一张证书 ───────────────
/// 自签单证书意味着"每次轮换都要用户重新确认一次信任"。而拆成 CA + leaf 之后：
/// 用户只信任一次 CA（5 年），leaf 到期时用 CA 无感重签（1 年），不需要再次弹框。
/// 顺带还能讲清一条证书链，这在验收时是加分项。
///
/// ── 方案来源与两处修正（阶段 0 实测，见 TRANSPORT-STORAGE-SECURITY-DESIGN.md §6.1）
///   1) **leaf 私钥必须持久化**。用 RSA.Create() 得到的临时密钥做**服务端**认证时，
///      Schannel 直接抛 `The platform does not support ephemeral keys`，而客户端只看到
///      `IOException: Received an unexpected EOF` —— 症状指向客户端、根因在服务端，极易误判成"方案不行"。
///      ⇒ 本类统一走"导入 CurrentUser\My + PersistKeySet"，禁止 EphemeralKeySet。
///   2) **CA 的存放位置改了**。原稿写 `%LOCALAPPDATA%\AuthBaseline\certs\`，
///      但那个目录**就是 NSIS 的安装目录**（按 productName 决定），会被卸载器与
///      "清理安装残留"这类例行操作整目录扫掉。所以统一挪到同级不同名的
///      `%LOCALAPPDATA%\AuthBaselineData\certs\`（与 pepper 同一策略，见 PepperProvider）。
///
/// ── 对外必须说清的边界 ──────────────────────────────────────
/// 本方案防的是"链路上的窃听者"。它**不**防"本机上的攻击者"：
/// 能读 CurrentUser 存储或能改本机根存储的进程，本就有管理员级能力。
/// 所以正确口径是「把最廉价的窃听路径堵死」，而不是「链路绝对安全」。
/// </summary>
public sealed class CertificateManager : IDisposable
{
    /* ==================== 常量与路径 ==================== */

    /// <summary>证书目录覆盖（测试用，语义同 AUTHBASELINE_PEPPER_FILE：指向哪里就用哪里）。</summary>
    public const string EnvVarCertDir = "AUTHBASELINE_CERT_DIR";

    /// <summary>信任存储覆盖：CurrentUser / LocalMachine / None。</summary>
    public const string EnvVarTrust = "AUTHBASELINE_CERT_TRUST";

    /// <summary>数据目录名。刻意与 productName（AuthBaseline，即安装目录名）不同 —— 见类注释第 2 点。</summary>
    private const string DataDirName = "AuthBaselineData";

    private const string CaSubject = "CN=AuthBaseline Local CA";
    private const string LeafSubject = "CN=127.0.0.1";

    /// <summary>
    /// PFX 的传输口令。它**不是**本方案的保护手段 —— 外层还有 DPAPI(CurrentUser)。
    /// 之所以仍然带一个：PFX 导入 API 需要一个口令，且万一某天这份 PFX 被拷到别处，
    /// 这一层口令至少能让它不至于"双击就能导入"。
    /// </summary>
    private const string PfxPassword = "AuthBaseline/cert/v1";

    /// <summary>DPAPI 附加熵（跟着代码走，不是秘密，作用是让别的程序难以"恰好"解开）。</summary>
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("AuthBaseline/cert/v1");

    private static readonly int CaValidYears = 5;
    private static readonly TimeSpan LeafValidFor = TimeSpan.FromDays(365);

    /// <summary>leaf 剩余寿命低于此值就轮换（提前量，避免演示当天刚好过期）。</summary>
    private static readonly TimeSpan LeafRotateBefore = TimeSpan.FromDays(30);

    /// <summary>CA 剩余寿命低于此值就重建整套（CA 临期意味着 leaf 也快无法续签）。</summary>
    private static readonly TimeSpan CaRotateBefore = TimeSpan.FromDays(180);

    /// <summary>证书目录。默认 %LOCALAPPDATA%\AuthBaselineData\certs\。</summary>
    public static string DefaultDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        DataDirName, "certs");

    public static string ResolveDir()
    {
        var explicitDir = Environment.GetEnvironmentVariable(EnvVarCertDir);
        return string.IsNullOrWhiteSpace(explicitDir) ? DefaultDir : explicitDir!;
    }

    /// <summary>
    /// 启动失败的可读原因落点。理由同 PepperProvider.ErrorLogPath：
    /// 桌面端 sidecar 的 Console 输出会被转发给无控制台的 GUI，留不下来；
    /// 不写文件的话"起不来"就没有任何可查线索。
    /// </summary>
    public static string ErrorLogPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        DataDirName, "cert-error.log");

    /* ==================== 对外属性 ==================== */

    /// <summary>leaf 证书（**带持久化私钥**），交给 Kestrel 做 HTTPS 端点。</summary>
    public X509Certificate2 LeafCertificate { get; }

    /// <summary>CA 证书（带私钥），用于后续无感重签 leaf。</summary>
    public X509Certificate2 CaCertificate { get; }

    public string CertDir { get; }

    /// <summary>导出的公钥证书路径 —— 测试脚本拿它当**固定信任锚**（`--cacert`）。</summary>
    public string PublicCertPath { get; }

    /// <summary>本次信任写到了哪个存储（CurrentUser / LocalMachine / 空=未写）。</summary>
    public string TrustStoreName { get; }

    /// <summary>本次启动做了什么（新建 CA / 轮换 leaf / 复用 / 写信任），用于启动日志。</summary>
    public IReadOnlyList<string> Notes { get; }

    private CertificateManager(X509Certificate2 ca, X509Certificate2 leaf, string certDir,
        string publicCertPath, string trustStoreName, List<string> notes)
    {
        CaCertificate = ca;
        LeafCertificate = leaf;
        CertDir = certDir;
        PublicCertPath = publicCertPath;
        TrustStoreName = trustStoreName;
        Notes = notes;
    }

    /* ==================== 主入口 ==================== */

    /// <summary>
    /// 准备证书：有则复用、无则签发、快到期则轮换，并把 CA 写入信任存储（可选）。
    ///
    /// 失败一律抛 <see cref="CertificateUnavailableException"/>，由 Program 决定是
    /// "拒绝启动"（RequireHttps=true）还是"显式退回 HTTP"（RequireHttps=false）。
    /// </summary>
    /// <param name="trustStore">CurrentUser / LocalMachine / None。</param>
    public static CertificateManager Provision(string trustStore)
    {
        try
        {
            return ProvisionCore(trustStore);
        }
        catch (CertificateUnavailableException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // 把"证书相关的任何意外"收敛成一个可被 Program 识别的类型。
            // 否则一个 IOException（例如证书目录不可写）会让进程直接崩溃退出 ——
            // 既拿不到"已拒绝启动"的明确语义，也留不下可读的 cert-error.log。
            throw new CertificateUnavailableException(
                $"证书初始化过程中出现未预期的错误：{ex.Message}", ex);
        }
    }

    private static CertificateManager ProvisionCore(string trustStore)
    {
        var notes = new List<string>();
        var dir = ResolveDir();
        Directory.CreateDirectory(dir);

        var metaPath = Path.Combine(dir, "certs.json");
        var caPfxPath = Path.Combine(dir, "ca.pfx.dpapi");
        var publicCertPath = Path.Combine(dir, "server.crt");

        var meta = ReadMetadata(metaPath);

        /* ---- ① CA：复用或新建 ---- */
        X509Certificate2 ca = null!;
        var reusedCa = TryLoadFromStore(meta?.CaThumbprint, CaSubject);
        if (reusedCa != null && IsUsable(reusedCa, CaRotateBefore))
        {
            ca = reusedCa;
            notes.Add($"复用 CA（{Short(reusedCa.Thumbprint)}，{reusedCa.NotAfter:yyyy-MM-dd} 到期）");
        }
        else
        {
            if (reusedCa != null)
            {
                notes.Add($"CA 即将到期（{reusedCa.NotAfter:yyyy-MM-dd}），重建");
                RemoveFromStore(reusedCa.Thumbprint);
                reusedCa.Dispose();
            }
            ca = CreateAndImportCa(caPfxPath);
            notes.Add($"新建 CA（{Short(ca.Thumbprint)}，{ca.NotAfter:yyyy-MM-dd} 到期）");
        }

        /* ---- ② leaf：复用或（用 CA 重）签发 ---- */
        X509Certificate2 leaf = null!;
        var reusedLeaf = TryLoadFromStore(meta?.LeafThumbprint, LeafSubject);
        if (reusedLeaf != null && IsUsable(reusedLeaf, LeafRotateBefore) && IssuedBy(reusedLeaf, ca))
        {
            leaf = reusedLeaf;
            notes.Add($"复用 leaf（{Short(reusedLeaf.Thumbprint)}，{reusedLeaf.NotAfter:yyyy-MM-dd} 到期）");
        }
        else
        {
            if (reusedLeaf != null)
            {
                notes.Add($"轮换 leaf（旧 {Short(reusedLeaf.Thumbprint)} → 到期 {reusedLeaf.NotAfter:yyyy-MM-dd}）");
                RemoveFromStore(reusedLeaf.Thumbprint);
                reusedLeaf.Dispose();
            }
            leaf = CreateAndImportLeaf(ca);
            notes.Add($"签发 leaf（{Short(leaf.Thumbprint)}，{leaf.NotAfter:yyyy-MM-dd} 到期）");
        }

        /* ---- ③ 信任：把 CA 公钥写入根存储，并回读自检 ---- */
        var written = string.Empty;
        if (!string.Equals(trustStore, "None", StringComparison.OrdinalIgnoreCase))
        {
            WriteTrust(ca, trustStore, notes);
            written = trustStore;
        }
        else
        {
            notes.Add("信任存储写入已显式关闭（AUTHBASELINE_CERT_TRUST=None）");
        }

        /* ---- ④ 导出公钥（脚本的信任锚，可公开） ---- */
        File.WriteAllText(publicCertPath,
            new string(PemEncoding.Write("CERTIFICATE", ca.Export(X509ContentType.Cert))),
            new UTF8Encoding(false));
        notes.Add($"已导出公钥 {Path.GetFileName(publicCertPath)}");

        /* ---- ⑤ 记账 ---- */
        WriteMetadata(metaPath, ca, leaf);

        return new CertificateManager(ca, leaf, dir, publicCertPath, written, notes);
    }

    /// <summary>给状态栏/接口用的摘要（**不含任何私钥信息**）。</summary>
    public object Describe() => new
    {
        subject = LeafCertificate.Subject,
        issuer = LeafCertificate.Issuer,
        notAfter = LeafCertificate.NotAfter.ToUniversalTime().ToString("o"),
        thumbprint = LeafCertificate.Thumbprint,
        caThumbprint = CaCertificate.Thumbprint,
        trustStore = string.IsNullOrEmpty(TrustStoreName) ? "none" : TrustStoreName
    };

    /* ==================== 证书生成 ==================== */

    /// <summary>
    /// 生成 CA：自签、CA=true、KeyUsage 含 KeyCertSign。
    ///
    /// 用 `CreateSelfSigned` 得到的实例**带临时私钥**，不能直接用于服务端认证；
    /// 但 CA 只做"签名"（签发 leaf），临时密钥对签名是够用的。
    /// 不过为了口径统一、也为了 My 存储里能留一份可复用的权威副本，
    /// 这里仍然走 ImportToMy（真实成本只有首次签发的几十毫秒）。
    /// </summary>
    private static X509Certificate2 CreateAndImportCa(string backupPfxPath)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(CaSubject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0,
            critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
            critical: true));

        // SKI + AKI 成对出现是证书链能被验证的前提：
        // OpenSSL 校验时要求"子证书的 AKI 等于签发者证书的 SKI"，
        // 缺了 AKI 会直接报 `Missing Authority Key Identifier` —— 而 Schannel 只是笼统地拒绝，
        // 反而看不出原因。CA 自签时 AKI 指向自己的 SKI。
        var caSki = new X509SubjectKeyIdentifierExtension(req.PublicKey, false);
        req.CertificateExtensions.Add(caSki);
        req.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(caSki));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(CaValidYears);

        using var selfSigned = req.CreateSelfSigned(notBefore, notAfter);
        var imported = ImportToMy(selfSigned);

        // 备份一份 DPAPI 保护的 PFX：万一 My 存储被清空（换账户 / 清理工具），
        // 还能拿回同一把 CA 私钥续签 leaf，而不是被迫重建整套信任。
        try
        {
            var pfx = selfSigned.Export(X509ContentType.Pfx, PfxPassword);
            File.WriteAllBytes(backupPfxPath,
                ProtectedData.Protect(pfx, Entropy, DataProtectionScope.CurrentUser));
        }
        catch (Exception ex)
        {
            // 备份失败不致命（My 存储里那份才是权威副本），但要让它在日志里留痕。
            Console.WriteLine($"[Cert] 警告：CA 私钥备份失败（不影响本次启动）：{ex.Message}");
        }

        return imported;
    }

    /// <summary>
    /// 用 CA 签发 leaf。
    ///
    /// ⚠️ SAN 必须同时含 `IP:127.0.0.1` 与 `DNS:localhost`：
    /// Chromium（WebView2）对 IP 直连**只认 SAN 里的 IP**，不看 CN。
    /// 漏了这一条，界面会以"白窗口"的形式失败 —— 没有任何错误信息可看。
    /// </summary>
    private static X509Certificate2 CreateAndImportLeaf(X509Certificate2 ca)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(LeafSubject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0,
            critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },   // serverAuth
            critical: false));

        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);   // 127.0.0.1 —— 桌面端实际用的地址
        san.AddDnsName("localhost");            // 开发时 dotnet run 的地址
        req.CertificateExtensions.Add(san.Build());

        // ⚠️ .NET 的 CertificateRequest.Create 不会自动补 AKI，必须显式加。
        // 少了它，OpenSSL 侧报 `Missing Authority Key Identifier`，链验证直接失败 ——
        // 即"证书签出来了，但没人能验过"，属于最难排查的一类问题。
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, true));


        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        // 序列号必须为正整数
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.Add(LeafValidFor);

        using var signed = req.Create(ca, notBefore, notAfter, serial);
        using var withKey = signed.CopyWithPrivateKey(key);   // 此刻仍是**临时**密钥
        return ImportToMy(withKey);                            // ← 必须过这一道，见类注释第 1 点
    }

    /* ==================== CurrentUser\My 存储 ==================== */

    /// <summary>
    /// 把"带私钥的证书"落到 `CurrentUser\My`，并回读一份返回。
    ///
    /// `PersistKeySet` 是关键：它把私钥写进用户密钥容器，使其成为**持久化密钥**。
    /// 不带它（或带 EphemeralKeySet）时，RSA 密钥只活在当前进程内 ——
    /// 客户端场景这是安全加固，**服务端场景直接不可用**（Schannel 拒绝临时密钥）。
    ///
    /// `UserKeySet` 让它落在当前用户下，从而**不需要管理员**，也就不会弹 UAC。
    /// </summary>
    private static X509Certificate2 ImportToMy(X509Certificate2 certWithKey)
    {
        var pfx = certWithKey.Export(X509ContentType.Pfx, PfxPassword);

        using var persisted = new X509Certificate2(pfx, PfxPassword,
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);

        using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(persisted);   // 证书与私钥一并落地
        }

        // 重新取一份"存储里的那个"，避免把中间态实例传出去
        return FindInStore(StoreName.My, persisted.Thumbprint)
            ?? throw new CertificateUnavailableException(
                $"证书导入 CurrentUser\\My 后回读失败：{persisted.Thumbprint}");
    }

    /// <summary>
    /// 按指纹（优先）或主题在指定存储里找一张**带私钥**的证书。
    /// 找不到返回 null，绝不用"随便找一张同名的顶上"糊弄过去。
    /// </summary>
    private static X509Certificate2? TryLoadFromStore(string? thumbprint, string subject)
    {
        if (!string.IsNullOrEmpty(thumbprint))
        {
            var byThumb = FindInStore(StoreName.My, thumbprint!);
            if (byThumb != null) return byThumb;
        }

        // 指纹缺失（首次 / 元数据损坏）时退化为按主题找，但要过滤掉过期证书
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var now = DateTime.Now;
            foreach (var c in store.Certificates)
            {
                if (c.Subject == subject && c.NotAfter > now && c.HasPrivateKey)
                    return c;
            }
        }
        catch { /* 存储不可读时按"没有"处理，由上层重新签发 */ }

        return null;
    }

    private static X509Certificate2? FindInStore(StoreName name, string thumbprint)
    {
        try
        {
            using var store = new X509Store(name, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
            // 注意 Find 返回的是集合里的**引用**，store Dispose 后证书对象仍可用；
            // 但为了不依赖这个细节，这里返回一个新实例。
            return found.Count > 0 ? new X509Certificate2(found[0]) : null;
        }
        catch { return null; }
    }

    private static void RemoveFromStore(string thumbprint)
    {
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
            foreach (var c in found) store.Remove(c);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Cert] 清理旧证书失败（不影响启动）：{ex.Message}");
        }
    }

    /// <summary>证书是否仍可安全使用：带私钥、未过期、且剩余寿命大于提前量。</summary>
    private static bool IsUsable(X509Certificate2 cert, TimeSpan rotateBefore)
    {
        if (!cert.HasPrivateKey) return false;
        try { return cert.NotAfter.ToUniversalTime() - DateTime.UtcNow > rotateBefore; }
        catch { return false; }
    }

    /// <summary>leaf 是否确由当前 CA 签发（防止元数据被换、或 CA 重建后误用旧 leaf）。</summary>
    private static bool IssuedBy(X509Certificate2 leaf, X509Certificate2 ca)
    {
        try
        {
            var caThumb = ca.Thumbprint;
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.ExtraStore.Add(ca);
            if (!chain.Build(leaf)) return false;
            // 链上必须出现当前 CA 的指纹
            foreach (var el in chain.ChainElements)
                if (string.Equals(el.Certificate.Thumbprint, caThumb, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }
        catch { return false; }
    }

    /* ==================== 信任写入（唯一会弹框的一步） ==================== */

    /// <summary>
    /// 把 CA 公钥写入根存储，**并回读自检**。
    ///
    /// 为什么必须自检：页面由后端同源提供（lib.rs 导航到后端地址），
    /// 一旦 WebView2 不信任证书，**整个界面连壳都渲染不出来** ——
    /// 用户看到的是白窗口，没有任何可读错误。所以"写进去了"不够，
    /// 必须回读确认"按指纹确实在、且没有被 Disallowed 存储显式否定"。
    ///
    /// ⚠️ 阶段 0 实测：写 `CurrentUser\Root` 会弹一次 Windows「安全警告」，
    /// 未点击时**无限期阻塞**。所以这一步绝不能出现在"用户已经看到界面之后"的热路径上；
    /// 产品路径是 NSIS 安装期写 `LocalMachine\Root`（安装器本就有管理员权限）。
    /// 开发/热替换场景允许退化为 CurrentUser（会弹一次，属预期）。
    /// </summary>
    private static void WriteTrust(X509Certificate2 ca, string storeName, List<string> notes)
    {
        var location = string.Equals(storeName, "LocalMachine", StringComparison.OrdinalIgnoreCase)
            ? StoreLocation.LocalMachine
            : StoreLocation.CurrentUser;

        var caCert = new X509Certificate2(ca.Export(X509ContentType.Cert));   // 只写公钥，私钥绝不外流

        using (var root = new X509Store(StoreName.Root, location))
        {
            root.Open(OpenFlags.ReadWrite);
            var existing = root.Certificates.Find(X509FindType.FindByThumbprint, caCert.Thumbprint, validOnly: false);
            if (existing.Count > 0)
            {
                notes.Add($"信任已存在（{location}\\Root，{Short(caCert.Thumbprint)}）");
            }
            else
            {
                root.Add(caCert);   // ← 可能弹出「安全警告」对话框
                notes.Add($"已写入信任（{location}\\Root，{Short(caCert.Thumbprint)}）");
            }
        }

        /* ---- 回读自检：不通过即拒绝启动 ---- */
        var ok = false;
        string failure;
        try
        {
            using var root = new X509Store(StoreName.Root, location);
            root.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            ok = root.Certificates.Find(X509FindType.FindByThumbprint, caCert.Thumbprint, validOnly: false).Count > 0;
            failure = $"根存储中查不到该 CA（{location}\\Root）";
        }
        catch (Exception ex)
        {
            failure = $"读取根存储失败：{ex.Message}";
        }

        if (!ok)
            throw new CertificateUnavailableException(
                "CA 写入信任存储后回读校验失败 —— 已拒绝启动。\n" +
                $"原因：{failure}\n" +
                "常见原因：写入被安全策略拦截 / 安全警告对话框未被确认 / 该证书被显式标记为不信任。\n" +
                "如果刚才弹出了 Windows「安全警告」，请选择『是』后重试。");

        // Windows 允许显式"不信任"某张根证书 —— 那条记录在 Disallowed 存储里，
        // 且优先级高于 Root。只查 Root 会漏掉这种"写进去了但被一票否决"的情形。
        try
        {
            using var disallowed = new X509Store("Disallowed", location);
            disallowed.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            if (disallowed.Certificates.Find(X509FindType.FindByThumbprint, caCert.Thumbprint, validOnly: false).Count > 0)
                throw new CertificateUnavailableException(
                    $"该 CA（{Short(caCert.Thumbprint)}）被系统显式标记为「不信任」（Disallowed 存储）。\n" +
                    "请先在「管理用户证书」中移除该不信任项，或清空当前用户证书存储后重试。");
            notes.Add("Disallowed 存储无干扰项");
        }
        catch (CertificateUnavailableException) { throw; }
        catch { /* 读不到 Disallowed 存储不算失败，只是少了一重检查 */ }
    }

    /* ==================== 元数据 ==================== */

    private sealed class CertMetadata
    {
        public string? CaThumbprint { get; set; }
        public string? LeafThumbprint { get; set; }
        public DateTimeOffset? CaNotAfter { get; set; }
        public DateTimeOffset? LeafNotAfter { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
    }

    private static CertMetadata? ReadMetadata(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<CertMetadata>(File.ReadAllText(path));
        }
        catch { return null; }   // 元数据坏了不是灾难：退化为"按主题找"，找不到就重签
    }

    private static void WriteMetadata(string path, X509Certificate2 ca, X509Certificate2 leaf)
    {
        try
        {
            var meta = new CertMetadata
            {
                CaThumbprint = ca.Thumbprint,
                LeafThumbprint = leaf.Thumbprint,
                CaNotAfter = ca.NotAfter.ToUniversalTime(),
                LeafNotAfter = leaf.NotAfter.ToUniversalTime(),
                UpdatedAt = DateTimeOffset.UtcNow
            };
            File.WriteAllText(path, JsonSerializer.Serialize(meta,
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Cert] 元数据写入失败（不影响本次运行）：{ex.Message}");
        }
    }

    /* ==================== 工具 ==================== */

    public static void WriteErrorLog(string detail)
    {
        try
        {
            var dir = Path.GetDirectoryName(ErrorLogPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(ErrorLogPath,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 证书初始化失败，后端已拒绝启动。\n\n{detail}\n",
                Encoding.UTF8);
        }
        catch { /* 连日志都写不了时只能放弃 */ }
    }

    /// <summary>成功后清掉上一次的失败标记，避免下次排障时被旧日志误导。</summary>
    public static void ClearErrorLog()
    {
        try { if (File.Exists(ErrorLogPath)) File.Delete(ErrorLogPath); } catch { }
    }

    private static string Short(string thumbprint) =>
        thumbprint.Length >= 8 ? thumbprint[..8].ToLowerInvariant() : thumbprint.ToLowerInvariant();

    public void Dispose()
    {
        LeafCertificate.Dispose();
        CaCertificate.Dispose();
    }
}
