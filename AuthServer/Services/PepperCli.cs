using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services;

/// <summary>
/// pepper 的导出 / 导入子命令。
///
/// ── 为什么必须提供它 ──────────────────────────────────────────
/// pepper 用 DPAPI 保护 ⇒ 绑定「本机 + 当前用户配置文件」。
/// 这挡得住别人拷走文件，但也意味着**换机器 / 重装系统时它同样读不出来**，
/// 而那正好是"全部口令都验不了"的场景。所以必须有一条把 pepper 搬到别处的通道。
///
/// ── 为什么导出文件要再用口令封装一层 ────────────────────────────
/// 导出物是要离开本机的：可能进网盘、U 盘、密码管理器。
/// 直接扔 32 字节明文等于把最关键的秘密暴露在链路上；
/// 而 DPAPI 密文换了机器又解不开。于是用「口令 → PBKDF2 → AES-GCM」重新封装：
///   · 换到任何机器上都能用口令打开；
///   · 落地形态是密文，放哪都只是"多一份要保护的密文"；
///   · 口令本身不进命令行参数（会留在 shell 历史里），只从环境变量或交互式输入读。
///
/// ── 用法 ──────────────────────────────────────────────────
///   authserver.exe --pepper-export &lt;输出文件&gt;
///   authserver.exe --pepper-import &lt;封装文件&gt;
///
/// 非交互场景（脚本 / CI）把口令放进环境变量 AUTHBASELINE_PEPPER_PASSPHRASE。
/// </summary>
internal static class PepperCli
{
    private const string PassphraseEnvVar = "AUTHBASELINE_PEPPER_PASSPHRASE";

    /// <summary>识别本模块负责的子命令。</summary>
    public static bool IsPepperCommand(string[] args) =>
        args.Length > 0 && args[0].StartsWith("--pepper-", StringComparison.Ordinal);

    public static int Run(string[] args)
    {
        try
        {
            return args[0] switch
            {
                "--pepper-export" => Export(args),
                "--pepper-import" => Import(args),
                _ => Usage($"未知子命令：{args[0]}")
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Pepper] 失败：{ex.Message}");
            return 1;
        }
    }

    private static int Export(string[] args)
    {
        if (args.Length < 2) return Usage("--pepper-export 需要指定输出文件路径");

        var outPath = args[1];
        Console.WriteLine($"[Pepper] 本机 pepper 路径：{PepperProvider.ResolvePath()}");
        var pepper = PepperProvider.ReadLocalPepper();
        Console.WriteLine($"[Pepper] 已读取本机 pepper（指纹 {PepperProvider.FingerprintOf(pepper)}）");

        var passphrase = ReadPassphrase("设置一个用于封装 pepper 的口令", confirm: true);
        if (passphrase is null) return 2;

        var blob = PepperEnvelope.Seal(pepper, passphrase);
        File.WriteAllBytes(outPath, blob);

        Console.WriteLine();
        Console.WriteLine($"[Pepper] 已导出：{outPath}（{blob.Length} 字节）");
        Console.WriteLine("[Pepper] 封装方式：PBKDF2-HMAC-SHA256(600000 次) 派生密钥 + AES-GCM");
        Console.WriteLine();
        Console.WriteLine("[Pepper] 注意：请把这份文件存到「另一台设备」（网盘 / U 盘 / 密码管理器均可）。");
        Console.WriteLine("[Pepper]   它与数据库同等重要：丢了就意味着换机后所有账号都登不进来。");
        Console.WriteLine("[Pepper]   同时也别忘了导出时设的那个口令 —— 文件和口令要分开存放。");
        return 0;
    }

    private static int Import(string[] args)
    {
        if (args.Length < 2) return Usage("--pepper-import 需要指定封装文件路径");

        var inPath = args[1];
        if (!File.Exists(inPath))
        {
            Console.Error.WriteLine($"[Pepper] 文件不存在：{inPath}");
            return 1;
        }

        var blob = File.ReadAllBytes(inPath);
        var passphrase = ReadPassphrase("输入导出时设置的口令", confirm: false);
        if (passphrase is null) return 2;

        byte[] pepper;
        try
        {
            pepper = PepperEnvelope.Open(blob, passphrase);
        }
        catch (CryptographicException)
        {
            // GCM 的认证标签校验失败 ⇒ 要么口令错，要么文件被改过。两者对用户而言是同一句提示。
            Console.Error.WriteLine("[Pepper] 打开失败：口令错误，或文件已损坏 / 被修改。");
            return 1;
        }

        Console.WriteLine($"[Pepper] 已解出 pepper（指纹 {PepperProvider.FingerprintOf(pepper)}）");

        // 覆盖前先备份：倘若导入的其实是"另一个 pepper"（导错文件了），
        // 本机原有的那份就成了唯一退路 —— 直接覆盖会让局面不可挽回。
        var target = PepperProvider.ResolvePath();
        if (File.Exists(target))
        {
            var backup = $"{target}.bak-{DateTime.Now:yyyyMMdd_HHmmss}";
            File.Copy(target, backup, overwrite: true);
            Console.WriteLine($"[Pepper] 原 pepper 已备份到：{backup}");
        }

        PepperProvider.WriteLocalPepper(pepper);
        Console.WriteLine($"[Pepper] 已写入：{target}");
        Console.WriteLine("[Pepper] 现在可以启动后端了；启动日志会打印指纹，可据此确认与导出端一致。");
        return 0;
    }

    private static int Usage(string? error)
    {
        if (!string.IsNullOrEmpty(error)) Console.Error.WriteLine($"[Pepper] {error}");
        Console.Error.WriteLine();
        Console.Error.WriteLine("用法：");
        Console.Error.WriteLine("  authserver.exe --pepper-export <输出文件>   导出本机 pepper（口令封装）");
        Console.Error.WriteLine("  authserver.exe --pepper-import <封装文件>   导入 pepper 并写回本机");
        Console.Error.WriteLine();
        Console.Error.WriteLine($"非交互场景可从环境变量读取口令：{PassphraseEnvVar}");
        return 2;
    }

    /// <summary>
    /// 读取口令：优先环境变量，否则交互式隐藏输入。
    /// 刻意**不支持命令行参数** —— 那会把口令留在 shell 历史与进程列表里。
    /// </summary>
    private static string? ReadPassphrase(string prompt, bool confirm)
    {
        var fromEnv = Environment.GetEnvironmentVariable(PassphraseEnvVar);
        if (!string.IsNullOrWhiteSpace(fromEnv))
        {
            if (fromEnv.Length < 8)
            {
                Console.Error.WriteLine($"[Pepper] 环境变量 {PassphraseEnvVar} 太短，至少 8 个字符。");
                return null;
            }
            Console.WriteLine($"[Pepper] 口令来自环境变量 {PassphraseEnvVar}（长度 {fromEnv.Length}）");
            return fromEnv;
        }

        if (Console.IsInputRedirected)
        {
            Console.Error.WriteLine(
                $"[Pepper] 当前无法交互输入。请设置环境变量 {PassphraseEnvVar} 后重试。");
            return null;
        }

        var first = ReadHidden($"{prompt}：");
        if (string.IsNullOrEmpty(first))
        {
            Console.Error.WriteLine("[Pepper] 口令为空，已取消。");
            return null;
        }
        if (first.Length < 8)
        {
            Console.Error.WriteLine("[Pepper] 口令太短，至少 8 个字符。");
            return null;
        }

        if (confirm)
        {
            var again = ReadHidden("再输入一次确认：");
            if (!string.Equals(first, again, StringComparison.Ordinal))
            {
                Console.Error.WriteLine("[Pepper] 两次输入不一致，已取消。");
                return null;
            }
        }

        return first;
    }

    /// <summary>隐藏回显地读一行（避免口令被旁观者看到）。</summary>
    private static string ReadHidden(string prompt)
    {
        Console.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0) sb.Length--;
                continue;
            }
            if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
        }
        return sb.ToString();
    }
}

/// <summary>
/// 导出文件的封装格式：口令 → PBKDF2 → AES-GCM。
///
/// 布局（大端）：
///   magic "ABPEPPERX"(9) | version(1) | iterations(4) | salt(16) | nonce(12) | tag(16) | ciphertext(32)
///
/// 把 iterations 写进文件而不是写死在代码里：日后提高迭代次数时，
/// 旧文件仍能按它自己记录的参数打开 —— 否则"提升安全性"会变成"旧备份全部作废"。
/// </summary>
internal static class PepperEnvelope
{
    private const string Magic = "ABPEPPERX";
    private const byte Version = 1;
    private const int Iterations = 600_000;   // OWASP 对 PBKDF2-HMAC-SHA256 的建议量级
    private const int SaltLength = 16;
    private const int NonceLength = 12;       // AES-GCM 标准 nonce 长度
    private const int TagLength = 16;
    private const int KeyLength = 32;

    public static byte[] Seal(byte[] pepper, string passphrase)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var key = DeriveKey(passphrase, salt, Iterations);

        var ciphertext = new byte[pepper.Length];
        var tag = new byte[TagLength];
        using (var gcm = new AesGcm(key, TagLength))
            gcm.Encrypt(nonce, pepper, ciphertext, tag);

        var magicBytes = Encoding.ASCII.GetBytes(Magic);
        var blob = new byte[magicBytes.Length + 1 + 4 + SaltLength + NonceLength + TagLength + ciphertext.Length];
        var offset = 0;

        magicBytes.CopyTo(blob, offset); offset += magicBytes.Length;
        blob[offset++] = Version;
        BinaryPrimitives.WriteInt32BigEndian(blob.AsSpan(offset, 4), Iterations); offset += 4;
        salt.CopyTo(blob, offset); offset += SaltLength;
        nonce.CopyTo(blob, offset); offset += NonceLength;
        tag.CopyTo(blob, offset); offset += TagLength;
        ciphertext.CopyTo(blob, offset);

        return blob;
    }

    public static byte[] Open(byte[] blob, string passphrase)
    {
        var magicBytes = Encoding.ASCII.GetBytes(Magic);
        var headerLength = magicBytes.Length + 1 + 4;
        if (blob.Length < headerLength + SaltLength + NonceLength + TagLength)
            throw new CryptographicException("文件太短，不是有效的 pepper 封装文件");
        if (!blob.AsSpan(0, magicBytes.Length).SequenceEqual(magicBytes))
            throw new CryptographicException("文件缺少 pepper 封装标识");

        var offset = magicBytes.Length;
        var version = blob[offset++];
        if (version != Version)
            throw new CryptographicException($"封装格式版本不支持：{version}（本程序支持 {Version}）");

        var iterations = BinaryPrimitives.ReadInt32BigEndian(blob.AsSpan(offset, 4)); offset += 4;
        var salt = blob.AsSpan(offset, SaltLength).ToArray(); offset += SaltLength;
        var nonce = blob.AsSpan(offset, NonceLength).ToArray(); offset += NonceLength;
        var tag = blob.AsSpan(offset, TagLength).ToArray(); offset += TagLength;
        var ciphertext = blob.AsSpan(offset).ToArray();

        var key = DeriveKey(passphrase, salt, iterations);
        var plain = new byte[ciphertext.Length];

        // 口令错误 / 文件被改 ⇒ GCM 标签校验失败 ⇒ 抛 CryptographicException
        using var gcm = new AesGcm(key, TagLength);
        gcm.Decrypt(nonce, ciphertext, tag, plain);

        if (plain.Length != PepperProvider.PepperLength)
            throw new CryptographicException(
                $"解出的 pepper 长度异常：{plain.Length} 字节（应为 {PepperProvider.PepperLength}）");

        return plain;
    }

    private static byte[] DeriveKey(string passphrase, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, KeyLength);
}
