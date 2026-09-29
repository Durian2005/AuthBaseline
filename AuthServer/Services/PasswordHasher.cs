using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services;

/// <summary>
/// 一次口令验证的结果。
///
/// 为什么要把「密码对不对」和「要不要顺手升级」放在同一个返回值里：
/// 这两件事的判断依据是同一个 —— 库里存的是哪种格式的哈希。
/// 如果拆成"先 Verify 一次、再自己判前缀"两次调用，调用方就得知道格式细节，
/// 于是"格式前缀"这个知识会散落到四个调用点，日后改动容易漏。
/// 由本层一次算清，调用方只需读结果。
/// </summary>
/// <param name="Valid">口令是否正确。</param>
/// <param name="NeedsUpgrade">
/// 验证通过，且库里存的是**旧格式**（无 pepper）—— 提示调用方可以就地重写为新格式。
/// 仅在验证成功时为 true：验证失败时不该改写任何东西。
/// </param>
public readonly record struct PasswordVerifyResult(bool Valid, bool NeedsUpgrade);

/// <summary>
/// 口令的哈希与验证。**全系统唯一的出口** —— 任何地方都不应再直接调用 BCrypt。
///
/// ── 存储格式 ──────────────────────────────────────────────
///   新格式：`v2$` + bcrypt( Base64( HMAC-SHA256(pepper, password) ) )
///   旧格式：bcrypt( password )                        ← 改造前的形态，仍是合法输入
///
/// 前缀 `v2$` 是**必要的**：两种格式的 bcrypt 串在字面上完全一样（都以 `$2a$11$` 开头），
/// 不加标记就只能"两种都试一遍"—— 那等于 pepper 一旦读不到就自动降级，
/// 而"pepper 缺失即失效"正是本机制存在的全部意义。见 Verify 里的红线注释。
///
/// ── 为什么用 HMAC 预处理，而不是把 pepper 拼在口令后面 ─────────────
/// 因为 **bcrypt 只取输入的前 72 字节**，超出的部分被静默丢掉。
/// 若写成 `bcrypt(password + pepper)`，那么：
///   · 口令一长，pepper 就被挤到 72 字节之外 ⇒ pepper **根本没参与计算**，
///     加了个寂寞，而且不会有任何报错 —— 这是最危险的失败模式：看起来做了防护，实际没有；
///   · 拼接还会带来歧义（`"ab"+"c"` 与 `"a"+"bc"` 无法区分）。
/// 改用 HMAC-SHA256 后，输出固定 32 字节（Base64 后 44 字符），
/// 稳定、无歧义、且永远在 72 字节以内，上述问题都不存在。
///
/// ── 关于 salt 与 cost ──────────────────────────────────────
/// 随机盐仍由 bcrypt 自己生成并内嵌在哈希串里（`$2a$11$` + 22 字符 salt + 31 字符 digest），
/// pepper **不替代**盐：盐防"相同口令产生相同哈希"（彩虹表 / 批量比对），
/// pepper 防"库被整体拿走"。两者防的不是同一件事，所以两个都要有。
/// </summary>
public static class PasswordHasher
{
    /// <summary>pepper 格式的版本标记。也就是"这个哈希算的时候用了 pepper"的唯一凭据。</summary>
    public const string PepperPrefix = "v2$";

    /// <summary>用于展示的格式名（写进审计，便于审计员理解"升级成了什么"）。</summary>
    public const string PepperFormatName = "bcrypt+pepper(v2)";

    /// <summary>旧格式名（同样给审计用）。</summary>
    public const string LegacyFormatName = "bcrypt(v0)";

    /// <summary>算一个新格式哈希。pepper 必须由 PepperProvider 提供，绝不允许为空。</summary>
    public static string Hash(string password, byte[] pepper)
    {
        if (pepper is null || pepper.Length == 0)
            throw new ArgumentException("pepper 不能为空 —— 缺少 pepper 时不允许写入口令哈希", nameof(pepper));

        return PepperPrefix + BCrypt.Net.BCrypt.HashPassword(PreHash(password, pepper));
    }

    /// <summary>
    /// 验证口令，自动识别新旧两种格式。
    ///
    /// ⚠️ 红线：识别到 `v2$` 前缀后**只走新格式这一条路，失败即失败，绝不回退去试旧格式**。
    ///   回退看起来"更兼容"，实际是把 pepper 变成摆设：
    ///   攻击者只要拿到数据库、再让 pepper 读不出来（删文件 / 换机 / 本机跑一个同版本程序），
    ///   验证就会自动退回无 pepper 的旧算法，防护归零且全程静默。
    ///   宁可让人登不进来（错误信息明确、可恢复），也不能让防护悄悄消失。
    /// </summary>
    public static PasswordVerifyResult Verify(string password, string? stored, byte[]? pepper)
    {
        // 库里出现空哈希属于脏数据（早期数据 / 人工改库）。当作验证失败，
        // 而不是把异常抛到上层变成 500 —— 登录接口不该因一条坏数据而不可用。
        if (string.IsNullOrEmpty(stored) || password is null)
            return new PasswordVerifyResult(false, false);

        if (stored.StartsWith(PepperPrefix, StringComparison.Ordinal))
        {
            // 走到这里说明这条哈希是带 pepper 算的。若此时手上没有 pepper，
            // 唯一正确的结论是"验不了"，而不是"换个算法试试"。
            if (pepper is null || pepper.Length == 0)
                return new PasswordVerifyResult(false, false);

            var body = stored[PepperPrefix.Length..];
            return new PasswordVerifyResult(SafeBcryptVerify(PreHash(password, pepper), body), false);
        }

        // 旧格式：没有前缀，就是改造前直接存的裸 bcrypt。
        // 验证通过 ⇒ 顺手标记为"可升级"，由调用方决定何时重写（当前只有登录入口这么做）。
        var legacyOk = SafeBcryptVerify(password, stored);
        return new PasswordVerifyResult(legacyOk, legacyOk);
    }

    /// <summary>这条哈希是不是 pepper 格式。用于迁移判断与自检输出。</summary>
    public static bool IsPepperFormat(string? stored) =>
        !string.IsNullOrEmpty(stored) && stored.StartsWith(PepperPrefix, StringComparison.Ordinal);

    /// <summary>
    /// bcrypt 验证的容错包装。
    /// 库里若存在被人工改坏的哈希串，BCrypt 会抛 SaltParseException ——
    /// 那属于"这条数据不可用"，语义上就是验证不通过，不该升级成 HTTP 500。
    /// </summary>
    private static bool SafeBcryptVerify(string input, string hash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(input, hash);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// pepper 预处理：HMAC-SHA256(pepper, password) → Base64。
    ///
    /// 用固定时间比较不适用于此处（这里是在算哈希输入，不是比对秘密），
    /// 关键是输出长度恒定（44 字符）且远小于 bcrypt 的 72 字节上限。
    /// </summary>
    private static string PreHash(string password, byte[] pepper)
    {
        using var hmac = new HMACSHA256(pepper);
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));
    }
}
