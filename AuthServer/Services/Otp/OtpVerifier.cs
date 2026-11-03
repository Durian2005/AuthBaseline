using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services.Otp;

/// <summary>
/// 一次链格提交的判定结论。
///
/// 分成四种而不是「通过/不通过」两种，是因为它们在**调用方的处置**上完全不同：
///   · <see cref="Mismatch"/> —— 就是「口令错」，计入失败次数、统一话术；
///   · <see cref="Exhausted"/> —— 链的配额用完了，凭据本身**是对的**，错的是链到了尽头。
///     必须回「需重建」而不是「口令错」，否则用户永远想不明白为什么自己记的口令突然不对了；
///   · <see cref="Malformed"/> —— 库里的链记录坏了（下标越界 / 基准不是 32 字节）。
///     这是**服务端数据问题**，不是用户问题，不能计入失败次数，也不能当成「口令错」。
/// 把三者混成一个 false，就等于把这三种完全不同的处置路径压平，之后必然有人按「口令错」处理。
/// </summary>
public enum OtpVerifyStatus
{
    /// <summary>接受本次提交，可以推进链。</summary>
    Valid,

    /// <summary>提交值不是链上这一格（重放 / 跨格 / 猜错），或格式根本不像一个格。</summary>
    Mismatch,

    /// <summary>配额已尽（<c>k = 0</c>），链需要重建。</summary>
    Exhausted,

    /// <summary>链记录本身不可用。</summary>
    Malformed
}

/// <summary>
/// 服务端视角的链状态（对应 <c>OtpChains</c> 里的 <c>v</c> / <c>k</c> / <c>length</c>）。
///
/// 只装「判定需要的那三个字段」，**刻意不装 userId / generation / createdAt** ——
/// 那些是存储与审计的事。判定函数只认这三个数，才可能在没有库、没有 Mongo、没有 DI 容器的机器上跑单测。
/// </summary>
/// <param name="V">当前验证基准，Base64（32 字节）。设计文档 §2.2 的 <c>v</c>，明文存储。</param>
/// <param name="K">期望下标，也就是「本次应当提交 <c>x_k</c>」里的那个 k。</param>
/// <param name="Length">链长 N。</param>
public readonly record struct OtpChainState(string V, int K, int Length);

/// <summary>判定结果。除了结论本身，还捎带两个「下一次该做什么」的信号。</summary>
/// <param name="Status">判定结论。</param>
/// <param name="NeedsRenewal">
/// 本次通过后应触发静默续期（<c>k ≤ N × 5%</c>）。**只在 <see cref="OtpVerifyStatus.Valid"/> 时为真** ——
/// 没通过就没有「本次登录」可以搭车，谈续期没有意义。
/// </param>
/// <param name="AtAlertLine">
/// 已跌破警戒线（<c>k ≤ N × 1%</c>）。给 §7.4 的可观测性用：对用户静默，但对系统不能静默。
/// </param>
public readonly record struct OtpVerifyResult(OtpVerifyStatus Status, bool NeedsRenewal, bool AtAlertLine)
{
    /// <summary>是否接受本次提交。语义上的唯一出口，调用方不该去比 <see cref="Status"/> 的字面值。</summary>
    public bool Valid => Status == OtpVerifyStatus.Valid;
}

/// <summary>
/// 哈希链的**纯计算层**：算链、判链、推进链。全部是静态纯函数。
///
/// ── 它刻意不做的事 ──────────────────────────────────────
/// 不碰库、不写审计、不签票、不读时钟、不读配置。这样一个类才能在 `dotnet test` 里
/// 毫秒级跑完，且结果不随机器状态漂移。
/// 存储（CAS 核销、续期替换）在 <c>OtpChainStore</c>；编排在 <c>OtpLoginService</c>；
/// 计次与话术在控制器。边界一旦糊掉，"这条链为什么拒了"就再也说不清是哪一层的锅。
///
/// ── 构造 ────────────────────────────────────────────────
///   <c>x₀ = PBKDF2-HMACSHA256(PW, salt: R, iter, 32 字节)</c>
///   <c>xᵢ = SHA256(xᵢ₋₁)</c>（对 32 字节原值做哈希，不做任何编码/拼接）
///   <c>v = x_N</c>，<c>k = N-1</c>；每次登录提交 <c>x_k</c>，服务端验 <c>H(x_k) == v</c>。
///
/// 为什么 <c>Encode</c> 必须是 PBKDF2 而不是裸哈希：设计文档 §2.4 —— <c>v</c> 是明文，
/// 拿到库的人可以离线猜口令，裸哈希时每次猜测只需 N 次 SHA-256（约 1ms），
/// 比现有的 BCrypt+pepper 弱两个数量级。这不是性能优化，是「拖库场景不能比现状更差」的底线。
///
/// ⚠️ 本类是**服务端与客户端的共同契约**：Rust 侧必须逐字复现 <see cref="Root"/> 与 <see cref="Iterate"/>
///    （同样的盐编码、同样的迭代次数、同样的字节序）。任何一处不同，表现都是「口令明明对却登不上」，
///    而这类故障极难归因 —— 所以参照实现放在这里，单测把它钉住。
///    编码口径也属于契约的一部分：口令按 **UTF-8** 编码，**不做 Unicode NFC/NFD 归一化**
///    （归一化一旦只在一侧发生，含组合字符的口令就会稳定地算错，且只对少数用户偶发）。
/// </summary>
public static class OtpVerifier
{
    /// <summary>链格的字节长度。SHA-256 输出 32 字节，PBKDF2 也取 32 字节，全链同宽。</summary>
    public const int RootLength = 32;

    // 链长与 PBKDF2 迭代次数**不在这里**：它们是部署参数，归 OtpOptions 管（唯一来源）。
    // 本类只保留"改了就两端不一致"的判定契约常量：格宽、算法名、5% / 1% 两条线。

    /// <summary>低于链长的这个百分比就续期。</summary>
    public const int RenewThresholdPercent = 5;

    /// <summary>低于链长的这个百分比就告警（只记日志，不改行为）。</summary>
    public const int AlertThresholdPercent = 1;

    /// <summary>链算法名，写进 <c>OtpChains.algorithm</c>。</summary>
    public const string ChainAlgorithm = "SHA256";

    /// <summary>KDF 名，写进 <c>OtpChains.kdf</c>。</summary>
    public const string KdfName = "PBKDF2-HMACSHA256";

    // ────────────────────────────────────────── 一、算链

    /// <summary>
    /// 算链根 <c>x₀ = PBKDF2(PW, R)</c>。
    ///
    /// 盐取 <c>R</c> 的 UTF-8 字节：<c>R</c> 是服务端下发的 Base32 文本，本身已经是一段随机串，
    /// 直接当盐用即可，不需要再套一层编码 —— 多套一层只会让客户端多一个必须复现的细节。
    /// </summary>
    /// <param name="password">用户口令（明文，只在内存里活到算完为止）。</param>
    /// <param name="r">公开链种子（Base32 文本）。</param>
    /// <param name="iterations">PBKDF2 迭代次数，必须与链上记录的一致。</param>
    public static byte[] Root(string password, string r, int iterations)
    {
        // 空口令在这里就该炸，而不是安静地算出一条"人人可算"的链。
        // 口令策略在别处管，但这一层不能假设别处一定管住了。
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("口令不能为空 —— 空口令会让链根可被任何人复现", nameof(password));
        if (string.IsNullOrEmpty(r))
            throw new ArgumentException("链种子 R 不能为空", nameof(r));
        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations), "PBKDF2 迭代次数必须为正");

        return Rfc2898DeriveBytes.Pbkdf2(
            password: password,
            salt: Encoding.UTF8.GetBytes(r),
            iterations: iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: RootLength);
    }

    /// <summary>
    /// 迭代哈希：<c>H^times(x)</c>。客户端用它从 <c>x₀</c> 走到 <c>x_k</c>，服务端用它算 <c>H(提交值)</c>（times = 1）。
    ///
    /// 为什么允许 <c>times = 0</c>：客户端在 k=0 时提交的正是 <c>x₀</c> 本身，
    /// 那时迭代次数就是 0。让它单独走一条分支，比在调用点写 <c>if (k == 0)</c> 少一个漏判点。
    /// </summary>
    /// <param name="x">起点，必须是 32 字节。</param>
    /// <param name="times">迭代次数，不得为负。</param>
    public static byte[] Iterate(ReadOnlySpan<byte> x, int times)
    {
        if (times < 0)
            throw new ArgumentOutOfRangeException(nameof(times), "迭代次数不能为负");
        if (x.Length != RootLength)
            throw new ArgumentException($"链格必须是 {RootLength} 字节，实际 {x.Length}", nameof(x));

        var current = x.ToArray();
        if (times == 0)
            return current;

        // 两块缓冲区来回换，避免 1000 次迭代里反复分配（链路在主登录路径上，不差这点但没必要浪费）。
        var buffer = new byte[RootLength];
        for (var i = 0; i < times; i++)
        {
            SHA256.HashData(current, buffer);
            (current, buffer) = (buffer, current);
        }

        return current;
    }

    /// <summary>建一条新链：只返回链头与初始下标，<c>x₀</c> 用完即弃、绝不外传。</summary>
    /// <param name="password">用户口令。</param>
    /// <param name="r">新链种子。</param>
    /// <param name="iterations">PBKDF2 迭代次数。</param>
    /// <param name="length">链长 N，至少 2（N=1 时一格都没有，初始 k 会变成 0，链一建出来就是死的）。</param>
    public static OtpChainState Create(string password, string r, int iterations, int length)
    {
        if (length < 2)
            throw new ArgumentOutOfRangeException(nameof(length), "链长至少为 2");

        var root = Root(password, r, iterations);
        return new OtpChainState(Encode(Iterate(root, length)), length - 1, length);
    }

    /// <summary>算出客户端本次该提交的格 <c>x_k</c>。这是**参照实现**，生产计算在 Rust 侧。</summary>
    public static string CodeAt(string password, string r, int iterations, int k)
    {
        if (k < 0)
            throw new ArgumentOutOfRangeException(nameof(k), "下标不能为负");

        return Encode(Iterate(Root(password, r, iterations), k));
    }

    // ────────────────────────────────────────── 二、判链

    /// <summary>
    /// 判定一次提交。
    ///
    /// ⚠️ 顺序是有讲究的，尤其是第 2 步与第 3 步**不能交换**：
    ///   1. 链记录畸形 ⇒ <see cref="OtpVerifyStatus.Malformed"/>（数据问题，不是用户问题）
    ///   2. <c>k ≤ 0</c> ⇒ <see cref="OtpVerifyStatus.Exhausted"/>（**先于**任何哈希比对）
    ///   3. <c>H(提交值) == v</c> ⇒ 通过；否则 <see cref="OtpVerifyStatus.Mismatch"/>
    ///
    /// 为什么 2 必须早于 3：<c>k = 0</c> 时 <c>v = x₁</c>，而 <c>H(x₀) = x₁</c> ——
    /// 用户的最后一个格刚好能"通过"这一格，链会静默多发一次。更糟的是 <c>x₀</c> 是口令派生根，
    /// 拿到它的人配合下发的 <c>R</c> 就可以离线猜口令。所以「配额」必须先于「哈希」被检查，
    /// 而不是指望哈希自己拒掉它 —— 哈希在这里恰恰**不会**拒。
    /// </summary>
    /// <param name="state">当前链状态。</param>
    /// <param name="submittedCode">客户端提交的链格（Base64）。</param>
    public static OtpVerifyResult Verify(in OtpChainState state, string? submittedCode)
    {
        // 1. 链记录本身是否可用：v 必须是可解码的 32 字节，k 必须落在 [0, N-1]。
        //    越界的 k 说明有人写过坏数据或迁移出错 —— 这种情况既不能放行也不能计入失败次数。
        var expected = TryDecode(state.V);
        if (expected is null || expected.Length != RootLength || state.K < 0 || state.K > state.Length - 1)
            return new OtpVerifyResult(OtpVerifyStatus.Malformed, false, false);

        // 2. 配额闸门。注意此时**不看提交值**：配额没了，提交什么都不该通过。
        if (state.K == 0)
            return new OtpVerifyResult(OtpVerifyStatus.Exhausted, false, false);

        // 3. 比对。格式不对的提交值一律按 Mismatch 处理，不额外区分 ——
        //    对攻击者而言「你的码格式错」和「你的码不对」都是"没通过"，区分只会多一个探测面；
        //    对开发者而言，真正的排错信息在审计的 response 袋里，不需要靠这个返回值。
        var submitted = TryDecode(submittedCode);
        if (submitted is null || submitted.Length != RootLength)
            return new OtpVerifyResult(OtpVerifyStatus.Mismatch, false, false);

        var actual = SHA256.HashData(submitted);

        // 恒定时间比较：这里比的是**秘密**（v 是明文存的验证基准），不是哈希输入的预处理。
        // 用 == 或 SequenceEqual 会按首个不同字节提前返回，把"前几位猜对了"泄露给能反复试的人。
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            return new OtpVerifyResult(OtpVerifyStatus.Mismatch, false, false);

        return new OtpVerifyResult(
            OtpVerifyStatus.Valid,
            NeedsRenewal(state.K, state.Length),
            AtAlertLine(state.K, state.Length));
    }

    /// <summary>
    /// 本次通过后是否该续期：<c>k ≤ N × 5%</c>。
    ///
    /// 用整数交叉相乘（<c>k × 100 ≤ N × 5</c>）而不是浮点百分比：链长与阈值都是整数，
    /// 浮点会在边界上给出「50.00000000000001 算不算」这种没有确定答案的问题，
    /// 而边界恰好是唯一需要被测的地方。
    /// </summary>
    public static bool NeedsRenewal(int k, int length) =>
        length > 1 && (long)k * 100 <= (long)length * RenewThresholdPercent;

    /// <summary>是否已跌破警戒线（<c>k ≤ N × 1%</c>）。只影响日志与告警，不改变判定。</summary>
    public static bool AtAlertLine(int k, int length) =>
        length > 1 && (long)k * 100 <= (long)length * AlertThresholdPercent;

    // ────────────────────────────────────────── 三、推进链

    /// <summary>
    /// 算出「本次通过之后」的链状态：<c>v ← 本次提交值</c>、<c>k ← k-1</c>。
    ///
    /// 返回新状态而不是就地改，是为了让存储层能把「读到的旧状态」与「要写的目标状态」
    /// 一起拿去做 CAS 条件（§7.5：两个客户端同交一格，只有一个能成功）——
    /// 判定与写法都得从同一个快照出发，否则 CAS 条件就无从写起。
    /// </summary>
    /// <param name="state">本次提交前的状态。</param>
    /// <param name="submittedCode">刚刚被判定通过的提交值。</param>
    public static OtpChainState Advance(in OtpChainState state, string submittedCode)
    {
        if (state.K <= 0)
            throw new InvalidOperationException("配额已尽的链不能推进 —— 应先重建");

        // 归一化：Base64 允许尾随 '=' 与空白变体，直接存原样会让同一条链出现两种字面值。
        var cell = TryDecode(submittedCode)
                   ?? throw new ArgumentException("提交值不是合法的 Base64", nameof(submittedCode));
        if (cell.Length != RootLength)
            throw new ArgumentException($"链格必须是 {RootLength} 字节，实际 {cell.Length}", nameof(submittedCode));

        return state with { V = Encode(cell), K = state.K - 1 };
    }

    // ────────────────────────────────────────── 四、编解码小工具

    /// <summary>把 32 字节链格编码成库里存的 Base64 文本。</summary>
    public static string Encode(ReadOnlySpan<byte> cell) => Convert.ToBase64String(cell);

    /// <summary>
    /// 链种子是否**形状合法**：32 个 Base32 字符（RFC 4648 字母表，不带填充）。
    ///
    /// 为什么形状也要校验：`R` 是链的盐，由客户端在续期时提交上来。
    /// 一个空串、一段短串或带非字母表字符的串不会让链"算不出来"——
    /// 它会让**所有**账号的链根落到一个可预测的盐上（比如空盐），
    /// 于是"同一个口令在不同账号上得到同一条链"，盐的意义直接归零。
    /// 这里只判形状不判随机性：随机性由客户端用 CSPRNG 保证，服务端无从验证。
    /// </summary>
    public static bool IsWellFormedSeed(string? r)
    {
        if (r is null || r.Length != 32) return false;

        foreach (var c in r)
        {
            var ok = (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7');
            if (!ok) return false;
        }

        return true;
    }

    /// <summary>
    /// 宽容的 Base64 解码：非法输入返回 <c>null</c> 而不是抛异常。
    /// 登录入口收到的是外部输入，一个乱码请求不该变成 500。
    /// </summary>
    public static byte[]? TryDecode(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return null;

        // 上界：Base64 每 4 字符解出 3 字节。多给 4 字节余量，避免把长度算式写死在两处。
        var buffer = new byte[(text.Length * 3 / 4) + 4];
        return Convert.TryFromBase64String(text, buffer, out var written)
            ? buffer[..written]
            : null;
    }
}
