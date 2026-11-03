using System.Security.Cryptography;
using System.Text;
using AuthServer.Services.Otp;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="OtpVerifier"/> 的纯逻辑回归。
///
/// 覆盖的是设计文档 §10.2 里能在**离线**成立的几条关键断言：
///   1. 同一格提交两次，第二次必拒；
///   2. 相邻格（<c>x_{k±1}</c>）提交必拒；
///   3. 用尽后拒绝，且回 <see cref="OtpVerifyStatus.Exhausted"/> 而非「凭据错误」；
///   6. 恒定时间比较（实现用 <c>FixedTimeEquals</c>，这里用"只翻一位也必须拒"钉住语义）；
/// 外加续期阈值边界、格式容错、以及一条完整的「哈希链标准例题」逐步复现。
///
/// 为什么这些必须是单测而不是探针：本类不碰库、不读时钟、不读配置，
/// 所以它能在任何机器上跑，且边界值可以精确构造（真实链要在 N=1000 上跑 950 次登录才能摸到续期点，
/// 而这里改个 <c>length</c> 就到位了）。
///
/// ⚠️ 除两个专门测口令派生的用例外，其余全部用**自造的 32 字节种子**（不走 PBKDF2）——
/// 否则每次断言都要付 100k 次迭代的代价，而那条路径与链的推进语义无关。
/// </summary>
public class OtpVerifierTests
{
    /// <summary>造一条与口令无关的链根，供推进/重放/跨格类用例使用。</summary>
    private static byte[] Seed(byte tag = 0) =>
        SHA256.HashData(Encoding.UTF8.GetBytes($"otp-verifier-test-seed-{tag}"));

    /// <summary>用给定根、链长 N 拼出初始状态（<c>v = x_N</c>、<c>k = N-1</c>）。</summary>
    private static OtpChainState StateFromRoot(byte[] root, int length) =>
        new(OtpVerifier.Encode(OtpVerifier.Iterate(root, length)), length - 1, length);

    /// <summary>取链上第 k 格的 Base64（k = 0 即根本身）。</summary>
    private static string Cell(byte[] root, int k) => OtpVerifier.Encode(OtpVerifier.Iterate(root, k));

    // ────────────────────────────────────────── 一、标准例题逐步复现

    /// <summary>
    /// 哈希链的标准例题：N = 5、<c>v = x₅</c>、<c>k = 4</c>，依次提交 <c>x₄ x₃ x₂ x₁</c>。
    ///
    /// 六步断言，一步不少 —— 这条用例的价值就在于它把「一次性」与「有配额」放在同一条时间线上：
    /// 通过四次之后，第五次即使提交的是链上真有的 <c>x₀</c>，也必须拒绝。
    /// </summary>
    [Fact]
    public void SampleChain_FiveCells_AcceptsExactlyFourThenExhausts()
    {
        var root = Seed(1);
        var state = StateFromRoot(root, length: 5);
        var accepted = 0;

        // 初始：v = x₅，k = 4（可用格数为 N-1 = 4）。
        Assert.Equal(4, state.K);
        Assert.Equal(Cell(root, 5), state.V);

        // ① 提交 x₄ → 通过，推进到 k=3、v=x₄。
        Assert.True(OtpVerifier.Verify(state, Cell(root, 4)).Valid);
        state = OtpVerifier.Advance(state, Cell(root, 4));
        accepted++;
        Assert.Equal(3, state.K);
        Assert.Equal(Cell(root, 4), state.V);

        // ② 再提交一次 x₄ → 必拒（此时 v 已是 x₄，H(x₄)=x₅≠v）。
        Assert.Equal(OtpVerifyStatus.Mismatch, OtpVerifier.Verify(state, Cell(root, 4)).Status);

        // ③ x₃ x₂ x₁ 依次通过，k 走到 0。
        foreach (var k in new[] { 3, 2, 1 })
        {
            Assert.True(OtpVerifier.Verify(state, Cell(root, k)).Valid, $"x_{k} 应当通过");
            state = OtpVerifier.Advance(state, Cell(root, k));
            accepted++;
        }
        Assert.Equal(0, state.K);
        Assert.Equal(Cell(root, 1), state.V);

        // ④ 再交 x₀ → 拒。注意这里**不是** Mismatch：凭据是真的，链是没了。
        //    这正是「k ≤ 0 必须早于哈希比对」的那道闸门 —— 此刻 H(x₀) 恰好就等于 v。
        var last = OtpVerifier.Verify(state, Cell(root, 0));
        Assert.False(last.Valid);
        Assert.Equal(OtpVerifyStatus.Exhausted, last.Status);

        // ⑤ 全程恰好通过 N-1 = 4 次。
        Assert.Equal(4, accepted);
    }

    // ────────────────────────────────────────── 二、推进 / 重放 / 跨格

    /// <summary>整条链按顺序走完：每一格都通过，k 逐次减一，v 逐次变成上一格。</summary>
    [Fact]
    public void Advance_WalksWholeChainAndDecrementsK()
    {
        var root = Seed(2);
        var state = StateFromRoot(root, length: 8);

        for (var step = 1; step <= 7; step++)
        {
            var expectK = 8 - step;
            Assert.Equal(expectK, state.K);

            var code = Cell(root, expectK);
            Assert.True(OtpVerifier.Verify(state, code).Valid);

            var next = OtpVerifier.Advance(state, code);
            Assert.Equal(expectK - 1, next.K);
            Assert.Equal(code, next.V);
            state = next;
        }

        Assert.Equal(0, state.K);
        Assert.Equal(OtpVerifyStatus.Exhausted, OtpVerifier.Verify(state, Cell(root, 0)).Status);
    }

    /// <summary>同一格第二次提交必拒 —— 这是「一次性」的字面含义。</summary>
    [Fact]
    public void Replay_SameCellTwice_SecondRejected()
    {
        var root = Seed(3);
        var state = StateFromRoot(root, length: 10);
        var code = Cell(root, 9);

        Assert.True(OtpVerifier.Verify(state, code).Valid);
        var advanced = OtpVerifier.Advance(state, code);

        Assert.Equal(OtpVerifyStatus.Mismatch, OtpVerifier.Verify(advanced, code).Status);
    }

    /// <summary>相邻两格都拒：<c>x_{k+1}</c>（还没轮到）与 <c>x_{k-1}</c>（下一格，不是这一格）。</summary>
    [Fact]
    public void AdjacentCells_Rejected()
    {
        var root = Seed(4);
        var state = StateFromRoot(root, length: 10); // k = 9

        Assert.Equal(OtpVerifyStatus.Mismatch, OtpVerifier.Verify(state, Cell(root, 10)).Status); // 未来格
        Assert.Equal(OtpVerifyStatus.Mismatch, OtpVerifier.Verify(state, Cell(root, 8)).Status);  // 前一格
    }

    /// <summary>
    /// 「差一位也算通过」必须不成立：改动提交值的任意一个字节，结论只能是 Mismatch。
    /// 这条顺带钉住恒定时间比较的**语义**（实现用 <c>FixedTimeEquals</c>，由代码评审保证）。
    /// </summary>
    [Fact]
    public void Tampered_Cell_SingleBitFlipRejected()
    {
        var root = Seed(5);
        var state = StateFromRoot(root, length: 10);
        var cell = OtpVerifier.Iterate(root, 9);

        Assert.True(OtpVerifier.Verify(state, OtpVerifier.Encode(cell)).Valid);

        foreach (var index in new[] { 0, OtpVerifier.RootLength / 2, OtpVerifier.RootLength - 1 })
        {
            var tampered = (byte[])cell.Clone();
            tampered[index] ^= 0x01; // 只翻最低位，差异最小
            Assert.Equal(
                OtpVerifyStatus.Mismatch,
                OtpVerifier.Verify(state, OtpVerifier.Encode(tampered)).Status);
        }
    }

    /// <summary>推进是纯函数：原状态不得被改写（存储层要靠「旧快照 + 目标快照」写 CAS）。</summary>
    [Fact]
    public void Advance_DoesNotMutateInputState()
    {
        var root = Seed(6);
        var state = StateFromRoot(root, length: 10);
        var before = state;

        OtpVerifier.Advance(state, Cell(root, 9));

        Assert.Equal(before, state);
    }

    // ────────────────────────────────────────── 三、配额与续期阈值

    /// <summary>配额用尽：即使提交值能通过哈希比对，也必须回 Exhausted（§10.2 断言 3）。</summary>
    [Fact]
    public void ZeroQuota_ReportsExhausted_NotMismatch()
    {
        var root = Seed(7);
        // 直接构造 k=0 的状态：v = x₁ —— 正常走到尽头时就是这个形状。
        var state = new OtpChainState(Cell(root, 1), 0, 10);

        var result = OtpVerifier.Verify(state, Cell(root, 0));

        Assert.False(result.Valid);
        Assert.Equal(OtpVerifyStatus.Exhausted, result.Status);
        // 没通过就不该捎带续期信号，否则调用方可能在失败路径上写出新链。
        Assert.False(result.NeedsRenewal);
        Assert.False(result.AtAlertLine);
    }

    /// <summary>
    /// 续期阈值边界：<c>k ≤ N × 5%</c>。N=1000 → 50 触发、51 不触发；N=100 → 5；N=20 → 1。
    /// 用整数交叉相乘判定，所以边界必须是确定的、可断言的。
    /// </summary>
    [Theory]
    [InlineData(1000, 51, false)]
    [InlineData(1000, 50, true)]
    [InlineData(1000, 1, true)]
    [InlineData(100, 6, false)]
    [InlineData(100, 5, true)]
    [InlineData(20, 2, false)]
    [InlineData(20, 1, true)]
    public void Renewal_ThresholdBoundaryExact(int length, int k, bool expected) =>
        Assert.Equal(expected, OtpVerifier.NeedsRenewal(k, length));

    /// <summary>警戒线更严（1%），且与续期互相独立：触发续期不等于已告警。</summary>
    [Theory]
    [InlineData(1000, 50, true, false)] // 该续期，但还没到警戒线
    [InlineData(1000, 10, true, true)]
    [InlineData(1000, 11, true, false)]
    [InlineData(1000, 60, false, false)] // 两条线都没碰到
    public void AlertLine_IndependentOfRenewal(int length, int k, bool renewal, bool alert)
    {
        Assert.Equal(renewal, OtpVerifier.NeedsRenewal(k, length));
        Assert.Equal(alert, OtpVerifier.AtAlertLine(k, length));
    }

    /// <summary>
    /// 续期信号只在通过时出现：不通过的提交不该被读成「该续期了」。
    /// 这条防的是将来有人把 <c>NeedsRenewal</c> 当成独立判断到处用。
    /// </summary>
    [Fact]
    public void RenewalSignal_OnlyOnAcceptedSubmission()
    {
        var root = Seed(8);
        // N=40 → 续期线是 2，所以 k=2 恰在线上。
        var state = new OtpChainState(Cell(root, 3), 2, 40);

        var good = OtpVerifier.Verify(state, Cell(root, 2));
        Assert.True(good.Valid);
        Assert.True(good.NeedsRenewal);

        var bad = OtpVerifier.Verify(state, Cell(root, 5));
        Assert.False(bad.Valid);
        Assert.False(bad.NeedsRenewal);
    }

    // ────────────────────────────────────────── 四、畸形输入

    /// <summary>外部输入一律不抛异常：非法 Base64、空串、长度不符都按 Mismatch 处理。</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-base64!!")]
    [InlineData("AAAA")]           // 3 字节，长度不对
    [InlineData("   ")]            // 空白
    public void MalformedSubmission_TreatedAsMismatch(string? code)
    {
        var root = Seed(9);
        var state = StateFromRoot(root, length: 10);

        var result = OtpVerifier.Verify(state, code);

        Assert.False(result.Valid);
        Assert.Equal(OtpVerifyStatus.Mismatch, result.Status);
    }

    /// <summary>格式合法但内容不对的格（全零 32 字节）同样只是 Mismatch，不是异常。</summary>
    [Fact]
    public void WellFormedButWrongCell_IsMismatch()
    {
        var state = StateFromRoot(Seed(9), length: 10);
        var zeros = OtpVerifier.Encode(new byte[OtpVerifier.RootLength]);

        Assert.Equal(OtpVerifyStatus.Mismatch, OtpVerifier.Verify(state, zeros).Status);
    }

    /// <summary>链记录坏了要单独报 Malformed —— 这既不能放行，也不该计入用户的失败次数。</summary>
    [Fact]
    public void MalformedChainState_ReportsMalformed()
    {
        var good = OtpVerifier.Encode(Seed(10));

        // v 不是合法 Base64。
        Assert.Equal(OtpVerifyStatus.Malformed,
            OtpVerifier.Verify(new OtpChainState("***", 5, 10), good).Status);

        // v 长度不是 32 字节。
        Assert.Equal(OtpVerifyStatus.Malformed,
            OtpVerifier.Verify(new OtpChainState(Convert.ToBase64String(new byte[16]), 5, 10), good).Status);

        // k 越过链长上限（N=10 时合法区间是 [0, 9]）。
        Assert.Equal(OtpVerifyStatus.Malformed,
            OtpVerifier.Verify(new OtpChainState(good, 10, 10), good).Status);

        // 负下标。
        Assert.Equal(OtpVerifyStatus.Malformed,
            OtpVerifier.Verify(new OtpChainState(good, -1, 10), good).Status);
    }

    // ────────────────────────────────────────── 五、口令派生（PBKDF2 参照实现）

    /// <summary>
    /// <c>x₀</c> 的确定性：同口令同 R 必得同值；换 R、换迭代次数必得不同值；输出恒 32 字节。
    /// 这三条是客户端与服务端「算的是同一条链」的最低契约。
    /// </summary>
    [Fact]
    public void Root_DeterministicAndSensitiveToSeedAndIterations()
    {
        const string pw = "Abc12345";
        const string r1 = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        const string r2 = "MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK";

        var a = OtpVerifier.Root(pw, r1, 1000);
        var b = OtpVerifier.Root(pw, r1, 1000);
        var c = OtpVerifier.Root(pw, r2, 1000);
        var d = OtpVerifier.Root(pw, r1, 2000);

        Assert.Equal(OtpVerifier.RootLength, a.Length);
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.NotEqual(a, d);
    }

    /// <summary>空口令 / 空种子 / 非法迭代次数必须当场拒绝，而不是算出一条人人可复现的链。</summary>
    [Fact]
    public void Root_RejectsIllegalArguments()
    {
        Assert.Throws<ArgumentException>(() => OtpVerifier.Root("", "R", 1000));
        Assert.Throws<ArgumentException>(() => OtpVerifier.Root("pw", "", 1000));
        Assert.Throws<ArgumentOutOfRangeException>(() => OtpVerifier.Root("pw", "R", 0));
    }

    /// <summary>
    /// 非 ASCII 口令：按 **UTF-8** 编码参与派生，结果确定；**不做 Unicode 归一化**。
    ///
    /// 这一条必须写死在契约里：只要客户端（Rust）与服务端对归一化的处理不一致，
    /// 同一个「看起来一样」的口令就会算出不同的链根，表现是「口令明明相同却登不上」，
    /// 而且只在含组合字符的口令上偶发 —— 这类故障几乎无法靠用户反馈定位。
    /// </summary>
    [Fact]
    public void Root_NonAsciiPassword_IsUtf8AndNotNormalized()
    {
        Assert.Equal(
            OtpVerifier.Root("密码Abc123", "R", 1000),
            OtpVerifier.Root("密码Abc123", "R", 1000));

        // 预组合的 é(U+00E9) 与组合序列 e+U+0301 是两个不同的 UTF-8 串。
        // 若哪天有人在派生前偷偷加了 Normalize(NFC)，这条断言会立刻变红。
        Assert.NotEqual(
            OtpVerifier.Root("é", "R", 1000),
            OtpVerifier.Root("e\u0301", "R", 1000));
    }

    /// <summary>
    /// 链种子形状校验：32 位 Base32（RFC 4648 字母表）。
    ///
    /// 为什么形状值得单测：`R` 在续期时由**客户端**提交。空串或短串不会让链算不出来 ——
    /// 它会让链根落到一个可预测的盐上，"同一口令在不同账号上得到同一条链"，盐的意义归零。
    /// 这类错误不会报错、不会崩，只会让方案在拖库场景下悄悄变弱，所以必须钉死。
    /// </summary>
    [Theory(DisplayName = "链种子形状：32 位 Base32 才算合法")]
    [InlineData("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", true)]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", true)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX", false)]         // 31 位
    [InlineData("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPX", false)]       // 33 位
    [InlineData("jbsWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", false)]        // 小写不在字母表内
    [InlineData("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX0", false)]        // '0' 不在 Base32 里
    [InlineData("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX1", false)]        // '1' 不在 Base32 里
    [InlineData("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX=", false)]        // 带填充不算（客户端不该带）
    public void IsWellFormedSeed_ShapeOnly(string? seed, bool expected) =>
        Assert.Equal(expected, OtpVerifier.IsWellFormedSeed(seed));

    /// <summary>链长小于 2 建不出能用的链（N=1 时初始 k=0，一建出来就是死的），应当直接拒绝。</summary>
    [Fact]
    public void Create_RejectsLengthBelowTwo()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => OtpVerifier.Create("pw", "R", 1000, 1));
    }

    /// <summary>
    /// 端到端（仍在纯计算层）：口令 → 建链 → 连续登录 N-1 次全部通过、第 N 次 Exhausted。
    /// 这是「参照实现」与「判定实现」互相对得上的唯一证据 ——
    /// Rust 侧只要和 <see cref="OtpVerifier"/> 一致，就能和这里的结论一致。
    /// </summary>
    [Fact]
    public void EndToEnd_PasswordChain_AllowsExactlyNMinusOneLogins()
    {
        const string pw = "Abc12345";
        const string r = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        const int iterations = 1000; // 单测特意调小；生产默认 100k 由配置给出
        const int length = 6;

        var state = OtpVerifier.Create(pw, r, iterations, length);
        Assert.Equal(length - 1, state.K);

        var accepted = 0;
        while (true)
        {
            var code = OtpVerifier.CodeAt(pw, r, iterations, state.K);
            var result = OtpVerifier.Verify(state, code);
            if (!result.Valid)
            {
                Assert.Equal(OtpVerifyStatus.Exhausted, result.Status);
                break;
            }

            state = OtpVerifier.Advance(state, code);
            accepted++;
        }

        Assert.Equal(length - 1, accepted);
        Assert.Equal(0, state.K);
    }
}
