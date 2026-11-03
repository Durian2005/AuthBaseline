using AuthServer.Services.Otp;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="OtpOptions"/> 的纯逻辑回归：默认值、环境变量覆盖、启动自检。
///
/// 为什么值得单测（这个类没有一行"业务逻辑"，但它能静默地把系统弄坏）：
///   · 链长 1 的链建出来初始 k=0，**一次都登不了**，而服务启动完全正常；
///   · 迭代次数 0 让 `v` 退化成裸 SHA 的迭代值，拖库场景下比现状弱两个数量级，
///     而登录照常成功、没有任何报错；
///   · 环境变量是探针**唯一**能在同一个二进制上切换档位的手段（安装目录的
///     appsettings.json 会被覆盖安装冲掉），解析错一个字符就会"以为在测 N=100，
///     其实跑的是 N=1000"—— 而续期路径要 0.95N 次登录才走到。
/// 这三条都属于"看起来跑起来了、其实测的不是那回事"，只能靠断言钉住。
/// </summary>
public class OtpOptionsTests
{
    /// <summary>默认值即"可用"：缺配置按可用启动（与 FaceIdOptions 同一原则）。</summary>
    [Fact(DisplayName = "默认值：N=1000 / PBKDF2 100k / 挑战 120s")]
    public void Defaults_AreUsable()
    {
        var opt = new OtpOptions();

        Assert.Equal(1000, opt.Length);
        Assert.Equal(100_000, opt.KdfIterations);
        Assert.Equal(120, opt.ChallengeTtlSeconds);
    }

    /// <summary>
    /// P8 删掉了 `Enabled` 总开关。这条用例把它钉成"不可再回来"：
    /// 开关的唯一意义是"关掉就回滚到口令路径"，而那条路径已经不存在 ——
    /// 若有人日后又想加回一个"临时关掉 OTP"的按钮，等于加回一个"一键让所有人登不进来"。
    /// </summary>
    [Fact(DisplayName = "P8：不存在 Otp:Enabled 开关")]
    public void NoMasterSwitch()
    {
        var names = typeof(OtpOptions).GetProperties().Select(p => p.Name).ToArray();
        Assert.DoesNotContain("Enabled", names);
    }

    /// <summary>
    /// 判定契约常量**不**在配置里：它们只在 <see cref="OtpVerifier"/> 有一份。
    /// 这条用例防的是"将来有人给 OtpOptions 加一个 RenewPercent 配置"——
    /// 一旦可配，服务端判定与客户端续期时机就会各说各话。
    /// </summary>
    [Fact(DisplayName = "判定契约常量只有一份：5% / 1% 定义在 OtpVerifier")]
    public void DecisionConstants_LiveOnlyInVerifier()
    {
        Assert.Equal(5, OtpVerifier.RenewThresholdPercent);
        Assert.Equal(1, OtpVerifier.AlertThresholdPercent);

        var names = typeof(OtpOptions).GetProperties().Select(p => p.Name).ToArray();
        Assert.DoesNotContain("RenewThresholdPercent", names);
        Assert.DoesNotContain("AlertThresholdPercent", names);
        Assert.DoesNotContain("RootLength", names);
    }

    /// <summary>
    /// 旧的 `AUTHBASELINE_OTP_ENABLED` 环境变量现在是**无操作**的：设成 false 也不该
    /// 影响任何参数。留着这条用例是因为探针脚本可能还在设置它 —— 必须确认它被安静地忽略，
    /// 而不是以某种方式把配置改坏。
    /// </summary>
    [Theory(DisplayName = "旧 OTP_ENABLED 环境变量不再起作用")]
    [InlineData("false")]
    [InlineData("0")]
    [InlineData("true")]
    public void Override_LegacyEnabled_IsIgnored(string raw) =>
        WithEnv("AUTHBASELINE_OTP_ENABLED", raw, opt =>
        {
            Assert.Equal(1000, opt.Length);
            Assert.DoesNotContain("Enabled", typeof(OtpOptions).GetProperties().Select(p => p.Name));
        });

    [Theory(DisplayName = "OTP_LENGTH 覆盖")]
    [InlineData("100", 100)]
    [InlineData(" 60 ", 60)]
    [InlineData("abc", 1000)]   // 非法值保持默认，不能把链长改成 0
    [InlineData("", 1000)]
    public void Override_Length(string raw, int expected) =>
        WithEnv("AUTHBASELINE_OTP_LENGTH", raw, opt => Assert.Equal(expected, opt.Length));

    [Theory(DisplayName = "OTP_KDF_ITERATIONS 覆盖")]
    [InlineData("1000", 1000)]
    [InlineData("0", 0)]        // 解析本身不拦（拦在 Validate），便于把错误配置报在启动时
    [InlineData("x", 100000)]
    public void Override_KdfIterations(string raw, int expected) =>
        WithEnv("AUTHBASELINE_OTP_KDF_ITERATIONS", raw, opt => Assert.Equal(expected, opt.KdfIterations));

    [Fact(DisplayName = "OTP_CHALLENGE_TTL_SECONDS 覆盖")]
    public void Override_ChallengeTtl() =>
        WithEnv("AUTHBASELINE_OTP_CHALLENGE_TTL_SECONDS", "30", opt => Assert.Equal(30, opt.ChallengeTtlSeconds));

    /// <summary>
    /// 非法参数必须**当场抛**：这两种配置都能"启动成功、登录全废"，
    /// 静默纠正会把问题推到用户投诉的那一刻，那时已无从归因。
    /// </summary>
    [Fact(DisplayName = "启动自检：链长 <2 / 迭代次数 ≤0 / 挑战 TTL ≤0 直接抛")]
    public void Validate_RejectsDangerousValues()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new OtpOptions { Length = 1 }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new OtpOptions { Length = 0 }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new OtpOptions { KdfIterations = 0 }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new OtpOptions { ChallengeTtlSeconds = 0 }.Validate());
        new OtpOptions().Validate(); // 默认值必须能过
    }

    /// <summary>启动摘要必须带上三个档位，否则"现在跑的是什么"只能靠猜。</summary>
    [Fact(DisplayName = "Describe 包含链长 / 迭代次数 / 两条阈值线")]
    public void Describe_MentionsKeyKnobs()
    {
        var text = new OtpOptions { Length = 100, KdfIterations = 5000 }.Describe();

        Assert.Contains("N=100", text);
        Assert.Contains("5000", text);
        Assert.Contains("5%", text);
        Assert.Contains("1%", text);
    }

    /// <summary>环境变量测试的公共壳：设值 → 覆盖 → 还原（不还原会污染同进程的其它用例）。</summary>
    private static void WithEnv(string name, string? value, Action<OtpOptions> act)
    {
        var previous = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, value);
        try
        {
            var opt = new OtpOptions();
            opt.ApplyEnvironmentOverrides();
            act(opt);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, previous);
        }
    }
}
