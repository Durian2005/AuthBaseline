using AuthServer.Models;
using AuthServer.Services.FaceId;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// 假活体判定的回归。它测的**不是算法**（真算法要模型，属集成测试），
/// 而是三条会影响"线上行为"的约定：
///   1) "spoof" 分支必须真的低于默认阈值 —— 否则探针里"照片被拒"的断言会变成假绿；
///   2) "pad_down" 必须返回 null（**不是 0**）—— 0 会被记成一次攻击，null 才会被当作环境问题；
///   3) 默认分支必须明显高于阈值，不能让"真人能录进去"变成擦边过。
///
/// 第 2 条尤其重要：fail closed 的方向是"拒"，但它必须带着**正确的理由**拒。
/// 把"模型没加载"记成"有人在用照片攻击"，会污染审计里最有价值的那条线索。
/// </summary>
public class StubFaceIdLivenessTests
{
    private static FaceIdFrame Frame() => new() { Width = 640, Height = 480 };

    private static FaceIdBox Box() => new() { X = 200, Y = 100, W = 160, H = 200 };

    [Fact(DisplayName = "默认行为 ⇒ 高分（模拟真人）")]
    public void Default_IsHigh()
    {
        var liveness = new StubFaceIdLiveness(new FaceIdOptions { Engine = "stub" });

        Assert.True(liveness.Status.Ready);
        var score = liveness.Score(Frame(), Box());
        Assert.NotNull(score);
        Assert.True(score!.Value > new FaceIdOptions().PadMinLive,
            "默认分数必须明显高于默认阈值，否则真人会被擦边拒掉");
    }

    [Fact(DisplayName = "spoof ⇒ 低于默认阈值（照片被拒）")]
    public void Spoof_IsBelowThreshold()
    {
        var opt = new FaceIdOptions { Engine = "stub", StubBehavior = "spoof" };
        var liveness = new StubFaceIdLiveness(opt);

        Assert.True(liveness.Status.Ready);
        var score = liveness.Score(Frame(), Box());
        Assert.NotNull(score);
        Assert.True(score!.Value < opt.PadMinLive);
        Assert.True(score.Value < 0.2, "模拟攻击的分数要远离阈值，避免被当成'擦边未过'");
    }

    /// <summary>
    /// ★ 模型不可用时必须返回 **null**，而不是 0。
    /// 0 会被调用方当成"活体检测失败"⇒ 记一次计次的攻击；null 才会走"引擎不可用"分支。
    /// 这条断言防的是"错误归因"，它比错误本身更难排查。
    /// </summary>
    [Fact(DisplayName = "★ pad_down ⇒ Status 不可用且分数为 null（不是 0）")]
    public void PadDown_ReturnsNull_NotZero()
    {
        var liveness = new StubFaceIdLiveness(new FaceIdOptions
        {
            Engine = "stub",
            StubBehavior = "pad_down"
        });

        Assert.False(liveness.Status.Ready);
        Assert.False(string.IsNullOrWhiteSpace(liveness.Status.Message));
        Assert.Null(liveness.Score(Frame(), Box()));
    }

    /// <summary>阈值必须能在同一次构建上用环境变量切换（探针要分别验证挡与放）。</summary>
    [Fact(DisplayName = "环境变量可覆盖开关与阈值")]
    public void EnvOverrides_Work()
    {
        var opt = new FaceIdOptions();
        var before = opt.PadMinLive;

        Environment.SetEnvironmentVariable("AUTHBASELINE_FACEID_PAD_MIN_LIVE", "0.91");
        Environment.SetEnvironmentVariable("AUTHBASELINE_FACEID_PAD_ENABLED", "false");
        try
        {
            opt.ApplyEnvironmentOverrides();
            Assert.Equal(0.91, opt.PadMinLive, 6);
            Assert.False(opt.PadEnabled);
        }
        finally
        {
            Environment.SetEnvironmentVariable("AUTHBASELINE_FACEID_PAD_MIN_LIVE", null);
            Environment.SetEnvironmentVariable("AUTHBASELINE_FACEID_PAD_ENABLED", null);
        }

        // 还原到默认值，避免污染同一进程里的其它用例
        Assert.False(new FaceIdOptions().PadEnabled,
            "默认关闭：验收流程要手举照片，默认开着会把验收堵死；开启是 opt-in 硬化");
        Assert.True(before > 0, "默认阈值必须为正");
    }

    [Theory(DisplayName = "业务码 → 活体审计码：必须是计次的那一条")]
    [InlineData("FACEID_LIVENESS_FAILED")]
    public void BusinessCode_MapsToCountedReason(string code)
    {
        var reason = FaceIdCodes.ToAuditReason(code);
        Assert.Equal(AuditReason.FaceIdLivenessFailed, reason);
        Assert.True(FaceIdCodes.IsCounted(reason));
    }
}
