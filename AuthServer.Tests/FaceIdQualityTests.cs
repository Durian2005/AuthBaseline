using AuthServer.Services.FaceId;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="FaceIdQuality"/> 的纯逻辑回归 —— 录入闸门的每条判据与每个边界。
///
/// 为什么这组断言值得单独存在：
///   · 闸门的产物是**存进库里的生物特征**。放行一张侧脸/糊脸，错误会被永久固化
///     （以后每次登录都要跟这张烂模板比）；拒绝一张正常脸，用户只是重试一次。
///     代价如此不对称，边界就必须由断言钉住，而不是靠"看起来差不多"。
///   · "多脸"这条分支在有真摄像头的机器上极难复现（要恰好有第二个人凑进来），
///     但它涉及**把别人的脸录进这个账号**。没有单测，它等于从未被验证过。
///   · 清晰度可能"测不出来"（假引擎 / ROI 越界）。"测不出来"必须**跳过**这一项，
///     不能当成不合格 —— 否则 stub 环境永远录不进去，而"录不进去"会被误读成
///     "功能坏了"。
/// </summary>
public class FaceIdQualityTests
{
    // 基准样本：640x480 的画面，脸宽 224（0.35），鼻子居中，无模糊信息。
    private const double FrameW = 640, FrameH = 480, FaceW = 224, FaceH = 216;

    /// <summary>构造一张"标准正脸"的关键点：眼A/眼B 对称，鼻尖在中点。</summary>
    private static double[] FrontalPoints(double noseShiftRatio = 0)
    {
        // 双眼间距 80，鼻尖偏移 = ratio * 80
        var cx = 320.0;
        var eyeDist = 80.0;
        var noseX = cx + noseShiftRatio * eyeDist;
        return new double[]
        {
            cx - eyeDist / 2, 200,   // 眼 A
            cx + eyeDist / 2, 200,   // 眼 B
            noseX, 240,              // 鼻尖
            cx + 20, 300,            // 嘴角 A
            cx - 20, 300             // 嘴角 B
        };
    }

    private static FaceIdQualitySample Sample(
        int faces = 1, double width = FaceW, double[]? points = null, double? sharpness = 300,
        double frameWidth = FrameW) =>
        new(faces, frameWidth, FrameH, width, FaceH, points ?? FrontalPoints(), sharpness);

    // 显式阈值（与 FaceIdOptions 默认值一致），避免单测跟着配置漂移。
    private const double MinWidth = 0.12, MaxYaw = 0.35, MaxRoll = 0.30, MinSharp = 60;

    private static FaceIdQualityResult Eval(FaceIdQualitySample sample) =>
        FaceIdQuality.Evaluate(sample, MinWidth, MaxYaw, MaxRoll, MinSharp);

    // ─────────────────────────────── 一、基础分支

    [Fact(DisplayName = "标准正脸 ⇒ Pass")]
    public void FrontalFace_Passes()
    {
        var r = Eval(Sample());
        Assert.Equal(FaceIdQualityVerdict.Pass, r.Verdict);
        Assert.True(r.Passed);
        Assert.Contains("faces=1", r.Diagnostic);
    }

    [Fact(DisplayName = "没有人脸 ⇒ NoFace（且不因缺少关键点而报侧脸）")]
    public void NoFace_ReportsNoFace()
    {
        var r = Eval(Sample(faces: 0, width: 0, points: Array.Empty<double>(), sharpness: null));
        Assert.Equal(FaceIdQualityVerdict.NoFace, r.Verdict);
    }

    /// <summary>
    /// ★ 多脸优先级：哪怕主脸极小（本来也会被 TooSmall 拒），也必须报 MultipleFaces。
    /// 这是为了让用户知道"画面里还有人"，而不是反复靠近镜头。
    /// </summary>
    [Fact(DisplayName = "★ 多脸优先于尺寸 ⇒ MultipleFaces")]
    public void MultipleFaces_WinsOverTooSmall()
    {
        var r = Eval(Sample(faces: 2, width: 20));
        Assert.Equal(FaceIdQualityVerdict.MultipleFaces, r.Verdict);
    }

    /// <summary>
    /// 多脸闸门可以**显式关掉**：用照片做识别测试时（明星各年龄段 / 双胞胎 / 特殊人群
    /// 都找不到真人来配合），举着手机的人自己很容易入镜，此时取面积最大那张即可。
    ///
    /// 这条断言钉两件事：
    ///   ① 关掉之后多脸不再是否决项，其它判据照常生效（这里给的是标准正脸 ⇒ Pass）；
    ///   ② **默认值必须是 true** —— 关掉等于放弃"存进去的是谁"，不能是默认行为。
    /// </summary>
    [Fact(DisplayName = "多脸闸门可显式关闭（照片测试），默认仍为拒绝")]
    public void MultipleFaces_CanBeAllowedForPhotoTesting()
    {
        var relaxed = FaceIdQuality.Evaluate(Sample(faces: 2), MinWidth, MaxYaw, MaxRoll, MinSharp,
            rejectMultipleFaces: false);
        Assert.Equal(FaceIdQualityVerdict.Pass, relaxed.Verdict);

        // 关掉多脸不等于关掉其它判据：太小/侧脸照样拒。
        var tooSmall = FaceIdQuality.Evaluate(Sample(faces: 2, width: 20), MinWidth, MaxYaw, MaxRoll,
            MinSharp, rejectMultipleFaces: false);
        Assert.Equal(FaceIdQualityVerdict.TooSmall, tooSmall.Verdict);

        Assert.True(new FaceIdOptions().RejectMultipleFaces, "默认必须拒绝多脸（照片测试是 opt-in）");
    }

    // ─────────────────────────────── 二、尺寸边界

    /// <summary>
    /// 边界取"含"：脸宽恰好等于下限时放行。
    /// 与判定式写 &lt; 还是 &lt;= 直接相关 —— 差一个像素不该改变结论，
    /// 但"压线即拒"会让阈值在配置里写的数字与实际生效值差一档。
    /// </summary>
    [Theory(DisplayName = "尺寸边界：恰好下限放行，差一丝拒绝")]
    [InlineData(0.12, true)]     // 恰好 0.12 ⇒ Pass
    [InlineData(0.1201, true)]
    [InlineData(0.1199, false)]  // 明确低于 ⇒ TooSmall
    [InlineData(0.05, false)]
    public void WidthBoundary(double ratio, bool expectPass)
    {
        var r = Eval(Sample(width: FrameW * ratio));
        Assert.Equal(expectPass ? FaceIdQualityVerdict.Pass : FaceIdQualityVerdict.TooSmall, r.Verdict);
    }

    /// <summary>帧宽缺失（调用方传错）也必须 fail closed，而不是除零后放行。</summary>
    [Fact(DisplayName = "帧宽为 0 ⇒ TooSmall（fail closed）")]
    public void ZeroFrameWidth_FailsClosed()
    {
        Assert.Equal(FaceIdQualityVerdict.TooSmall, Eval(Sample(frameWidth: 0)).Verdict);
    }

    // ─────────────────────────────── 三、正脸度边界

    [Theory(DisplayName = "正脸度：鼻尖偏移恰好到上限仍放行，超过即侧脸")]
    [InlineData(0.0, true)]
    [InlineData(0.35, true)]
    [InlineData(0.3501, false)]
    [InlineData(-0.35, true)]     // 左右对称：负方向同样按绝对值判
    [InlineData(-0.36, false)]
    public void YawBoundary(double shift, bool expectPass)
    {
        var r = Eval(Sample(points: FrontalPoints(shift)));
        Assert.Equal(expectPass ? FaceIdQualityVerdict.Pass : FaceIdQualityVerdict.NotFrontal, r.Verdict);
    }

    [Fact(DisplayName = "歪头超过容差 ⇒ NotFrontal")]
    public void RollBeyondTolerance_IsRejected()
    {
        var pts = FrontalPoints();
        // 左眼抬高 40 px（眼距 80）⇒ |dy|/|dx| = 0.5 > 0.30
        pts[1] = 160;
        Assert.Equal(FaceIdQualityVerdict.NotFrontal, Eval(Sample(points: pts)).Verdict);
    }

    /// <summary>
    /// ★ 关键点退化（NaN）⇒ NotFrontal，而不是 Pass。
    /// 若放行，引擎会在对齐那一步失败并返回 null；那样失败原因会变成
    /// "特征提不出来"，把一次可解释的几何问题伪装成算法故障。
    /// </summary>
    [Fact(DisplayName = "★ 关键点含 NaN ⇒ NotFrontal（fail closed）")]
    public void NaNAtLandmarks_FailsClosed()
    {
        var pts = FrontalPoints();
        pts[4] = double.NaN;   // 鼻尖 x
        Assert.Equal(FaceIdQualityVerdict.NotFrontal, Eval(Sample(points: pts)).Verdict);
    }

    [Fact(DisplayName = "关键点数量不足 ⇒ NotFrontal（fail closed）")]
    public void ShortPoints_FailsClosed()
    {
        Assert.Equal(FaceIdQualityVerdict.NotFrontal, Eval(Sample(points: new double[] { 1, 2, 3 })).Verdict);
    }

    // ─────────────────────────────── 四、清晰度：可测 / 不可测

    [Theory(DisplayName = "清晰度边界：恰好下限放行，低于下限判糊")]
    [InlineData(60.0, true)]
    [InlineData(59.99, false)]
    [InlineData(0.0, false)]
    [InlineData(1000.0, true)]
    public void SharpnessBoundary(double sharpness, bool expectPass)
    {
        var r = Eval(Sample(sharpness: sharpness));
        Assert.Equal(expectPass ? FaceIdQualityVerdict.Pass : FaceIdQualityVerdict.Blurry, r.Verdict);
    }

    /// <summary>
    /// ★ 清晰度测不出来（null）⇒ **跳过**这一项。
    /// 这是"假引擎也能走通录入"的前提：若把 null 当"糊"，stub 探针永远录不进去，
    /// 整条回归链就失去意义。
    /// </summary>
    [Fact(DisplayName = "★ 清晰度不可测 ⇒ 跳过，不判糊")]
    public void UnmeasurableSharpness_IsSkipped()
    {
        Assert.Equal(FaceIdQualityVerdict.Pass, Eval(Sample(sharpness: null)).Verdict);
    }

    // ─────────────────────────────── 五、几何量本身

    [Fact(DisplayName = "YawRatio：正脸为 0，偏移按眼距归一")]
    public void YawRatio_IsNormalizedByEyeDistance()
    {
        Assert.Equal(0.0, FaceIdQuality.YawRatio(FrontalPoints()), 9);
        Assert.Equal(0.5, FaceIdQuality.YawRatio(FrontalPoints(0.5)), 9);
        Assert.Equal(-1.0, FaceIdQuality.YawRatio(FrontalPoints(-1.0)), 9);
    }

    [Fact(DisplayName = "YawRatio：眼距为 0 / 数组过短 ⇒ NaN（不可用于判定）")]
    public void YawRatio_Degenerate_ReturnsNaN()
    {
        var zeroEye = FrontalPoints();
        zeroEye[2] = zeroEye[0];
        Assert.True(double.IsNaN(FaceIdQuality.YawRatio(zeroEye)));
        Assert.True(double.IsNaN(FaceIdQuality.YawRatio(new double[] { 1, 2, 3 })));
    }

    [Fact(DisplayName = "RollRatio：双眼水平为 0，|dy|/|dx| 线性")]
    public void RollRatio_MeasuresEyeLineSlope()
    {
        Assert.Equal(0.0, FaceIdQuality.RollRatio(FrontalPoints()), 9);

        var pts = FrontalPoints();
        pts[1] = 200 + 20;   // 左眼下降 20，眼距 80 ⇒ 0.25
        Assert.Equal(0.25, FaceIdQuality.RollRatio(pts), 9);
    }

    [Fact(DisplayName = "RollRatio：眼距为 0 ⇒ NaN")]
    public void RollRatio_Degenerate_ReturnsNaN()
    {
        var pts = FrontalPoints();
        pts[2] = pts[0];
        Assert.True(double.IsNaN(FaceIdQuality.RollRatio(pts)));
    }
}
