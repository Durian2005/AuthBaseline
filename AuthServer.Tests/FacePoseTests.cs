using AuthServer.Services.Face;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="FacePose"/> 的纯逻辑回归 —— 也就是"活体动作判定"里**不碰摄像头的那一半**。
///
/// 为什么这一半值得单独钉住：
///   · 阈值（0.13 / 0.07 / 0.05）是从真实摄像头上逐点核对出来的经验值，
///     "顺手调一点让它更好过"是最容易发生、也最难被发现的退化 —— 调松了，
///     防重放的强度就悄悄掉了；调紧了，普通用户录不进来。这里把取值与边界一起固定。
///   · 动作池在 2026-10-14 从 4 个减到 2 个（去掉抬头/低头）。这个决定有明确的代价
///     （对"预录左右两方向视频"的抵抗力变弱），必须由测试记录住**当时的取舍**，
///     而不是靠某个人记得。谁要加回 pitch 动作，就得先改这条断言并解释。
///   · 判定所需的常量之间存在**不变量**（滑窗长度 ≥ 命中数、有效帧下限 ≥ 基线帧数……）。
///     写成断言后，"调一个忘了调另一个"会立刻变成红测试，而不是现场偶发的判定失败。
///
/// 摄像头相关的部分（采样节奏、丢帧、跳变、预览推帧）不在本文件里 ——
/// 那些只能由真机（或 P1-5 的帧回放 fixture）覆盖。
/// </summary>
public class FacePoseTests
{
    /// <summary>
    /// 造一张"正脸"：双眼水平、鼻尖居中、嘴巴在下方对称。
    /// 坐标系随意（只关心比值），但比例要接近真人：瞳距 100px、眼嘴纵向 60px。
    /// </summary>
    private static FaceBox Box(double noseDx = 0, double noseDy = 0, double scale = 1.0)
    {
        double eyeAx = 100, eyeAy = 100, eyeBx = 200, eyeBy = 100;
        double noseX = 150 + noseDx, noseY = 100 + noseDy;
        double mouthAx = 120, mouthAy = 160, mouthBx = 180, mouthBy = 160;

        return new FaceBox
        {
            X = 100 * scale, Y = 60 * scale, W = 100 * scale, H = 120 * scale,
            Points = new[]
            {
                eyeAx * scale, eyeAy * scale,
                eyeBx * scale, eyeBy * scale,
                noseX * scale, noseY * scale,
                mouthAx * scale, mouthAy * scale,
                mouthBx * scale, mouthBy * scale
            },
            Score = 0.95
        };
    }

    // ────────────────────────────────────────── 一、动作池（含取舍记录）

    /// <summary>
    /// ★ 动作池必须**恰好**是 left / right。
    /// 2026-10-14 去掉抬头/低头是因为 pitch 代理值在真实摄像头上不稳
    /// （坐姿、眼镜、摄像头俯仰角都会整体搬移基线），不是"占位没做完"。
    /// </summary>
    [Fact(DisplayName = "★ 动作池恰好是 left/right（pitch 动作已下线，加回需改此断言）")]
    public void Actions_AreExactlyLeftAndRight()
    {
        Assert.Equal(new[] { "left", "right" }, FacePose.Actions);
        Assert.Equal(2, FacePose.Actions.Length);
        // 去重：同一个动作出现两次会让"随机抽取"实际偏向某一个方向。
        Assert.Equal(FacePose.Actions.Length, FacePose.Actions.Distinct().Count());
    }

    /// <summary>每个动作都必须有给用户看的说明，且说明互不相同（否则界面会误导方向）。</summary>
    [Fact(DisplayName = "动作文案齐全且互不相同")]
    public void ActionText_CoversAllActions()
    {
        var texts = FacePose.Actions.Select(FacePose.ActionText).ToArray();
        Assert.All(texts, t => Assert.False(string.IsNullOrWhiteSpace(t)));
        Assert.Equal(texts.Length, texts.Distinct().Count());
        Assert.Contains("左", texts[0]);
        Assert.Contains("右", texts[1]);
    }

    /// <summary>未知动作的文案退回"请正对摄像头"，不会抛异常。</summary>
    [Theory(DisplayName = "未知动作 ⇒ 中性文案")]
    [InlineData("up")]
    [InlineData("")]
    [InlineData("LEFT")]   // 大小写敏感：动作名来自服务端常量，不该做模糊匹配
    public void ActionText_UnknownFallsBack(string action)
    {
        Assert.Equal("请正对摄像头", FacePose.ActionText(action));
    }

    // ────────────────────────────────────────── 二、满足动作的判定

    /// <summary>
    /// ★ 阈值边界：yaw 偏移 **恰好** 0.13 算满足，差 0.001 就不算。
    /// 真实帧几乎不可能落在这条线上，所以只有单测能钉住"判定式是 >= 还是 >"。
    /// </summary>
    [Theory(DisplayName = "★ 动作阈值边界（YawTurn = 0.13）")]
    [InlineData("left", 0.13, true)]
    [InlineData("left", 0.1299, false)]
    [InlineData("left", 0.5, true)]
    [InlineData("right", -0.13, true)]
    [InlineData("right", -0.1299, false)]
    [InlineData("right", -0.5, true)]
    [InlineData("left", -0.5, false)]    // 方向相反不算：否则随便转个头就能过
    [InlineData("right", 0.5, false)]
    public void Satisfied_Threshold(string action, double dy, bool expected)
    {
        Assert.Equal(expected, FacePose.Satisfied(action, dy, 0));
    }

    /// <summary>
    /// ★ 未知动作**一律不满足** —— 即使偏移量巨大。
    /// 这是防"判定被蒙过"的最后一层：动作名只可能来自 FacePose.Actions，
    /// 但一旦有人把 pitch 动作加回池子里而忘了实现判定，这里必须失败而不是放行。
    /// </summary>
    [Theory(DisplayName = "★ 未知动作即便偏移巨大也判不满足")]
    [InlineData("up")]
    [InlineData("down")]
    [InlineData("")]
    public void Satisfied_UnknownAction_NeverTrue(string action)
    {
        Assert.False(FacePose.Satisfied(action, 9.9, 9.9));
        Assert.False(FacePose.Satisfied(action, -9.9, -9.9));
    }

    // ────────────────────────────────────────── 三、回正判定

    /// <summary>
    /// 回正判定同时看 yaw 与 pitch：只回正一半就取特征，会拿侧脸去比对正规录入的模板。
    /// 边界值（0.07 / 0.05）同样要精确。
    /// </summary>
    [Theory(DisplayName = "回正阈值边界（yaw 0.07 / pitch 0.05）")]
    [InlineData(0, 0, true)]
    [InlineData(0.07, 0.05, true)]      // 恰好压线：算回正
    [InlineData(-0.07, -0.05, true)]    // 负方向同样压线
    [InlineData(0.071, 0, false)]       // yaw 越界
    [InlineData(0, 0.051, false)]       // pitch 越界
    [InlineData(-0.071, 0, false)]
    [InlineData(0, -0.051, false)]
    public void IsNeutral_Threshold(double dy, double dp, bool expected)
    {
        Assert.Equal(expected, FacePose.IsNeutral(dy, dp));
    }

    // ────────────────────────────────────────── 四、关键点指标

    /// <summary>正脸 ⇒ yaw / pitch 都应为 0，iod 等于瞳距。</summary>
    [Fact(DisplayName = "正脸关键点 ⇒ yaw=0、pitch=0、iod=瞳距")]
    public void Metrics_FrontalFace()
    {
        var (yaw, pitch, iod) = FacePose.Metrics(Box());
        Assert.Equal(0.0, yaw, 6);
        Assert.Equal(0.0, pitch, 6);
        Assert.Equal(100.0, iod, 6);
    }

    /// <summary>
    /// 偏移量换成比值：鼻尖右移 10px / 瞳距 100px ⇒ yaw = 0.1；
    /// 鼻尖下移 30px / 眼嘴纵向 60px ⇒ pitch = 0.5。
    /// 这两个数就是"判定看到的东西"，算错了阈值再准也没意义。
    /// </summary>
    [Fact(DisplayName = "yaw / pitch 是按瞳距与眼嘴距归一化的比值")]
    public void Metrics_NormalizedOffsets()
    {
        var (yaw, pitch, _) = FacePose.Metrics(Box(noseDx: 10, noseDy: 30));
        Assert.Equal(0.1, yaw, 6);
        Assert.Equal(0.5, pitch, 6);
    }

    /// <summary>
    /// ★ 比值天然抗缩放：整张画面放大 2 倍，yaw / pitch 必须**完全不变**，iod 翻倍。
    /// 这条保证"换个分辨率"不会让判定整体偏移 —— 参考项目的阈值能直接搬过来就靠它。
    /// </summary>
    [Fact(DisplayName = "★ 画面缩放不改变 yaw / pitch（比值抗缩放）")]
    public void Metrics_ScaleInvariant()
    {
        var a = FacePose.Metrics(Box(noseDx: 10, noseDy: 30, scale: 1.0));
        var b = FacePose.Metrics(Box(noseDx: 10, noseDy: 30, scale: 2.0));

        Assert.Equal(a.Yaw, b.Yaw, 9);
        Assert.Equal(a.Pitch, b.Pitch, 9);
        Assert.Equal(a.Iod * 2, b.Iod, 6);
    }

    /// <summary>
    /// 退化输入（关键点全部重合 ⇒ 瞳距与眼嘴距都是 0）不能产生 NaN/Infinity。
    /// 一旦出现 NaN，所有比较都是 false，动作永远判不出来 —— 而症状只会表现为
    /// "怎么都不通过"，极难定位。这里用 max(…, 1e-6) 兜住。
    /// </summary>
    [Fact(DisplayName = "★ 退化关键点（间距为 0）⇒ 不出 NaN / Infinity")]
    public void Metrics_DegeneratePoints_NoNaN()
    {
        var box = new FaceBox { Points = new double[10], W = 1, H = 1 };
        var (yaw, pitch, iod) = FacePose.Metrics(box);

        Assert.False(double.IsNaN(yaw));
        Assert.False(double.IsNaN(pitch));
        Assert.False(double.IsNaN(iod));
        Assert.False(double.IsInfinity(yaw));
        Assert.False(double.IsInfinity(pitch));
        Assert.Equal(0.0, iod, 9);
    }

    // ────────────────────────────────────────── 五、中位数与原位性

    /// <summary>基线用的是**中位数**而不是平均值：一两次异常帧不该把基线带偏。</summary>
    [Theory(DisplayName = "Median：空 / 单值 / 奇偶长度")]
    [InlineData(new double[0], 0.0)]
    [InlineData(new[] { 0.42 }, 0.42)]
    [InlineData(new[] { 0.3, 0.1, 0.2 }, 0.2)]              // 奇数取中间
    [InlineData(new[] { 0.4, 0.1, 0.3, 0.2 }, 0.25)]        // 偶数取中间两数均值为 0.25
    [InlineData(new[] { 0.2, 0.2, 0.9 }, 0.2)]
    public void Median_Cases(double[] input, double expected)
    {
        Assert.Equal(expected, FacePose.Median(input.ToList()), 9);
    }

    /// <summary>
    /// ★ Median 不许改动入参：调用方在采集循环里持续往同一个 List 追加样本，
    /// 若 Median 就地排序，采到的顺序会被打乱（诊断信息里的 min/max 就不可信了）。
    /// </summary>
    [Fact(DisplayName = "★ Median 不改动入参列表")]
    public void Median_DoesNotMutateInput()
    {
        var input = new List<double> { 3, 1, 2 };
        FacePose.Median(input);
        Assert.Equal(new[] { 3.0, 1.0, 2.0 }, input);

        // 重复调用结果必须稳定（若内部排序漏了复制，第二次会得到同样的值但顺序已变，
        // 这里的入参断言就是抓那种"看起来对"的实现）。
        Assert.Equal(2.0, FacePose.Median(input), 9);
        Assert.Equal(new[] { 3.0, 1.0, 2.0 }, input);
    }

    // ────────────────────────────────────────── 六、常量之间的不变量

    /// <summary>
    /// 这些断言不看具体数值，只看它们**彼此是否相容**。
    /// 它们能抓到的典型事故：把 HitWindow 调小却没调 HitNeeded（动作永远不成立）、
    /// 把 MinSamples 调到基线帧数以下（基线还没算出来就开始判动作）。
    /// </summary>
    [Fact(DisplayName = "★ 判定常量之间的不变量")]
    public void Constants_Invariants()
    {
        Assert.True(FacePose.HitNeeded <= FacePose.HitWindow,
            "滑窗内最多只有 HitWindow 帧，命中要求不能超过它 —— 否则动作永远不成立");
        Assert.True(FacePose.HitNeeded >= 1);
        Assert.True(FacePose.BaselineFrames >= 1);
        Assert.True(FacePose.NeutralFrames >= 1);
        Assert.True(FacePose.MinSamples >= FacePose.BaselineFrames + FacePose.NeutralFrames,
            "有效帧下限至少要够算出基线并观察到回正");
        Assert.True(FacePose.MaxMiss >= 1);
        Assert.True(FacePose.MaxJumps >= 1);
        Assert.InRange(FacePose.SampleIntervalSeconds, 0.01, 0.2);   // 5~100 Hz，14 Hz 落在中间
        Assert.True(FacePose.YawTurn > FacePose.NeutralYaw,
            "动作阈值必须比回正容差大，中间留出回差，否则一帧会被同时判成'在做动作'和'已回正'");
        Assert.InRange(FacePose.JumpRatio, 0.1, 2.0);
    }

    /// <summary>
    /// 阈值常量取值钉死。改这些数字必须同时改这条断言 —— 强制改的人留下解释，
    /// 因为它们是"在真实摄像头上逐点核对过"的经验值，不能靠感觉调。
    /// </summary>
    [Fact(DisplayName = "阈值取值钉死（0.13 / 0.07 / 0.05）")]
    public void Thresholds_ArePinned()
    {
        Assert.Equal(0.13, FacePose.YawTurn, 9);
        Assert.Equal(0.07, FacePose.NeutralYaw, 9);
        Assert.Equal(0.05, FacePose.NeutralPitch, 9);
    }
}
