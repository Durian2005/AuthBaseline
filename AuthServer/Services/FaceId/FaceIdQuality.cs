namespace AuthServer.Services.FaceId;

/**
 * 录入质量闸门：一个**纯函数**，输入一帧的几何量与清晰度，输出"这一帧能不能用来录"。
 *
 * 为什么必须是纯函数：
 *   闸门的每一条判据都是一个"放行/拒绝"的决定，而决定的对错只能靠边界样本举证。
 *   若这些判断写在采集循环里（依赖摄像头、依赖 Mat），那么在没有任何摄像头的机器上
 *   一条都测不了 —— 而 P0 的教训正是"没有回归的判定，改了也不知道有没有改坏"。
 *
 * 判据顺序（也是有代价的取舍，顺序不能随便换）：
 *   ① 没有人脸            → NoFace
 *   ② 多于一张脸          → MultipleFaces   ← **安全优先，排在最前**
 *   ③ 人脸太小            → TooSmall
 *   ④ 侧脸 / 歪头         → NotFrontal
 *   ⑤ 糊                  → Blurry
 *
 * ② 为什么排在人脸大小之前：画面里出现第二张脸时，系统无法确认"存进去的是谁"。
 *   这不是"体验不好"，而是**把别人的生物特征录进这个账号**的风险。
 *   所以哪怕主脸很小（本来也会被 ③ 拒），也要优先报"多脸"，让用户知道
 *   问题出在画面里还有人，而不是让他反复靠近镜头。
 *
 * ⑤ 为什么排在最后：清晰度的度量依赖 ROI（脸框），脸框本身不可信时
 *   （太小、侧脸）算出来的方差也没有意义。先修几何，再谈清晰度。
 *
 * 一条贯穿始终的原则：**测不出来 ⇒ 跳过这一项，而不是判不合格**。
 *   假引擎没有像素、某些帧的 ROI 越界，都会让清晰度为 null。
 *   若把 null 当成"糊"，stub 环境将永远录不进去 —— 一个"安全的"设计
 *   如果让功能在正常环境下不可用，那它只是把风险换成了不可用。
 *   但几何量（脸数、大小、正脸度）没有"测不出来"这一说，缺失一律 fail closed。
 */
public enum FaceIdQualityVerdict
{
    /// <summary>这一帧可用。</summary>
    Pass,

    /// <summary>画面里没有人脸。</summary>
    NoFace,

    /// <summary>画面里有不止一张脸 —— 无法确认存的是谁。</summary>
    MultipleFaces,

    /// <summary>人脸太小（离得太远）。</summary>
    TooSmall,

    /// <summary>侧脸或歪头幅度过大，对齐后的特征不可靠。</summary>
    NotFrontal,

    /// <summary>画面糊（失焦 / 运动模糊）。</summary>
    Blurry
}

/// <summary>
/// 一帧的可测量输入。刻意只放**标量**，不放 Mat / 帧对象 ——
/// 这样单测可以直接构造它，不需要任何图像。
/// </summary>
public sealed record FaceIdQualitySample(
    int FaceCount,
    double FrameWidth,
    double FrameHeight,
    double BoxWidth,
    double BoxHeight,
    double[] Points,
    double? Sharpness);

/// <summary>闸门结论 + 一行诊断（诊断只进审计，不进响应体）。</summary>
public sealed record FaceIdQualityResult(FaceIdQualityVerdict Verdict, string Diagnostic)
{
    public bool Passed => Verdict == FaceIdQualityVerdict.Pass;
}

/// <summary>质量闸门的纯判定入口。</summary>
public static class FaceIdQuality
{
    /// <summary>
    /// 按配置的阈值判定一帧。
    /// </summary>
    public static FaceIdQualityResult Evaluate(FaceIdQualitySample sample, FaceIdOptions opt) =>
        Evaluate(sample, opt.MinFaceWidthRatio, opt.MaxYawRatio, opt.MaxRollRatio, opt.MinSharpness);

    /// <summary>
    /// 判定一帧（阈值显式传入，便于单测把边界钉死，不依赖配置类）。
    /// </summary>
    /// <param name="minWidthRatio">脸宽 / 帧宽 的下限。</param>
    /// <param name="maxYawRatio">鼻尖水平偏移 / 双眼间距 的上限（绝对值）。</param>
    /// <param name="maxRollRatio">双眼连线 |dy| / |dx| 的上限。</param>
    /// <param name="minSharpness">拉普拉斯方差下限；sample.Sharpness 为 null 时跳过。</param>
    public static FaceIdQualityResult Evaluate(FaceIdQualitySample sample,
        double minWidthRatio, double maxYawRatio, double maxRollRatio, double minSharpness)
    {
        var yaw = YawRatio(sample.Points);
        var roll = RollRatio(sample.Points);
        var widthRatio = sample.FrameWidth > 0 ? sample.BoxWidth / sample.FrameWidth : double.NaN;
        var diagnostic =
            $"faces={sample.FaceCount} width={Format(widthRatio)} yaw={Format(yaw)} "
            + $"roll={Format(roll)} sharp={Format(sample.Sharpness)}";

        if (sample.FaceCount <= 0)
            return new FaceIdQualityResult(FaceIdQualityVerdict.NoFace, diagnostic);

        if (sample.FaceCount > 1)
            return new FaceIdQualityResult(FaceIdQualityVerdict.MultipleFaces, diagnostic);

        // 帧宽缺失/为 0 属于调用方传错，但也不能放行 —— fail closed。
        if (!double.IsFinite(widthRatio) || widthRatio < minWidthRatio)
            return new FaceIdQualityResult(FaceIdQualityVerdict.TooSmall, diagnostic);

        // 关键点退化（NaN）同样 fail closed：那意味着对齐会失败，
        // 与其让引擎在下面抛/返回 null，不如在这里给出准确的原因。
        if (!double.IsFinite(yaw) || !double.IsFinite(roll)
            || Math.Abs(yaw) > maxYawRatio || Math.Abs(roll) > maxRollRatio)
            return new FaceIdQualityResult(FaceIdQualityVerdict.NotFrontal, diagnostic);

        // null = 这套引擎测不了清晰度 ⇒ 跳过这一项（理由见类头最后一段）。
        if (sample.Sharpness is double sharpness && sharpness < minSharpness)
            return new FaceIdQualityResult(FaceIdQualityVerdict.Blurry, diagnostic);

        return new FaceIdQualityResult(FaceIdQualityVerdict.Pass, diagnostic);
    }

    /// <summary>
    /// 正脸度：鼻尖相对双眼中点的**水平**偏移，以双眼间距为单位。
    /// 正值 = 鼻子偏向画面右侧（人脸 B 的眼睛那一侧）。
    /// 关键点顺序与 <see cref="FaceIdBox.Points"/> 一致：眼A 眼B 鼻 嘴角A 嘴角B。
    ///
    /// 为什么用这个比值而不是角度：5 个点给不出可靠的三维姿态，
    /// 而"鼻子离开双眼中点多少"是一个**单调**反映左右转头的量，且与脸的大小无关。
    /// 它不精确，但足够把"明显侧脸"挡在门外 —— 那正是闸门要做的事。
    /// </summary>
    public static double YawRatio(double[] points)
    {
        if (points is null || points.Length < 6) return double.NaN;
        double ax = points[0], bx = points[2];
        double nx = points[4];

        var eyeDist = Math.Abs(bx - ax);
        if (!double.IsFinite(eyeDist) || eyeDist <= 0) return double.NaN;

        var eyeMid = (ax + bx) / 2;
        if (!double.IsFinite(eyeMid) || !double.IsFinite(nx)) return double.NaN;
        return (nx - eyeMid) / eyeDist;
    }

    /// <summary>
    /// 滚转角（歪头）：双眼连线的 |dy| / |dx|。0 = 双眼水平，越大越歪。
    /// </summary>
    public static double RollRatio(double[] points)
    {
        if (points is null || points.Length < 4) return double.NaN;
        var dx = Math.Abs(points[2] - points[0]);
        var dy = Math.Abs(points[3] - points[1]);
        if (!double.IsFinite(dx) || !double.IsFinite(dy) || dx <= 0) return double.NaN;
        return dy / dx;
    }

    private static string Format(double? value) =>
        value is null || !double.IsFinite(value.Value) ? "n/a" : value.Value.ToString("F3");
}
