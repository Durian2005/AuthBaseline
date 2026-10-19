namespace AuthServer.Services.FaceId;

/**
 * 假活体判定：让"照片/屏幕被拒"这条分支在没有摄像头、没有模型的机器上也能被回归。
 *
 * 行为由 FaceIdOptions.StubBehavior 决定（探针通过环境变量切换）：
 *   · "spoof"    ⇒ 每次都给一个远低于阈值的分数（模拟举着手机翻拍）
 *   · "pad_down" ⇒ Status 为不可用、Score 返回 null（模拟模型文件缺失）
 *   · 其余       ⇒ 返回一个稳定的高分（模拟真人）
 *
 * 分数刻意给**常量**而不是加噪声：探针要断言的是"低于阈值就会被拒"，
 * 任何随机性都会让这条断言变成概率事件 —— 而概率事件不能当门禁用。
 */
public sealed class StubFaceIdLiveness : IFaceIdLiveness
{
    /// <summary>模拟真人时的分数（远高于默认阈值 0.70，留足余量）。</summary>
    private const double LiveScore = 0.95;

    /// <summary>模拟攻击时的分数（远低于默认阈值，且明显不是"刚好擦边"）。</summary>
    private const double SpoofScore = 0.05;

    private readonly FaceIdOptions _opt;

    public StubFaceIdLiveness(FaceIdOptions opt)
    {
        _opt = opt;
        Status = string.Equals(opt.StubBehavior, "pad_down", StringComparison.Ordinal)
            ? FaceIdLivenessStatus.Down("假引擎：活体模型不可用（stub）")
            : FaceIdLivenessStatus.Up();
    }

    public FaceIdLivenessStatus Status { get; }

    public double? Score(FaceIdFrame frame, FaceIdBox box)
    {
        if (!Status.Ready) return null;
        return string.Equals(_opt.StubBehavior, "spoof", StringComparison.Ordinal) ? SpoofScore : LiveScore;
    }
}
