namespace AuthServer.Services.FaceId;

/**
 * 活体判定（PAD，Presentation Attack Detection）的抽象。
 *
 * 它回答的问题只有一个：**这一帧里的脸，是不是"一个真人的脸"** ——
 * 而不是"这张脸是谁"（那是 Feature/Similarity 的事），
 * 也不是"这张脸清不清楚"（那是 FaceIdQuality 的事）。
 *
 * 为什么单独抽一层而不塞进 IFaceIdEngine：
 *   ① 录入链路需要它，P2 的登录链路也需要它，但两条链路的**失败语义不同**
 *      （录入失败不计次、登录失败要计次）—— 把判定与记账分开，才能各写各的。
 *   ② 它有自己的模型与自己的失败模式（模型缺失 = 不可用）。混进引擎会让
 *      "人脸检不出来"与"活体模型没加载"在调用点变成同一个分支。
 *
 * ⚠️ 本层**只给分数，不做决定**：阈值属于策略，收在调用方（见 FaceIdOptions.PadMinLive）。
 *    这样"阈值今天定 0.70、明天按样本改成 0.65"不需要动算法代码。
 */
public sealed record FaceIdLivenessStatus(bool Ready, string Message)
{
    public static FaceIdLivenessStatus Up() => new(true, string.Empty);
    public static FaceIdLivenessStatus Down(string message) => new(false, message);
}

public interface IFaceIdLiveness
{
    FaceIdLivenessStatus Status { get; }

    /// <summary>
    /// 返回 live 概率（0..1）；**null 表示模型不可用**。
    ///
    /// 返回 null 而不是 0 或 1，是因为这两种数值都会被误读：
    ///   0 ⇒ 调用方会当成"活体检测失败"，把环境问题记成一次攻击；
    ///   1 ⇒ 那就成了 fail open（模型坏了反而全部放行），是本模块最不能接受的失败方向。
    /// 调用方拿到 null 必须**拒绝本次操作并如实报"引擎不可用"**。
    /// </summary>
    double? Score(FaceIdFrame frame, FaceIdBox box);
}
