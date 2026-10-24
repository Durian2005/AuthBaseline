namespace AuthServer.Services.FaceId;

/**
 * 纯人脸登录引擎的抽象。
 *
 * 为什么要有这一层（而不是让控制器直接调 OpenCV）：
 *   1) **策略与算法分离**：审计怎么写、失败计不计次、票据什么时候签 —— 这些属于认证策略，
 *      必须留在 C# 一处收口；引擎只负责"这一帧里有没有脸、这张脸像不像"。
 *   2) **可替换**：真实引擎依赖摄像头与本地模型，在没有摄像头的机器上整条链就不可测。
 *      有了抽象，回归探针可以注入假引擎，把"用户名 → 人脸 → 签票 → 审计"整条链跑通。
 *   3) **采集端留在服务端**：接口上没有"接收前端传来的特征"这种形状，
 *      所以"前端伪造一个向量直接提交"这条路在类型层面就不存在。
 *
 * 与 <see cref="AuthServer.Services.Face.IFaceEngine"/>（人脸 2FA）是两套**各自独立**的抽象：
 *   本模块无动作挑战、无活体判定、无预览推帧，接口因此小得多。
 *   两套接口刻意不共用任何类型 —— 将来删除 2FA 模块时，本文件与它的实现都不受影响。
 *
 * 这一层刻意**不引用任何 OpenCvSharp 类型**（帧用不透明的 Backing 转发），
 * 这样假引擎不必为了编译而拖进 OpenCV 原生库。
 */

/// <summary>一帧画面。对上层是不透明的，只暴露尺寸。</summary>
public sealed class FaceIdFrame
{
    public int Width { get; init; }
    public int Height { get; init; }

    /// <summary>引擎自己认识的帧对象（CvFaceIdEngine 里是 OpenCvSharp 的 Mat）。上层不许碰。</summary>
    public object? Backing { get; init; }
}

/// <summary>
/// 一帧里的**一张**脸。字段顺序与 YuNet 的 15 个浮点输出一一对应，
/// 便于对照参考实现排查（<c>[x, y, w, h, 眼A, 眼B, 鼻, 嘴A, 嘴B, 置信度]</c>）。
/// </summary>
public sealed class FaceIdBox
{
    public double X { get; init; }
    public double Y { get; init; }
    public double W { get; init; }
    public double H { get; init; }

    /// <summary>5 个关键点，展平成 10 个数：眼A(x,y) 眼B(x,y) 鼻(x,y) 嘴A(x,y) 嘴B(x,y)。</summary>
    public double[] Points { get; init; } = new double[10];

    /// <summary>检测置信度（YuNet 的第 15 个输出）。</summary>
    public double Score { get; init; }
}

/// <summary>引擎可用性。不可用时 <see cref="Message"/> 是给人看的原因。</summary>
public sealed record FaceIdEngineStatus(bool Ready, string Message)
{
    public static FaceIdEngineStatus Up() => new(true, string.Empty);
    public static FaceIdEngineStatus Down(string message) => new(false, message);
}

/// <summary>
/// 一张脸的**一对**特征：主模型（ArcFace，512 维）+ 第二模型（SFace，128 维）。
///
/// 为什么必须是"一对"而不是两个独立方法：
///   两条特征必须来自**同一张 112×112 对齐图**。分成两次调用就要求调用方自己保证
///   "两次传的是同一帧、同一个脸框"，而那个约束没有任何东西在检查 —— 一旦错位，
///   AND 会拿 A 的脸和 B 的脸做比较，结果既不是通过也不是不通过，而是随机。
///   收成一个返回值，"同源"就成了类型层面的性质。
/// </summary>
public sealed record FaceIdFeaturePair(double[] Primary, double[] Second);

/// <summary>
/// 纯人脸登录引擎。所有实现都必须满足两条：
///   1) 采集、检测、特征提取**全在本进程内**完成，不接受外部传入的任何画面或特征；
///   2) 线程安全 —— 登录/录入两条路径可能并发调用，而 OpenCV 的
///      DetectorYN / Net 实例并不保证线程安全（不加锁属于随机崩溃）。
/// </summary>
public interface IFaceIdEngine
{
    FaceIdEngineStatus Status { get; }

    /// <summary>打开摄像头（幂等）。返回 null 表示成功，否则是给用户看的原因。</summary>
    string? TryOpen();

    /// <summary>关闭并释放摄像头。桌面端"关页面即释放摄像头"依赖它。</summary>
    void Close();

    /// <summary>读一帧。读失败返回 null（调用方按"质量问题"处理）。</summary>
    FaceIdFrame? ReadFrame();

    /// <summary>返回画面中面积最大的那张脸，没有则返回 null。</summary>
    FaceIdBox? DetectLargest(FaceIdFrame frame);

    /// <summary>
    /// 返回画面里**全部**检测到的脸（录入闸门要数人数：画面里两张脸时不能挑一张存下来 ——
    /// 究竟是哪一张会被存进模板，用户和系统都无法确认）。
    ///
    /// 与 <see cref="DetectLargest"/> 刻意的差别：只做"有几个、在哪"，不涉及特征。
    /// 空列表表示这一帧没有人脸（**不是**错误）。
    /// </summary>
    IReadOnlyList<FaceIdBox> DetectAll(FaceIdFrame frame);

    /// <summary>
    /// 在脸框内测清晰度（拉普拉斯方差），供录入闸门判"糊没糊"。
    ///
    /// 返回 **null 表示"这套引擎测不了"**，而不是"很差"：
    /// 假引擎没有真实像素，只能返回 null；闸门据此**跳过**这一项，
    /// 而不是把一个测不出来的指标当成不合格（那会让 stub 环境永远录不进去）。
    /// </summary>
    double? Sharpness(FaceIdFrame frame, FaceIdBox box);

    /// <summary>
    /// 在**指定的一帧与一张脸**上提特征，返回一对（主模型 + 第二模型）。
    ///
    /// 返回 null 表示该帧不可用（对齐失败 / 关键点退化 / 任一模型未加载）——
    /// **不返回"只有一半"的值**：半个特征没法做 AND，只能被误当成一次单模型判定。
    /// </summary>
    FaceIdFeaturePair? Feature(FaceIdFrame frame, FaceIdBox box);

    /// <summary>两个特征的余弦相似度。特征**不做 L2 归一化**存储，归一化在这里做。</summary>
    double Similarity(double[] a, double[] b);
}
