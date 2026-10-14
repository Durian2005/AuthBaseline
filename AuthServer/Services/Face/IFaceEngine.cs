namespace AuthServer.Services.Face;

/**
 * 人脸引擎的抽象。
 *
 * 为什么要有这一层（而不是让控制器直接调 OpenCV）：
 *   1) **策略与算法分离**：审计怎么写、失败计不计次、票据什么时候签 —— 这些属于认证策略，
 *      必须留在 C# 一处收口；引擎只负责"这一帧里有没有脸、这张脸像不像"。
 *   2) **可替换**：真实引擎依赖摄像头与本地模型，在没有摄像头的机器上整条链就不可测。
 *      有了抽象，回归探针可以注入假引擎，把"口令 → 挑战 → 人脸 → 签票 → 审计"整条链跑通。
 *   3) **采集端留在服务端**：接口上没有"接收前端传来的特征"这种形状，
 *      所以"前端伪造一个向量直接提交"这条路在类型层面就不存在。
 *
 * 这一层刻意**不引用任何 OpenCvSharp 类型**（帧用不透明的 Backing 转发），
 * 这样假引擎不必为了编译而拖进 OpenCV 原生库。
 */

/// <summary>一帧画面。对上层是不透明的，只暴露尺寸。</summary>
public sealed class FaceFrame
{
    public int Width { get; init; }
    public int Height { get; init; }

    /// <summary>引擎自己认识的帧对象（CvFaceEngine 里是 OpenCvSharp 的 Mat）。上层不许碰。</summary>
    public object? Backing { get; init; }
}

/// <summary>
/// 一帧里的**一张**脸。字段顺序与 YuNet 的 15 个浮点输出一一对应，
/// 便于对照参考实现排查（<c>[x, y, w, h, 眼A, 眼B, 鼻, 嘴A, 嘴B, 置信度]</c>）。
/// </summary>
public sealed class FaceBox
{
    public double X { get; init; }
    public double Y { get; init; }
    public double W { get; init; }
    public double H { get; init; }

    /// <summary>5 个关键点，展平成 10 个数：眼A(x,y) 眼B(x,y) 鼻(x,y) 嘴A(x,y) 嘴B(x,y)。</summary>
    public double[] Points { get; init; } = new double[10];

    /// <summary>检测置信度（YuNet 的第 15 个输出）。</summary>
    public double Score { get; init; }

    /// <summary>人脸中心（画面内归一化前的像素坐标），用于跳变检测。</summary>
    public double CenterX => X + W / 2.0;
    public double CenterY => Y + H / 2.0;
}

/// <summary>引擎可用性。不可用时 <see cref="Message"/> 是给人看的原因。</summary>
public sealed record FaceEngineStatus(bool Ready, string Message)
{
    public static FaceEngineStatus Up() => new(true, string.Empty);
    public static FaceEngineStatus Down(string message) => new(false, message);
}

/// <summary>
/// 一次动作挑战的采样结果。
///
/// <see cref="BusinessCode"/> 只在失败时有值，且**必须是 BusinessCodes.Face* 里的取值** ——
/// 计数与否由 <see cref="FaceCodes.IsCounted"/> 按它对应的审计码决定，不由本层判断。
/// </summary>
public sealed class ChallengeOutcome
{
    public bool Passed { get; init; }
    public string BusinessCode { get; init; } = string.Empty;

    /// <summary>通过时才有：**动作完成后已回正**的那一帧的特征。</summary>
    public double[]? Feature { get; init; }

    /// <summary>压成一行的诊断量，写进审计的 request/response JSON 袋（绝不单独加列）。</summary>
    public string Diagnostic { get; init; } = string.Empty;

    public int Samples { get; init; }
    public int Misses { get; init; }
    public int Jumps { get; init; }
    public double ElapsedSeconds { get; init; }

    public static ChallengeOutcome Fail(string businessCode, string diagnostic, int samples = 0, int misses = 0,
        int jumps = 0, double elapsed = 0)
        => new()
        {
            Passed = false, BusinessCode = businessCode, Diagnostic = diagnostic,
            Samples = samples, Misses = misses, Jumps = jumps, ElapsedSeconds = elapsed
        };
}

/// <summary>
/// 人脸引擎。所有实现都必须满足两条：
///   1) 采集、检测、特征提取**全在本进程内**完成，不接受外部传入的任何画面或特征；
///   2) 线程安全 —— 登录/录入/管理三条路径可能并发调用，而 OpenCV 的
///      DetectorYN / Recognizer 实例并不保证线程安全（不加锁属于随机崩溃）。
/// </summary>
public interface IFaceEngine
{
    FaceEngineStatus Status { get; }

    /// <summary>打开摄像头（幂等）。返回 null 表示成功，否则是给用户看的原因。</summary>
    string? TryOpen();

    /// <summary>关闭并释放摄像头。桌面端"关页面即释放摄像头"依赖它。</summary>
    void Close();

    /// <summary>读一帧。读失败返回 null（调用方按"质量问题"处理，不计次）。</summary>
    FaceFrame? ReadFrame();

    /// <summary>返回画面中面积最大的那张脸，没有则返回 null。</summary>
    FaceBox? DetectLargest(FaceFrame frame);

    /// <summary>在**指定的一帧与一张脸**上提特征。返回 null 表示该帧不可用。</summary>
    double[]? Feature(FaceFrame frame, FaceBox box);

    /// <summary>两个特征的余弦相似度。特征**不做 L2 归一化**存储，归一化在这里做。</summary>
    double Similarity(double[] a, double[] b);

    /// <summary>跑一次完整的动作挑战：求基线 → 等动作 → 等回正 → 从回正那一帧提特征。</summary>
    ChallengeOutcome RunChallenge(string action);
}
