using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services.Face;

/**
 * 假引擎：不碰摄像头、不加载模型，但**行为形状与真引擎完全一致**。
 *
 * 它解决的是一个具体的工程问题：人脸模块里最需要被回归覆盖的，是
 * "口令通过 → 发挑战 → 人脸过/不过 → 计次/不计次 → 签票/不签票 → 审计怎么写"
 * 这条链，以及 A 组（计次）与 B 组（不计次）的分流。
 *   而这些分支恰恰**在有摄像头的开发机上也几乎没法手工复现** ——
 *   要拿一张照片、要预录一段不对应动作的视频、要精确制造"动作做完没回正"。
 * 假引擎让这些分支变成"改一个环境变量就能走到"的确定性路径。
 *
 * 它**不**承担算法正确性的举证责任：那由 Stage 0 的对照实验单独保证
 * （C# 管线与 cv2 管线逐位等价，cos = 1.00000000）。
 *
 * 特征由"呈现身份"字符串的 SHA-256 确定性派生 ——
 * 同一个身份两次派生出的向量逐位相同，所以"录入 → 验证"的余弦正好是 1.0；
 * 换一个身份则两个向量近乎正交。这正是真引擎里"本人 / 非本人"的语义。
 */
public sealed class StubFaceEngine : IFaceEngine
{
    private readonly FaceOptions _opt;
    private bool _open;

    public StubFaceEngine(FaceOptions opt)
    {
        _opt = opt;
        Console.WriteLine("[Face] ⚠️ 正在使用**假引擎**（无摄像头/无模型）—— 仅供流程与审计验证");
    }

    public FaceEngineStatus Status => string.Equals(_opt.StubBehavior, "engine_down", StringComparison.Ordinal)
        ? FaceEngineStatus.Down("假引擎：模拟引擎不可用")
        : FaceEngineStatus.Up();

    public string? TryOpen()
    {
        if (string.Equals(_opt.StubBehavior, "engine_down", StringComparison.Ordinal))
            return "假引擎：模拟摄像头不可用";
        _open = true;
        return null;
    }

    public void Close() => _open = false;

    public FaceFrame? ReadFrame()
    {
        if (!_open) return null;
        if (string.Equals(_opt.StubBehavior, "engine_down", StringComparison.Ordinal)) return null;
        // Backing 留 null：假引擎没有真实像素，上层也不许去碰它。
        return new FaceFrame { Width = _opt.CaptureWidth, Height = _opt.CaptureHeight };
    }

    public FaceBox? DetectLargest(FaceFrame frame)
    {
        if (string.Equals(_opt.StubBehavior, "no_face", StringComparison.Ordinal)) return null;

        // 一张"假脸"：位置固定，5 个关键点按参考比例摆好，好让姿态计算不会除零。
        double w = _opt.CaptureWidth * 0.35, h = _opt.CaptureHeight * 0.45;
        double x = (_opt.CaptureWidth - w) / 2, y = (_opt.CaptureHeight - h) / 2;
        double cx = x + w / 2, cy = y + h / 2;
        var pts = new double[]
        {
            cx - w * 0.20, cy - h * 0.10,   // 眼 A
            cx + w * 0.20, cy - h * 0.10,   // 眼 B
            cx,            cy + h * 0.05,   // 鼻尖
            cx + w * 0.15, cy + h * 0.28,   // 嘴角 A
            cx - w * 0.15, cy + h * 0.28    // 嘴角 B
        };
        return new FaceBox { X = x, Y = y, W = w, H = h, Points = pts, Score = 0.99 };
    }

    public double[]? Feature(FaceFrame frame, FaceBox box) => Derive(_opt.StubIdentity);

    public double Similarity(double[] a, double[] b)
    {
        if (a.Length != b.Length || a.Length == 0) return 0;
        double dot = 0, na = 0, nb = 0;
        for (int i = 0; i < a.Length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
        if (na <= 0 || nb <= 0) return 0;
        return dot / (Math.Sqrt(na) * Math.Sqrt(nb));
    }

    public ChallengeOutcome RunChallenge(string action)
    {
        var openError = TryOpen();
        if (openError is not null) return ChallengeOutcome.Fail("FACE_ENGINE_UNAVAILABLE", openError);

        var behavior = _opt.StubBehavior;
        switch (behavior)
        {
            case "engine_down":
                return ChallengeOutcome.Fail("FACE_ENGINE_UNAVAILABLE", "stub: engine_down");
            case "no_face":
                return ChallengeOutcome.Fail("FACE_NO_FACE", "stub: no_face", samples: 12);
            case "liveness_failed":
                return ChallengeOutcome.Fail("FACE_LIVENESS_FAILED", "stub: liveness_failed", samples: 40);
            case "not_returned":
                return ChallengeOutcome.Fail("FACE_NOT_RETURNED", "stub: not_returned", samples: 30);
            default:
                return new ChallengeOutcome
                {
                    Passed = true,
                    Feature = Derive(_opt.StubIdentity),
                    Diagnostic = "stub: ok",
                    Samples = 24,
                    ElapsedSeconds = 0.1
                };
        }
    }

    /// <summary>把身份字符串确定性派生成 128 维向量（范数量级与真引擎同阶，便于观察日志）。</summary>
    private static double[] Derive(string identity)
    {
        var seed = SHA256.HashData(Encoding.UTF8.GetBytes("face-stub|" + (identity ?? string.Empty)));
        var feature = new double[128];
        for (int i = 0; i < 128; i++)
        {
            // 取 4 字节折成一个 [-1,1) 的浮点，再放大到与真特征相同的量级（范数 ~10）。
            int v = seed[(i * 4) % 32] | (seed[(i * 4 + 1) % 32] << 8)
                  | (seed[(i * 4 + 2) % 32] << 16) | (seed[(i * 4 + 3) % 32] << 24);
            feature[i] = (v / (double)int.MaxValue) * 0.9;
        }
        return feature;
    }
}
