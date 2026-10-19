using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services.FaceId;

/**
 * 纯人脸登录的假引擎：不碰摄像头、不加载模型，但**行为形状与真引擎完全一致**。
 *
 * 它解决的是一个具体的工程问题：本模块里最需要被回归覆盖的，是
 * "用户名 → 采集 → 特征 → 比对 → 签票/不签票 → 审计怎么写"这条链，
 * 以及"计次 / 不计次"的分流。而这些分支恰恰**在有摄像头的开发机上也几乎没法手工复现**。
 * 假引擎让这些分支变成"改一个环境变量就能走到"的确定性路径。
 *
 * 它**不**承担算法正确性的举证责任：那由 P0 Stage 0 的对照实验单独保证
 * （C# 管线与 cv2 管线逐位等价）。
 *
 * 特征由"呈现身份"字符串的 SHA-256 确定性派生 ——
 * 同一个身份两次派生出的向量逐位相同，所以"录入 → 验证"的余弦正好是 1.0；
 * 换一个身份则两个向量近乎正交。这正是真引擎里"本人 / 非本人"的语义。
 * 派生维度取 512，与 ArcFace 真实输出一致（模板里记的 dim 因此两种引擎通用）。
 *
 * ⚠️ 派生必须走"无符号整数 → [-1,1) 线性映射"，**不能**把 4 个字节直接
 *    `BitConverter.ToSingle` 转 float（P0-5 单测钉住，改前先读 Derive 的注释）：
 *    ① 那样约 0.8% 的字节组会解出 NaN/Inf，一个 NaN 就能污染整个点积，
 *       把"同身份余弦 1.0"变成 NaN，本人被 Mismatch 拒掉；
 *    ② float32 位模式量级横跨 1e-38~1e38，余弦被少数极端坐标主导，
 *       实测跨身份余弦最大冲到 0.36，"近乎正交"并不成立。
 */
public sealed class StubFaceIdEngine : IFaceIdEngine
{
    private readonly FaceIdOptions _opt;
    private bool _open;

    public StubFaceIdEngine(FaceIdOptions opt)
    {
        _opt = opt;
        Console.WriteLine("[FaceId] ⚠️ 正在使用**假引擎**（无摄像头/无模型）—— 仅供流程与审计验证");
    }

    public FaceIdEngineStatus Status => string.Equals(_opt.StubBehavior, "engine_down", StringComparison.Ordinal)
        ? FaceIdEngineStatus.Down("假引擎：模拟引擎不可用")
        : FaceIdEngineStatus.Up();

    public string? TryOpen()
    {
        if (string.Equals(_opt.StubBehavior, "engine_down", StringComparison.Ordinal))
            return "假引擎：模拟摄像头不可用";
        _open = true;
        return null;
    }

    public void Close() => _open = false;

    public FaceIdFrame? ReadFrame()
    {
        if (!_open) return null;
        if (string.Equals(_opt.StubBehavior, "engine_down", StringComparison.Ordinal)) return null;
        // Backing 留 null：假引擎没有真实像素，上层也不许去碰它。
        return new FaceIdFrame { Width = _opt.CaptureWidth, Height = _opt.CaptureHeight };
    }

    public FaceIdBox? DetectLargest(FaceIdFrame frame)
    {
        var all = DetectAll(frame);
        FaceIdBox? best = null;
        foreach (var box in all)
            if (best is null || box.W * box.H > best.W * best.H) best = box;
        return best;
    }

    /// <summary>
    /// 假引擎的"数脸"：no_face 返回空，multi_face 返回两张（第二张略小、位置偏右下），
    /// 其余行为返回一张。
    ///
    /// 为什么值得为"两张脸"单独造一个行为：录入闸门里最容易被漏掉的一条就是
    /// "到底把谁的脸存进去了"。这条分支在有真摄像头的机器上也难复现
    /// （需要恰好有第二个人凑进画面），但它是**隐私事故**而不是体验问题。
    /// </summary>
    public IReadOnlyList<FaceIdBox> DetectAll(FaceIdFrame frame)
    {
        if (string.Equals(_opt.StubBehavior, "no_face", StringComparison.Ordinal))
            return Array.Empty<FaceIdBox>();

        var turned = string.Equals(_opt.StubBehavior, "turned", StringComparison.Ordinal);
        var primary = MakeBox(1.0, 0.0, 0.0, turned);

        if (string.Equals(_opt.StubBehavior, "multi_face", StringComparison.Ordinal))
        {
            return new[]
            {
                primary,
                // 第二张脸：0.7 倍大小，往右下挪 —— 面积明显小于主脸，
                // 这样"挑了最大的那张"与"只允许一张"两条分支能被区分开。
                MakeBox(0.7, 0.20, 0.16, false)
            };
        }
        return new[] { primary };
    }

    /// <summary>
    /// 造一张"假脸"。scale 控制相对画面的大小，dx/dy 控制相对中心的位置偏移。
    /// 5 个关键点按参考比例摆好，好让对齐变换不会除零。
    /// </summary>
    private FaceIdBox MakeBox(double scale, double dx, double dy, bool turned)
    {
        double w = _opt.CaptureWidth * 0.35 * scale, h = _opt.CaptureHeight * 0.45 * scale;
        double x = (_opt.CaptureWidth - w) / 2 + _opt.CaptureWidth * dx;
        double y = (_opt.CaptureHeight - h) / 2 + _opt.CaptureHeight * dy;
        double cx = x + w / 2, cy = y + h / 2;

        // turned：鼻尖明显偏向一侧（双眼位置不动）—— 正脸度指标会因此越界。
        double noseDx = turned ? w * 0.22 : 0;
        var pts = new double[]
        {
            cx - w * 0.20, cy - h * 0.10,        // 眼 A
            cx + w * 0.20, cy - h * 0.10,        // 眼 B
            cx + noseDx,   cy + h * 0.05,        // 鼻尖
            cx + w * 0.15, cy + h * 0.28,        // 嘴角 A
            cx - w * 0.15, cy + h * 0.28         // 嘴角 B
        };
        return new FaceIdBox { X = x, Y = y, W = w, H = h, Points = pts, Score = 0.99 };
    }

    public double[]? Feature(FaceIdFrame frame, FaceIdBox box)
    {
        // low_quality：模拟"这一帧不可用"（对齐失败/画面质量不足），
        // 上层据此走"不计次"的质量分支。
        if (string.Equals(_opt.StubBehavior, "low_quality", StringComparison.Ordinal)) return null;
        return Derive(_opt.StubIdentity);
    }

    /// <summary>
    /// 假引擎没有像素，因此默认**测不了**清晰度（返回 null ⇒ 闸门跳过这一项）。
    ///
    /// 唯有 behavior=blurry 时返回一个明确的低值，用来覆盖"糊了要拒"这条分支 ——
    /// 否则质量闸门里有一整条判定在无摄像头的机器上永远走不到。
    /// </summary>
    public double? Sharpness(FaceIdFrame frame, FaceIdBox box) =>
        string.Equals(_opt.StubBehavior, "blurry", StringComparison.Ordinal) ? 2.0 : null;

    /// <summary>
    /// 从身份字符串确定性派生 512 维特征：SHA-256(identity#i) 取 32 字节，
    /// 每 4 字节按**无符号**整数读出后线性映射到 [-1,1)，64 个分组正好 512 维。
    /// </summary>
    /// <remarks>
    /// 为什么不是"每 4 字节直接转 float"（`BitConverter.ToSingle`）——
    /// 这条弯路 P0-5 的单测已经踩过并钉住，改动前务必读完：
    ///   ① **NaN 污染**：哈希字节按 IEEE-754 单精度解释时，约 0.8% 的字节组
    ///      会落在 NaN/Inf 编码区。向量里只要有一个 NaN，点积整体变 NaN，
    ///      "同身份余弦 1.0"的承诺崩塌，本人被 Mismatch 拒在门外。
    ///   ② **量级失控**：float32 位模式横跨约 1e-38~1e38，余弦被少数极端
    ///      坐标主导。实测 190 个跨身份组合里 |cos| 最大 0.36 —— 对默认
    ///      阈值 0.50 虽仍未越界，但"近乎正交"的注释已经是假的，
    ///      而 P3 一旦把阈值往下调，假引擎就会开始假阳性。
    /// 换成均匀映射后：不可能产出非有限值；同身份余弦 = 1.0（双精度 epsilon 内）；
    /// 实测 190 个跨身份组合 |cos| 最大 0.12、均值 0.038。
    /// </remarks>
    internal static double[] Derive(string identity)
    {
        var feature = new double[512];
        for (int i = 0; i < 64; i++)
        {
            var block = SHA256.HashData(Encoding.UTF8.GetBytes($"{identity}#{i}"));
            for (int j = 0; j < 8; j++)
            {
                var u = BitConverter.ToUInt32(block, j * 4);
                feature[i * 8 + j] = u / 2147483648.0 - 1.0;   // [0, 2^32) → [-1, 1)
            }
        }
        return feature;
    }

    public double Similarity(double[] a, double[] b)
    {
        if (a.Length != b.Length || a.Length == 0) return 0;
        double dot = 0, na = 0, nb = 0;
        for (int i = 0; i < a.Length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
        if (na <= 0 || nb <= 0) return 0;
        return dot / (Math.Sqrt(na) * Math.Sqrt(nb));
    }
}
