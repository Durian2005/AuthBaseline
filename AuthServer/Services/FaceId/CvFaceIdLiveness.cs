using OpenCvSharp;
using OpenCvSharp.Dnn;

namespace AuthServer.Services.FaceId;

/**
 * 基于 MiniFASNetV2（Silent-Face-Anti-Spoofing，Apache-2.0）的活体判定。
 *
 * ⚠️⚠️ **预处理是这套分数的地基，一个字都不能改**（改了分数就不再有意义）：
 *   · 裁剪：以检测框中心扩 **2.7 倍**（上游文件名里的 2.7 就是这个数），clamp 到画面内；
 *   · 尺寸：resize 到 **80×80**，**不做五点对齐**（这个模型是在"原样裁块"上训练的，
 *           先做对齐反而会破坏它依赖的纹理/边框线索）；
 *   · 通道：**BGR**，且**不交换 R/B**（与上游 cv2.imread 的次序一致）；
 *   · 数值：**保持 0–255，绝不除 255**；
 *   · 布局：NCHW（BlobFromImage 默认就是 NCHW）。
 *
 *   实测依据（2026-10-19，46 帧真人样本）：除 255 之后，真人帧被判成 replay 的概率
 *   ≈0.99；保持 0–255 时 live≈0.88。换句话说"除 255"这个看似无害的惯例，
 *   会让**本人永远录不进去**。这条结论只针对于本权重，换模型必须重新标定。
 *
 * 输出：3 类 softmax = [print（打印照片）, live（真人）, replay（屏幕回放）]。
 *   索引顺序来自上游训练标签（print=0, real=1, replay=2），不是我们排的。
 *   活体分数取 p[live]；另两类之和就是"疑似攻击"的置信度。
 *
 * 不可用时**整体降级为 fail closed**：Score 返回 null，调用方必须拒绝操作。
 * 绝不"模型没了就当真人"——那会让卸载模型文件变成一种绕过手段。
 */
public sealed class CvFaceIdLiveness : IFaceIdLiveness
{
    /// <summary>模型输入边长。权重是固定 80×80 训练的。</summary>
    private const int InputSize = 80;

    /// <summary>裁剪倍数，见类头红线。这里是常量而**不是配置项**，避免被随手调。</summary>
    private const double CropScale = 2.7;

    /// <summary>三分类里 live 的下标（[print, live, replay]）。</summary>
    private const int LiveIndex = 1;

    private readonly FaceIdOptions _opt;
    private readonly object _lock = new();

    private Net? _net;

    public CvFaceIdLiveness(FaceIdOptions opt)
    {
        _opt = opt;
        TryLoad();
    }

    public FaceIdLivenessStatus Status { get; private set; } = FaceIdLivenessStatus.Down("未初始化");

    private void TryLoad()
    {
        try
        {
            // OpenCV 的 ONNX 读取按 ANSI 编组路径，中文目录会变乱码（同 2FA/FaceId 引擎）。
            var path = CvFaceIdEngine.EnsureAsciiModel(_opt.ResolvePadModel());
            if (!File.Exists(path))
            {
                Status = FaceIdLivenessStatus.Down("活体模型文件缺失");
                Console.WriteLine($"[FaceId] 活体判定不可用：模型缺失（{path}）");
                return;
            }

            _ = Cv2.GetVersionString();
            _net = CvDnn.ReadNetFromOnnx(path);
            Status = FaceIdLivenessStatus.Up();
            Console.WriteLine($"[FaceId] 活体判定就绪 · MiniFASNetV2 · 阈值 {_opt.PadMinLive:F2}");
        }
        catch (Exception ex)
        {
            _net = null;
            Status = FaceIdLivenessStatus.Down($"活体模型加载失败：{ex.Message}");
            Console.WriteLine($"[FaceId] 活体判定不可用：{ex.Message}");
        }
    }

    public double? Score(FaceIdFrame frame, FaceIdBox box)
    {
        if (_net is null) return null;
        if (frame.Backing is not Mat mat || mat.Empty()) return null;

        using var crop = CropAround(mat, box);
        if (crop is null || crop.Empty()) return null;

        double[] probs;
        lock (_lock)
        {
            try
            {
                // scale = 1.0 ⇒ 保持 0–255（红线，见类头）。
                using var blob = CvDnn.BlobFromImage(crop, 1.0, new Size(InputSize, InputSize),
                    new Scalar(0, 0, 0), swapRB: false, crop: false);
                _net.SetInput(blob);
                using var output = _net.Forward();
                using var flat = output.Reshape(1, 1);
                if (flat.Cols < 3) return null;
                probs = Softmax(new[]
                {
                    (double)flat.At<float>(0, 0),
                    (double)flat.At<float>(0, 1),
                    (double)flat.At<float>(0, 2)
                });
            }
            catch (Exception ex)
            {
                // 单帧失败不该把整次录入打死：调用方会当作"这一帧没给出结论"继续读下一帧。
                Console.WriteLine($"[FaceId] 活体判定单帧异常：{ex.Message}");
                return null;
            }
        }

        var live = probs[LiveIndex];
        // NaN/Inf 一律当作"没有结论"，由调用方 fail closed（绝不返回一个"看起来很高"的值）。
        return double.IsFinite(live) ? Math.Clamp(live, 0.0, 1.0) : null;
    }

    /// <summary>
    /// 以人脸框中心扩 <see cref="CropScale"/> 倍后裁剪，越界部分夹到画面内。
    ///
    /// 取整方式刻意与上游 Python 的 <c>int()</c> 一致（向零截断），
    /// 这样 C# 与 Python 参考实现在同一帧上裁出的像素区域完全相同 ——
    /// 否则 Stage 0 那种"逐位对照"会因为一个像素的偏移而永远差一点点。
    /// </summary>
    private static Mat? CropAround(Mat src, FaceIdBox box)
    {
        double cx = box.X + box.W / 2.0;
        double cy = box.Y + box.H / 2.0;
        double halfW = box.W * CropScale / 2.0;
        double halfH = box.H * CropScale / 2.0;

        int x1 = Math.Max(0, (int)(cx - halfW));
        int y1 = Math.Max(0, (int)(cy - halfH));
        int x2 = Math.Min(src.Width, (int)(cx + halfW));
        int y2 = Math.Min(src.Height, (int)(cy + halfH));
        if (x2 - x1 < 8 || y2 - y1 < 8) return null;

        return new Mat(src, new Rect(x1, y1, x2 - x1, y2 - y1));
    }

    private static double[] Softmax(double[] logits)
    {
        var max = double.NegativeInfinity;
        foreach (var v in logits) if (v > max) max = v;

        var sum = 0.0;
        var exp = new double[logits.Length];
        for (int i = 0; i < logits.Length; i++)
        {
            exp[i] = Math.Exp(logits[i] - max);
            sum += exp[i];
        }
        for (int i = 0; i < exp.Length; i++) exp[i] /= sum;
        return exp;
    }
}
