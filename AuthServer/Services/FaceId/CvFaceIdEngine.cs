using System.Security.Cryptography;
using System.Text;
using OpenCvSharp;
using OpenCvSharp.Dnn;

namespace AuthServer.Services.FaceId;

/**
 * 纯人脸登录的真实引擎：OpenCvSharp 4 的 YuNet 检测 + ArcFace（w600k_r50）特征。
 *
 * 与 2FA 的 <see cref="AuthServer.Services.Face.CvFaceEngine"/> 是两套**独立**实现：
 * 本类刻意重复了摄像头开关、中文路径镜像等代码，而不是 import 那个类 ——
 * 模块边界以"删掉 2FA 时本类零牵连"为准，重复 ~80 行是这个代价换来的。
 * 两套引擎可以同时跑、互不共享实例（各自持有一份检测器与识别器）。
 *
 * 这个文件里的每一个"古怪"写法都对应一个已验证的事实，改动前请先读注释：
 *
 *   ① **检测器不能改输入尺寸。** OpenCvSharp 的 FaceDetectorYN 没有暴露 `setInputSize`，
 *      画面尺寸与 `Create` 预设不符时 OpenCV 直接抛异常（不是自动缩放）。
 *      ⇒ 所以 `Create` 时用的尺寸必须与摄像头采集尺寸一致（见 FaceIdOptions.CaptureWidth/Height）。
 *
 *   ② **ArcFace 的预处理是 (x-127.5)/128 + RGB 序，与 SFace 的 scale=1.0 完全不同。**
 *      参考实现（insightface python 包的 ArcFaceONNX 封装）为：
 *        BlobFromImage(aligned, scale=1/128, size=112x112, mean=127.5, swapRB=true, crop=false)
 *      其中 swapRB=true 负责 BGR→RGB（ArcFace 训练于 RGB）。scale/mean 换一个数值
 *      就会掉到另一条支路（SFace 上实测过：换缩放 ⇒ cos≈0.13）。
 *      这条与 ① 的对齐一起，构成 P0 Stage 0 对照实验的验证对象。
 *
 *   ③ **对齐必须用 LMEDS，不能用默认的 RANSAC。** 5 个点做相似变换时 RANSAC 会给出
 *      一个错解（2FA 的 SFace 上实测对齐图最大差 178 灰阶），LMEDS 才与
 *      cv2.FaceRecognizerSF.alignCrop / insightface 的 estimate_norm 一致。
 *      参考点取 insightface 的 arcface_dst（112x112 画布上的标准五点）。
 *
 *   ④ **特征不做 L2 归一化。** 归一化在比对时做（见 Similarity）。
 *      如果哪天"顺手"把归一化挪进存储，历史模板会全部失效。
 *
 *   ⑤ **中文路径读不了 ONNX。** 路径按 ANSI 编组，含中文时变成乱码文件名。
 *      本项目所在的目录名就含中文，所以必须镜像到 ASCII 目录（见 EnsureAsciiModel）。
 */
public sealed class CvFaceIdEngine : IFaceIdEngine, IDisposable
{
    private readonly FaceIdOptions _opt;
    private readonly object _modelLock = new();
    private readonly object _cameraLock = new();

    private FaceDetectorYN? _detector;
    private Net? _recognizer;
    private VideoCapture? _camera;
    private FaceIdEngineStatus _status = FaceIdEngineStatus.Down("尚未初始化");

    /// <summary>5 个关键点在 112x112 对齐图上的目标位置（insightface arcface_dst）。</summary>
    private static readonly Point2f[] ArcfaceRefPoints =
    {
        new(38.2946f, 51.6963f),
        new(73.5318f, 51.5014f),
        new(56.0252f, 71.7366f),
        new(41.5493f, 92.3655f),
        new(70.7299f, 92.2041f)
    };

    public CvFaceIdEngine(FaceIdOptions opt)
    {
        _opt = opt;
        TryLoadModels();
    }

    public FaceIdEngineStatus Status => _status;

    // ────────────────────────────────────────────── 模型加载

    private void TryLoadModels()
    {
        try
        {
            var detectorPath = EnsureAsciiModel(_opt.ResolveDetector());
            var recognizerPath = EnsureAsciiModel(_opt.ResolveRecognizer());

            if (!File.Exists(detectorPath) || !File.Exists(recognizerPath))
            {
                _status = FaceIdEngineStatus.Down("人脸模型文件缺失");
                Console.WriteLine($"[FaceId] 引擎不可用：模型缺失（{recognizerPath}）");
                return;
            }

            // 触发原生库加载：如果 OpenCvSharp 的原生 DLL 没跟着发布出去，
            // 这里会抛而不是等到用户点"登录"时才炸。
            _ = Cv2.GetVersionString();

            _detector = FaceDetectorYN.Create(detectorPath, string.Empty,
                new Size(_opt.CaptureWidth, _opt.CaptureHeight), 0.6f, 0.3f, 5000);
            _recognizer = CvDnn.ReadNetFromOnnx(recognizerPath);

            _status = FaceIdEngineStatus.Up();
            Console.WriteLine($"[FaceId] 引擎就绪 · OpenCV {Cv2.GetVersionString()} · "
                + $"检测 {_opt.CaptureWidth}x{_opt.CaptureHeight} · 阈值 {_opt.Threshold:F2}"
                + $"（灰区 ±{_opt.GrayBand:F2}）");
        }
        catch (Exception ex)
        {
            // 引擎不可用**不是**致命错误：纯人脸登录是可选登录方式，缺摄像头/缺模型
            // 不该把整个认证系统拖下线。代价是必须显式留痕（P2 的控制器负责写审计），
            // 且**绝不允许**静默降级成"没有人脸也能过人脸登录"。
            _status = FaceIdEngineStatus.Down($"人脸引擎初始化失败：{ex.Message}");
            Console.WriteLine($"[FaceId] 引擎不可用：{ex.Message}");
        }
    }

    /// <summary>
    /// 把含非 ASCII 字符的模型路径镜像到纯 ASCII 目录，返回可用的路径。
    /// （与 2FA 引擎同原因：OpenCV 的 ONNX 读取把路径按 ANSI 编组，中文目录名会变乱码。
    ///  刻意重复而不是共用，是为了模块删除时互不牵连。）
    /// </summary>
    internal static string EnsureAsciiModel(string path)
    {
        if (path.All(c => c < 128)) return path;
        if (!File.Exists(path)) return path;   // 让上层给出"文件缺失"这个更准确的原因

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path)))[..12];
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AuthBaselineData", "faceid-models", hash);
        Directory.CreateDirectory(dir);
        var target = Path.Combine(dir, Path.GetFileName(path));

        var src = new FileInfo(path);
        var dst = new FileInfo(target);
        if (dst.Exists && dst.Length == src.Length) return target;   // 已镜像且大小一致

        File.Copy(path, target, overwrite: true);
        Console.WriteLine($"[FaceId] 模型路径含非 ASCII，已镜像到 {target}");
        return target;
    }

    // ────────────────────────────────────────────── 摄像头

    public string? TryOpen()
    {
        lock (_cameraLock)
        {
            if (_camera is not null && _camera.IsOpened()) return null;
            if (_status.Ready == false) return _status.Message;

            try
            {
                _camera?.Dispose();
                _camera = new VideoCapture(_opt.CameraIndex, VideoCaptureAPIs.DSHOW);
                _camera.Set(VideoCaptureProperties.FrameWidth, _opt.CaptureWidth);
                _camera.Set(VideoCaptureProperties.FrameHeight, _opt.CaptureHeight);
                if (!_camera.IsOpened())
                {
                    _camera.Dispose();
                    _camera = null;
                    return "未检测到可用的摄像头";
                }
                return null;
            }
            catch (Exception ex)
            {
                return $"打开摄像头失败：{ex.Message}";
            }
        }
    }

    public void Close()
    {
        lock (_cameraLock)
        {
            _camera?.Release();
            _camera?.Dispose();
            _camera = null;
        }
    }

    public FaceIdFrame? ReadFrame()
    {
        lock (_cameraLock)
        {
            if (_camera is null || !_camera.IsOpened()) return null;
            var frame = new Mat();
            if (!_camera.Read(frame) || frame.Empty())
            {
                frame.Dispose();
                return null;
            }
            return new FaceIdFrame { Width = frame.Width, Height = frame.Height, Backing = frame };
        }
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
    /// 检测全部人脸。与 <see cref="DetectLargest"/> 共用同一段实现（DetectAllInternal），
    /// 避免"录入时数脸"和"登录时挑脸"两套检测参数悄悄走偏 ——
    /// 两边一旦不一致，会出现"录入说有 1 张脸、登录却检出 2 张"这种无法归因的怪事。
    /// </summary>
    public IReadOnlyList<FaceIdBox> DetectAll(FaceIdFrame frame)
    {
        if (frame.Backing is not Mat mat) return Array.Empty<FaceIdBox>();
        return DetectAllInternal(mat);
    }

    private List<FaceIdBox> DetectAllInternal(Mat mat)
    {
        lock (_modelLock)
        {
            if (_detector is null) return new List<FaceIdBox>();
            // ⚠️ 尺寸不符会直接抛（见类头 ①）。采集尺寸由 FaceIdOptions 固定为同一值，
            //    这里再兜一层：不匹配时显式缩放，宁可略损精度也不要抛异常。
            Mat input = mat;
            bool resized = false;
            if (mat.Width != _opt.CaptureWidth || mat.Height != _opt.CaptureHeight)
            {
                input = new Mat();
                Cv2.Resize(mat, input, new Size(_opt.CaptureWidth, _opt.CaptureHeight));
                resized = true;
            }

            try
            {
                using var faces = new Mat();
                _detector.Detect(input, faces);
                var found = new List<FaceIdBox>(faces.Rows);
                if (faces.Rows == 0) return found;

                for (int r = 0; r < faces.Rows; r++)
                {
                    double x = faces.At<float>(r, 0), y = faces.At<float>(r, 1);
                    double w = faces.At<float>(r, 2), h = faces.At<float>(r, 3);
                    var pts = new double[10];
                    for (int i = 0; i < 10; i++) pts[i] = faces.At<float>(r, 4 + i);

                    // 缩放兜底时把坐标映射回原帧，避免上层拿到两套坐标系。
                    if (resized)
                    {
                        double sx = (double)mat.Width / _opt.CaptureWidth;
                        double sy = (double)mat.Height / _opt.CaptureHeight;
                        x *= sx; y *= sy; w *= sx; h *= sy;
                        for (int i = 0; i < 5; i++) { pts[i * 2] *= sx; pts[i * 2 + 1] *= sy; }
                    }

                    found.Add(new FaceIdBox
                    {
                        X = x, Y = y, W = w, H = h, Points = pts,
                        Score = faces.At<float>(r, 14)
                    });
                }
                return found;
            }
            finally
            {
                if (resized) input.Dispose();
            }
        }
    }

    // ────────────────────────────────────────────── 特征

    public double[]? Feature(FaceIdFrame frame, FaceIdBox box)
    {
        if (frame.Backing is not Mat mat) return null;
        lock (_modelLock)
        {
            if (_recognizer is null) return null;

            var src = new Point2f[5];
            for (int i = 0; i < 5; i++) src[i] = new Point2f((float)box.Points[i * 2], (float)box.Points[i * 2 + 1]);

            // ③ 对齐：LMEDS 而不是默认 RANSAC（见类头 ③）
            using var srcMat = Mat.FromArray(src);
            using var dstMat = Mat.FromArray(ArcfaceRefPoints);
            using Mat? m = Cv2.EstimateAffinePartial2D(srcMat, dstMat, null, RobustEstimationAlgorithms.LMEDS);
            // 相似变换解不出来（关键点退化）⇒ 这一帧不可用。不能把空矩阵丢给 WarpAffine，
            // 那会得到一张全黑的"对齐图"，再算出一段毫无意义的特征 —— 然后表现为"人脸不匹配"，
            // 把一次坐标退化伪装成一次认证失败。
            if (m is null || m.Empty()) return null;

            using var aligned = new Mat();
            Cv2.WarpAffine(mat, aligned, m, new Size(112, 112));

            // ② 特征：scale=1/128 / mean=127.5 / swapRB=true —— 一个字都不能改（见类头 ②）
            using Mat blob = CvDnn.BlobFromImage(aligned, 1.0 / 128.0, new Size(112, 112),
                new Scalar(127.5, 127.5, 127.5), true, false);
            _recognizer.SetInput(blob);
            using Mat output = _recognizer.Forward();

            int n = (int)output.Total();
            if (n == 0) return null;
            var feature = new double[n];
            for (int i = 0; i < n; i++) feature[i] = output.At<float>(0, i);
            return feature;
        }
    }

    /// <summary>
    /// 脸框内的清晰度：灰度拉普拉斯响应的方差。
    ///
    /// 为什么是"方差"而不是"平均梯度"：平均梯度会被整张脸的明暗对比主导
    /// （白墙前的人脸天然梯度大），而方差反映的是**高频细节保留了多少** ——
    /// 失焦/运动模糊恰好是高频被抹掉，方差随之塌下去。这也是 OpenCV 社区里
    /// 最常用的失焦度量，够用且不需要额外模型。
    ///
    /// 只在脸框内算，不取整帧：背景的纹理不该参与"这张脸糊没糊"的判断。
    /// 返回 null 表示**测不了**（框越界/太小、矩阵不可用），而不是"很差"。
    /// </summary>
    public double? Sharpness(FaceIdFrame frame, FaceIdBox box)
    {
        if (frame.Backing is not Mat mat || mat.Empty()) return null;

        int x = Math.Max(0, (int)Math.Round(box.X));
        int y = Math.Max(0, (int)Math.Round(box.Y));
        int w = Math.Min(mat.Width - x, (int)Math.Round(box.W));
        int h = Math.Min(mat.Height - y, (int)Math.Round(box.H));
        if (w < 8 || h < 8) return null;   // 框太小，方差没有统计意义

        try
        {
            using var roi = new Mat(mat, new Rect(x, y, w, h));
            using var gray = new Mat();
            Cv2.CvtColor(roi, gray, ColorConversionCodes.BGR2GRAY);
            using var lap = new Mat();
            Cv2.Laplacian(gray, lap, MatType.CV_64F);
            Cv2.MeanStdDev(lap, out _, out var stddev);
            var variance = stddev.Val0 * stddev.Val0;
            return double.IsFinite(variance) ? variance : null;
        }
        catch (Exception)
        {
            // 这里刻意吞掉异常：清晰度只是闸门里的一项，测不了就不该把整次录入打挂。
            // 上层会把 null 当作"跳过这一项"，而不是"不合格"（见 IFaceIdEngine.Sharpness）。
            return null;
        }
    }

    public double Similarity(double[] a, double[] b)
    {
        if (a.Length != b.Length || a.Length == 0) return 0;
        double dot = 0, na = 0, nb = 0;
        for (int i = 0; i < a.Length; i++)
        {
            dot += a[i] * b[i];
            na += a[i] * a[i];
            nb += b[i] * b[i];
        }
        if (na <= 0 || nb <= 0) return 0;
        return dot / (Math.Sqrt(na) * Math.Sqrt(nb));
    }

    public void Dispose()
    {
        Close();
        lock (_modelLock)
        {
            _detector?.Dispose();
            _detector = null;
            _recognizer?.Dispose();
            _recognizer = null;
        }
    }
}
