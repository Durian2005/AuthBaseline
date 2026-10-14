using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using OpenCvSharp;
using OpenCvSharp.Dnn;

namespace AuthServer.Services.Face;

/**
 * 真实引擎：OpenCvSharp 4 的 YuNet 检测 + SFace 特征。
 *
 * 这个文件里的每一个"古怪"写法都对应 Stage 0 实测到的一个事实，改动前请先读注释：
 *
 *   ① **检测器不能改输入尺寸。** OpenCvSharp 的 FaceDetectorYN 没有暴露 `setInputSize`，
 *      画面尺寸与 `Create` 预设不符时 OpenCV 直接抛异常（不是自动缩放）。
 *      ⇒ 所以 `Create` 时用的尺寸必须与摄像头采集尺寸一致（见 FaceOptions.CaptureWidth/Height）。
 *      同尺寸下 C# 与 Python cv2 的检测输出逐位一致（实测最大误差 4.3e-5）。
 *
 *   ② **SFace 在主包里没有绑定。** OpenCvSharp4 只到 LBPH/Fisher/Eigen，没有 FaceRecognizerSF。
 *      但 SFace 就是个普通 ONNX，用 CvDnn 直跑结果与 cv2 逐位等价：
 *        BlobFromImage(aligned, scale=1.0, size=112x112, mean=0, swapRB=true, crop=false)
 *        ⇒ 与 cv2.FaceRecognizerSF.feature() 的余弦 = 1.00000000（实测）。
 *      注意 scale=1.0 而**不是** 1/255 —— 换一个缩放就会掉到 cos≈0.13，是彻底另一条支路。
 *
 *   ③ **对齐必须用 LMEDS，不能用默认的 RANSAC。** 5 个点做相似变换时 RANSAC 会给出
 *      一个错解（实测对齐图最大差 178 灰阶），LMEDS 才与 cv2.FaceRecognizerSF.alignCrop 一致
 *      （实测最大差 2 灰阶，纯舍入）。
 *
 *   ④ **特征不做 L2 归一化。** cv2 与 C# 的输出范数都在 10 上下，归一化在比对时做。
 *      如果哪天"顺手"把归一化挪进存储，历史模板会全部失效。
 *
 *   ⑤ **中文路径读不了 YuNet 的 ONNX。** 路径按 ANSI 编组，含中文时变成乱码文件名。
 *      本项目所在的目录名就含中文，所以必须镜像到 ASCII 目录（见 EnsureAsciiModel）。
 */
public sealed class CvFaceEngine : IFaceEngine, IDisposable
{
    private readonly FaceOptions _opt;
    private readonly object _modelLock = new();
    private readonly object _cameraLock = new();

    /// <summary>
    /// 预览帧的落点。可为 null（探针会直接 new 一个引擎来量算法，不需要界面）。
    /// 采集期间由本引擎推帧 —— 那几秒里摄像头归它独占，读到的就是判定用的那一帧。
    /// </summary>
    private readonly FacePreviewService? _preview;

    private FaceDetectorYN? _detector;
    private Net? _recognizer;
    private VideoCapture? _camera;
    private FaceEngineStatus _status = FaceEngineStatus.Down("尚未初始化");
    private string _detectorPath = string.Empty;
    private string _recognizerPath = string.Empty;

    /// <summary>5 个关键点在 112x112 对齐图上的目标位置（SFace 官方参考点）。</summary>
    private static readonly Point2f[] SfaceRefPoints =
    {
        new(38.2946f, 51.6963f),
        new(73.5318f, 51.5014f),
        new(56.0252f, 71.7366f),
        new(41.5493f, 92.3655f),
        new(70.7299f, 92.2041f)
    };

    public CvFaceEngine(FaceOptions opt, FacePreviewService? preview = null)
    {
        _opt = opt;
        _preview = preview;
        TryLoadModels();
    }

    public FaceEngineStatus Status => _status;

    // ────────────────────────────────────────────── 模型加载

    private void TryLoadModels()
    {
        try
        {
            _detectorPath = EnsureAsciiModel(_opt.ResolveDetector());
            _recognizerPath = EnsureAsciiModel(_opt.ResolveRecognizer());

            if (!File.Exists(_detectorPath) || !File.Exists(_recognizerPath))
            {
                _status = FaceEngineStatus.Down("人脸模型文件缺失");
                Console.WriteLine($"[Face] 引擎不可用：模型缺失（{_detectorPath}）");
                return;
            }

            // 触发原生库加载：如果 OpenCvSharp 的原生 DLL 没跟着发布出去，
            // 这里会抛而不是等到用户点"验证"时才炸。
            _ = Cv2.GetVersionString();

            _detector = FaceDetectorYN.Create(_detectorPath, string.Empty,
                new Size(_opt.CaptureWidth, _opt.CaptureHeight), 0.6f, 0.3f, 5000);
            _recognizer = CvDnn.ReadNetFromOnnx(_recognizerPath);

            _status = FaceEngineStatus.Up();
            Console.WriteLine($"[Face] 引擎就绪 · OpenCV {Cv2.GetVersionString()} · "
                + $"检测 {_opt.CaptureWidth}x{_opt.CaptureHeight} · 阈值 {_opt.Threshold:F2}");
        }
        catch (Exception ex)
        {
            // 引擎不可用**不是**致命错误：人脸是可选第二因子，缺摄像头/缺模型
            // 不该把整个认证系统拖下线。代价是必须显式留痕（AuditReason.FaceEngineUnavailable）。
            _status = FaceEngineStatus.Down($"人脸引擎初始化失败：{ex.Message}");
            Console.WriteLine($"[Face] 引擎不可用：{ex.Message}");
        }
    }

    /// <summary>
    /// 把含非 ASCII 字符的模型路径镜像到纯 ASCII 目录，返回可用的路径。
    ///
    /// OpenCV 的 ONNX 读取把路径按 ANSI 编组；路径里只要有一段是中文
    /// （如 `\某中文目录\model.onnx`），就会被解成一串乱码文件名，
    /// 然后报"文件不存在" —— 报错信息还会把乱码显示出来，极易被误判成"文件真的不在"。
    /// 本机项目目录名恰好就是中文，所以这个分支在开发机上必然走到。
    /// </summary>
    internal static string EnsureAsciiModel(string path)
    {
        if (path.All(c => c < 128)) return path;
        if (!File.Exists(path)) return path;   // 让上层给出"文件缺失"这个更准确的原因

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path)))[..12];
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AuthBaselineData", "face-models", hash);
        Directory.CreateDirectory(dir);
        var target = Path.Combine(dir, Path.GetFileName(path));

        var src = new FileInfo(path);
        var dst = new FileInfo(target);
        if (dst.Exists && dst.Length == src.Length) return target;   // 已镜像且大小一致

        File.Copy(path, target, overwrite: true);
        Console.WriteLine($"[Face] 模型路径含非 ASCII，已镜像到 {target}");
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

    private Mat? ReadRaw()
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
            return frame;
        }
    }

    public FaceFrame? ReadFrame()
    {
        var mat = ReadRaw();
        if (mat is null) return null;
        return new FaceFrame { Width = mat.Width, Height = mat.Height, Backing = mat };
    }

    public FaceBox? DetectLargest(FaceFrame frame)
    {
        if (frame.Backing is not Mat mat) return null;
        lock (_modelLock)
        {
            if (_detector is null) return null;
            // ⚠️ 尺寸不符会直接抛（见类头 ①）。采集尺寸由 FaceOptions 固定为同一值，
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
                if (faces.Rows == 0) return null;

                FaceBox? best = null;
                for (int r = 0; r < faces.Rows; r++)
                {
                    double x = faces.At<float>(r, 0), y = faces.At<float>(r, 1);
                    double w = faces.At<float>(r, 2), h = faces.At<float>(r, 3);
                    var pts = new double[10];
                    for (int i = 0; i < 10; i++) pts[i] = faces.At<float>(r, 4 + i);

                    // 缩放兜底时把坐标映射回原帧，避免上层拿到两套坐标系。
                    double sx = resized ? (double)mat.Width / _opt.CaptureWidth : 1.0;
                    double sy = resized ? (double)mat.Height / _opt.CaptureHeight : 1.0;
                    if (resized)
                    {
                        x *= sx; y *= sy; w *= sx; h *= sy;
                        for (int i = 0; i < 5; i++) { pts[i * 2] *= sx; pts[i * 2 + 1] *= sy; }
                    }

                    var box = new FaceBox
                    {
                        X = x, Y = y, W = w, H = h, Points = pts,
                        Score = faces.At<float>(r, 14)
                    };
                    if (best is null || box.W * box.H > best.W * best.H) best = box;
                }
                return best;
            }
            finally
            {
                if (resized) input.Dispose();
            }
        }
    }

    // ────────────────────────────────────────────── 预览

    /**
     * 取一张带标注的预览 JPEG。**只服务于界面显示，不参与任何判定。**
     *
     * 与 RunChallenge 的边界刻意划清：
     *   · 这里不做活体、不比对模板、不产生特征、不写审计；
     *   · 失败一律返回 null（含"引擎未就绪"），由调用方翻成"暂无画面"，
     *     绝不用一张占位图冒充"这是你现在的样子"。
     *
     * 摄像头不在这里 Close()：预览是连续取帧，每帧开关一次设备既慢
     * （DSHOW 打开要几百毫秒）也没有意义。空闲释放由 FacePreviewService
     * 在"没有有效 token"时统一负责。
     */
    public FacePreviewFrame? SnapshotPreview()
    {
        if (!_status.Ready) return null;

        var openError = TryOpen();
        if (openError is not null)
        {
            // 引擎就绪但设备打不开（被别的程序占用 / 没有摄像头）：
            // 给一张写明原因的占位图，比让界面一直空着更容易定位问题。
            return new FacePreviewFrame(
                FacePreviewEncoder.Placeholder(_opt.CaptureWidth, _opt.CaptureHeight, "CAMERA UNAVAILABLE"),
                FacePreviewFrame.StateDown, null, DateTime.UtcNow);
        }

        using var mat = ReadRaw();
        if (mat is null) return null;

        var box = DetectLargest(new FaceFrame { Width = mat.Width, Height = mat.Height, Backing = mat });
        var state = box is null ? FacePreviewFrame.StateNoFace : FacePreviewFrame.StateDetected;
        return new FacePreviewFrame(FacePreviewEncoder.Annotate(mat, box, state), state,
            box?.Score, DateTime.UtcNow);
    }

    // ────────────────────────────────────────────── 特征

    public double[]? Feature(FaceFrame frame, FaceBox box)
    {
        if (frame.Backing is not Mat mat) return null;
        lock (_modelLock)
        {
            if (_recognizer is null) return null;

            var src = new Point2f[5];
            for (int i = 0; i < 5; i++) src[i] = new Point2f((float)box.Points[i * 2], (float)box.Points[i * 2 + 1]);

            // ② 对齐：LMEDS 而不是默认 RANSAC（见类头 ③）
            using var srcMat = Mat.FromArray(src);
            using var dstMat = Mat.FromArray(SfaceRefPoints);
            using Mat? m = Cv2.EstimateAffinePartial2D(srcMat, dstMat, null, RobustEstimationAlgorithms.LMEDS);
            // 相似变换解不出来（关键点退化）⇒ 这一帧不可用。不能把空矩阵丢给 WarpAffine，
            // 那会得到一张全黑的"对齐图"，再算出一段毫无意义的特征 —— 然后表现为"人脸不匹配"，
            // 把一次坐标退化伪装成一次认证失败。
            if (m is null || m.Empty()) return null;

            using var aligned = new Mat();
            Cv2.WarpAffine(mat, aligned, m, new Size(112, 112));

            // ③ 特征：scale=1.0 / swapRB=true / mean=0 / crop=false —— 一个字都不能改
            using Mat blob = CvDnn.BlobFromImage(aligned, 1.0, new Size(112, 112), new Scalar(0, 0, 0), true, false);
            _recognizer.SetInput(blob);
            using Mat output = _recognizer.Forward();

            int n = (int)output.Total();
            if (n == 0) return null;
            var feature = new double[n];
            for (int i = 0; i < n; i++) feature[i] = output.At<float>(0, i);
            return feature;
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

    // ────────────────────────────────────────────── 动作挑战

    /// <summary>
    /// 分三阶段采样：① 求基线 ② 等动作出现 ③ 等回正并从那一帧提特征。
    ///
    /// 为什么非要"回正"那一帧：动作做到位时脸是侧着的，用侧脸提的特征去跟正规录入的
    /// 模板比，本身就会掉分。而且这一步顺带保证"通过动作的脸"和"用于比对的脸"
    /// 来自**同一段连续画面** —— 否则可以拿一段预录动作来过活体、再用另一张照片来做比对。
    /// </summary>
    public ChallengeOutcome RunChallenge(string action)
    {
        var sw = Stopwatch.StartNew();
        var baseYawSamples = new List<double>();
        var basePitchSamples = new List<double>();
        double? baseYaw = null, basePitch = null;

        var hits = new Queue<int>();
        int neutralRun = 0, miss = 0, jumps = 0, samples = 0, framesRead = 0;
        bool actionSeen = false;
        (double cx, double cy)? prevCenter = null;
        (double Cost, FaceFrame Frame, FaceBox Box)? best = null;

        double minDy = 0, maxDy = 0, minDp = 0, maxDp = 0, faceWidth = 0;

        string Diag()
        {
            var b = new StringBuilder();
            b.Append($"elapsed {sw.Elapsed.TotalSeconds:F1}s samples {samples} frames {framesRead} miss {miss} jumps {jumps}");
            b.Append($" yaw {minDy:+0.00;-0.00}..{maxDy:+0.00;-0.00} pitch {minDp:+0.00;-0.00}..{maxDp:+0.00;-0.00}");
            b.Append(baseYaw is null ? " base n/a" : $" base {baseYaw:+0.00;-0.00}/{basePitch:+0.00;-0.00}");
            b.Append($" faceW {faceWidth:F0} actionSeen {actionSeen}");
            return b.ToString();
        }

        /**
         * 采集期间把画面推给界面。用的是**判定用的那一帧**（所见即所判），
         * 但只在副本上画框 —— 在原图上画会把框的像素喂进后面的对齐与特征提取。
         *
         * 限流到约 10 帧/秒：采样是 14Hz，逐帧编码 JPEG 只是白烧 CPU，
         * 而人眼在 640x480 上分不出 10 与 14 的差别。
         */
        double lastPreviewAt = -1.0;
        void PublishPreview(FaceFrame? f, FaceBox? b)
        {
            if (_preview is null || f?.Backing is not Mat pm) return;
            if (sw.Elapsed.TotalSeconds - lastPreviewAt < 0.1) return;
            lastPreviewAt = sw.Elapsed.TotalSeconds;

            var state = b is null
                ? FacePreviewFrame.StateNoFace
                : (actionSeen ? FacePreviewFrame.StateReturned : FacePreviewFrame.StateAction);
            try
            {
                _preview.Publish(new FacePreviewFrame(
                    FacePreviewEncoder.Annotate(pm, b, state), state, b?.Score, DateTime.UtcNow));
            }
            catch (Exception ex)
            {
                // 推帧失败不影响判定本身 —— 采集循环必须继续走完
                Console.WriteLine($"[Face] 采集期推帧失败：{ex.Message}");
            }
        }

        try
        {
            var openError = TryOpen();
            if (openError is not null)
                return ChallengeOutcome.Fail("FACE_ENGINE_UNAVAILABLE", openError);

            while (sw.Elapsed.TotalSeconds < _opt.MaxChallengeSeconds)
            {
                var frame = ReadFrame();
                var box = frame is null ? null : DetectLargest(frame);
                if (frame is not null) framesRead++;

                if (box is null)
                {
                    PublishPreview(frame, null);
                    if (frame?.Backing is IDisposable d) d.Dispose();
                    miss++;
                    if (miss >= FacePose.MaxMiss)
                    {
                        // 一帧都没读到 = 设备/引擎问题（不计次）；读到过帧但一直没脸 = 人没坐好（不计次）。
                        // 两者都不该计失败：它们不是攻击信号。
                        var code = framesRead == 0 ? "FACE_ENGINE_UNAVAILABLE" : "FACE_NO_FACE";
                        return ChallengeOutcome.Fail(code, Diag(), samples, miss, jumps, sw.Elapsed.TotalSeconds);
                    }
                    Thread.Sleep((int)(FacePose.SampleIntervalSeconds * 1000));
                    continue;
                }
                miss = 0;

                // 跳变检测：正常转头时人脸中心连续移动；被换成另一路视频 / 换张照片
                // 会表现为突然的整体位移。属启发式，只拦明显跳变（宁可漏也不能误伤）。
                faceWidth = box.W > 0 ? box.W : 1.0;
                var center = (box.CenterX, box.CenterY);
                if (prevCenter is not null)
                {
                    double dist = Math.Sqrt(Math.Pow(center.Item1 - prevCenter.Value.cx, 2)
                                          + Math.Pow(center.Item2 - prevCenter.Value.cy, 2));
                    if (dist / faceWidth > FacePose.JumpRatio)
                    {
                        jumps++;
                        if (jumps > FacePose.MaxJumps)
                        {
                            if (frame?.Backing is IDisposable dj) dj.Dispose();
                            return ChallengeOutcome.Fail("FACE_LIVENESS_FAILED", Diag(), samples, miss, jumps,
                                sw.Elapsed.TotalSeconds);
                        }
                    }
                }
                prevCenter = center;

                var (yaw, pitch, _) = FacePose.Metrics(box);
                samples++;
                PublishPreview(frame, box);

                if (baseYaw is null)
                {
                    baseYawSamples.Add(yaw);
                    basePitchSamples.Add(pitch);
                    if (baseYawSamples.Count >= FacePose.BaselineFrames)
                    {
                        baseYaw = FacePose.Median(baseYawSamples);
                        basePitch = FacePose.Median(basePitchSamples);
                    }
                    if (frame?.Backing is IDisposable db) db.Dispose();
                    Thread.Sleep((int)(FacePose.SampleIntervalSeconds * 1000));
                    continue;
                }

                double dy = yaw - baseYaw.Value;
                double dp = pitch - basePitch!.Value;
                maxDy = Math.Max(maxDy, dy); minDy = Math.Min(minDy, dy);
                maxDp = Math.Max(maxDp, dp); minDp = Math.Min(minDp, dp);

                if (!actionSeen)
                {
                    hits.Enqueue(FacePose.Satisfied(action, dy, dp) ? 1 : 0);
                    while (hits.Count > FacePose.HitWindow) hits.Dequeue();
                    if (hits.Sum() >= FacePose.HitNeeded)
                    {
                        actionSeen = true;
                        neutralRun = 0;
                    }
                }
                else
                {
                    if (FacePose.IsNeutral(dy, dp))
                    {
                        neutralRun++;
                        double cost = Math.Abs(dy) + Math.Abs(dp);
                        if (best is null || cost < best.Value.Cost)
                        {
                            if (best?.Frame.Backing is IDisposable old) old.Dispose();
                            best = (cost, frame!, box);
                            frame = null;   // 交给 best 持有，别在这里释放
                        }
                    }
                    else
                    {
                        neutralRun = 0;
                    }
                    if (neutralRun >= FacePose.NeutralFrames) break;
                }

                if (frame?.Backing is IDisposable df) df.Dispose();
                Thread.Sleep((int)(FacePose.SampleIntervalSeconds * 1000));
            }

            if (samples < FacePose.MinSamples)
                return ChallengeOutcome.Fail("FACE_LOW_QUALITY",
                    "有效帧不足（" + Diag() + "）", samples, miss, jumps, sw.Elapsed.TotalSeconds);

            if (!actionSeen)
                return ChallengeOutcome.Fail("FACE_LIVENESS_FAILED",
                    "未观察到动作（" + Diag() + "）", samples, miss, jumps, sw.Elapsed.TotalSeconds);

            if (neutralRun < FacePose.NeutralFrames || best is null)
                return ChallengeOutcome.Fail("FACE_NOT_RETURNED",
                    "动作后未回正（" + Diag() + "）", samples, miss, jumps, sw.Elapsed.TotalSeconds);

            var feature = Feature(best.Value.Frame, best.Value.Box);
            if (feature is null)
                return ChallengeOutcome.Fail("FACE_NO_FACE",
                    "取特征失败（" + Diag() + "）", samples, miss, jumps, sw.Elapsed.TotalSeconds);

            return new ChallengeOutcome
            {
                Passed = true,
                Feature = feature,
                Diagnostic = Diag(),
                Samples = samples,
                Misses = miss,
                Jumps = jumps,
                ElapsedSeconds = sw.Elapsed.TotalSeconds
            };
        }
        finally
        {
            if (best?.Frame.Backing is IDisposable d) d.Dispose();
            Close();
        }
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
