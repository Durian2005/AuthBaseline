namespace AuthServer.Services.Face;

/**
 * 人脸模块的配置。全部有默认值 —— 缺配置时按"可用"启动，
 * 而不是像 pepper/证书那样拒绝启动。
 *
 * 为什么人脸不走"缺配置就拒绝启动"：
 *   人脸是**可选**第二因子。拒绝启动等于让"这台机器没有摄像头"这种
 *   再普通不过的情况把整个认证系统一起拖下线 —— 那是拿可用性换一个
 *   本来就没打算强制的功能。
 * 与之相反的代价必须由调用方承担：引擎不可用时要**明确降级并留痕**
 *   （AuditReason.FaceEngineUnavailable），而不是静默跳过第二因子。
 */
public class FaceOptions
{
    public const string SectionName = "Face";

    /// <summary>总开关。false 时人脸模块整体不参与任何流程（等价于从未实现过）。</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// 引擎落点：cv = 真实 OpenCV 引擎；stub = 假引擎（无摄像头也能跑通流程）。
    ///
    /// 之所以把这件事做成配置而不是编译期分支：回归探针需要在**没有摄像头**的
    /// 环境里验证"口令 → 挑战 → 人脸 → 签票 → 审计"这条链。假引擎让这条链
    /// 可测，而真实引擎的算法正确性由 Stage 0 的对照实验单独保证。
    /// </summary>
    public string Engine { get; set; } = "cv";

    /// <summary>
    /// 强制策略：off | optional | required-for-roles。
    ///
    /// 第一版**只实现 optional**（产品约定：已注册用户可选添加、新注册可选导入、
    /// 管理员一律不强制）。其余取值只做解析与告警，不做强制 ——
    /// 宁可明确"没实现"，也不要留一个看起来能用、实际没人测过的开关。
    /// </summary>
    public string Enforcement { get; set; } = "optional";

    /// <summary>
    /// 余弦相似度判定阈值。默认 0.50，与参考项目 FaceLogin 一致
    /// （SFace 官方值是 0.363，参考项目在 LFW 上评后取 0.5，偏保守一侧）。
    ///
    /// ⚠️ 阈值只对"同一条特征管线"有意义。Stage 0 已验证 C# 管线与 cv2 管线
    ///    在同一输入尺寸下逐位等价（cos = 0.9999），所以这个数字可以直接搬。
    /// </summary>
    public double Threshold { get; set; } = 0.50;

    /// <summary>每人的模板上限。多留几张压低误拒率，但上限越高"碰巧命中"概率越大。</summary>
    public int MaxTemplates { get; set; } = 8;

    /// <summary>
    /// 检测模型（YuNet）。相对路径按 exe 所在目录解析。
    /// ⚠️ 目录叫 `face-models` 而不是 `models`：后者会和 C# 源码目录 `Models` 撞名（Windows 大小写不敏感）。
    /// </summary>
    public string DetectorModel { get; set; } = "face-models/face_detection_yunet_2023mar.onnx";

    /// <summary>特征模型（SFace）。</summary>
    public string RecognizerModel { get; set; } = "face-models/face_recognition_sface_2021dec.onnx";

    public int CameraIndex { get; set; } = 0;

    /// <summary>
    /// 【离线回放】把"读摄像头"换成"读一个目录里的图片序列"。空 = 正常用摄像头。
    ///
    /// 存在的理由：动作挑战的判定逻辑（基线 / 滑窗命中 / 回正 / 跳变）只有在**真实画面**上
    /// 才有意义，而真实画面过去只能靠真机复现 —— 每次改阈值都得把人叫到摄像头前重看一遍，
    /// 而且"当时到底发生了什么"无法回看。录一次帧、之后反复回放，才能把这段逻辑纳入回归。
    ///
    /// ⚠️ 只影响采集源，**不改判定逻辑**：回放走的是 RunChallenge 的同一段代码，
    ///    所以回放通过 ≠ 只是"假引擎放行"，它是真的把 YuNet/SFace 跑了一遍。
    /// ⚠️ 录下来的帧是**真人的脸**。fixture 目录已在 .gitignore 里（tools/fixtures/），
    ///    绝不要把它们提交到公开仓库。
    /// </summary>
    public string ReplayDir { get; set; } = string.Empty;

    /// <summary>
    /// 【录制】把采集到的每一帧顺手写成 JPEG。空 = 不录。
    /// 与 <see cref="ReplayDir"/> 对应：录一次 → 以后反复回放。
    /// </summary>
    public string RecordDir { get; set; } = string.Empty;

    /// <summary>是否处于回放模式。</summary>
    public bool IsReplaying => !string.IsNullOrWhiteSpace(ReplayDir);

    /// <summary>是否处于录制模式。</summary>
    public bool IsRecording => !string.IsNullOrWhiteSpace(RecordDir);

    /// <summary>
    /// 采集分辨率。**必须与检测器预设尺寸一致** ——
    /// OpenCvSharp 的 FaceDetectorYN 没有暴露 setInputSize，输入尺寸与预设不符会直接抛异常。
    /// 反过来，尺寸固定也带来一个好处：录入与验证永远走同一分辨率，
    /// 避免"换个摄像头/换台机器就认不出"（实测跨分辨率比对余弦会掉到 0.59 一线）。
    /// </summary>
    public int CaptureWidth { get; set; } = 640;
    public int CaptureHeight { get; set; } = 480;

    /// <summary>挑战 token 有效期（秒）。</summary>
    public int ChallengeTtlSeconds { get; set; } = 90;

    /// <summary>
    /// 假引擎的"呈现身份"。仅测试用：等于账号用户名时相似度视为通过，
    /// 否则视为不通过。**默认空** ⇒ 假引擎一律判"不匹配"（安全的一侧失败方向）。
    /// </summary>
    public string StubIdentity { get; set; } = string.Empty;

    /// <summary>
    /// 假引擎的行为开关（仅测试用）：ok | liveness_failed | no_face | not_returned | engine_down。
    /// 存在的意义是让回归探针能在**没有摄像头**的环境里分别走到 A 组（计次）与 B 组（不计次）
    /// 的分支 —— 这两组的差异是这个模块最需要被回归覆盖的部分，而它们恰恰最难手工复现。
    /// </summary>
    public string StubBehavior { get; set; } = "ok";

    /// <summary>采集阶段的单次挑战最长秒数。</summary>
    public double MaxChallengeSeconds { get; set; } = 8.0;

    /// <summary>
    /// 环境变量覆盖：安装目录里的配置文件会被覆盖安装冲掉，
    /// 而测试与排障需要"不改配置文件就换行为"。与 EmailOptions 同手法。
    /// </summary>
    public void ApplyEnvironmentOverrides()
    {
        var enabled = Environment.GetEnvironmentVariable("AUTHBASELINE_FACE_ENABLED");
        if (!string.IsNullOrWhiteSpace(enabled))
            Enabled = !enabled.Trim().Equals("false", StringComparison.OrdinalIgnoreCase) && enabled.Trim() != "0";

        var engine = Environment.GetEnvironmentVariable("AUTHBASELINE_FACE_ENGINE");
        if (!string.IsNullOrWhiteSpace(engine)) Engine = engine.Trim();

        var threshold = Environment.GetEnvironmentVariable("AUTHBASELINE_FACE_THRESHOLD");
        if (!string.IsNullOrWhiteSpace(threshold)
            && double.TryParse(threshold.Trim(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var t))
            Threshold = t;

        var stub = Environment.GetEnvironmentVariable("AUTHBASELINE_FACE_STUB_IDENTITY");
        if (stub is not null) StubIdentity = stub.Trim();

        var behavior = Environment.GetEnvironmentVariable("AUTHBASELINE_FACE_STUB_BEHAVIOR");
        if (!string.IsNullOrWhiteSpace(behavior)) StubBehavior = behavior.Trim();

        // 录制 / 回放：同样走环境变量，理由与上面几条一致 ——
        // 安装目录里的 appsettings.json 会被覆盖安装冲掉，而排障时改不了它。
        var replay = Environment.GetEnvironmentVariable("AUTHBASELINE_FACE_REPLAY_DIR");
        if (!string.IsNullOrWhiteSpace(replay)) ReplayDir = replay.Trim();

        var record = Environment.GetEnvironmentVariable("AUTHBASELINE_FACE_RECORD_DIR");
        if (!string.IsNullOrWhiteSpace(record)) RecordDir = record.Trim();
    }

    /// <summary>是否走假引擎。</summary>
    public bool UseStubEngine => string.Equals(Engine, "stub", StringComparison.OrdinalIgnoreCase);

    /// <summary>把模型路径解析成绝对路径（相对路径按 exe 所在目录）。</summary>
    public string ResolveDetector() => Resolve(DetectorModel);
    public string ResolveRecognizer() => Resolve(RecognizerModel);

    private static string Resolve(string path) =>
        Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);
}
