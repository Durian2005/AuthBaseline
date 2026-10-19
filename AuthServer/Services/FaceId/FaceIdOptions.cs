namespace AuthServer.Services.FaceId;

/**
 * 纯人脸登录模块（FaceId）的配置。全部有默认值 —— 缺配置时按"可用"启动，
 * 而不是像 pepper/证书那样拒绝启动。
 *
 * 为什么人脸不走"缺配置就拒绝启动"：
 *   人脸是**可选**的登录方式。拒绝启动等于让"这台机器没有摄像头"这种
 *   再普通不过的情况把整个认证系统一起拖下线 —— 那是拿可用性换一个
 *   本来就没打算强制的功能。
 * 与之相反的代价必须由调用方承担：引擎不可用时要**明确降级并留痕**，
 *   而不是静默跳过（P2 的 FaceIdController 负责这一点）。
 *
 * 与 <see cref="AuthServer.Services.Face.FaceOptions"/>（人脸 2FA）是两套**独立**配置：
 *   模块之间不共享任何实例，后续删除其中任一个模块都不影响另一个。
 *   两个模块可以共用同一个 YuNet 检测模型文件（那只是一个数据文件，不是代码），
 *   特征模型则完全不同：2FA 用 SFace，本模块用 ArcFace（w600k_r50，Glint360K 训练）。
 */
public class FaceIdOptions
{
    public const string SectionName = "FaceId";

    /// <summary>总开关。false 时本模块整体不参与任何流程（等价于从未实现过）。</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// 引擎落点：cv = 真实 OpenCV 引擎；stub = 假引擎（无摄像头也能跑通流程）。
    /// 与人脸 2FA 同思路：探针需要在**没有摄像头**的环境里验证
    /// "用户名 → 采集 → 特征 → 比对 → 签票 → 审计"这条链。
    /// </summary>
    public string Engine { get; set; } = "cv";

    /// <summary>
    /// 余弦相似度判定阈值 —— **通过线本身**（P3 定档：0.30）。
    ///
    /// 定档依据（`tools/faceid_threshold_sweep.py`，LFW 正 3000 对 / 负 50000 对，
    /// 共 7915 张图；正样本 median 0.671、负样本 p99.99 = 0.267）：
    ///   阈值 0.30 ⇒ FAR 2e-5、TAR 98.30%
    ///   阈值 0.50 ⇒ FAR ≈ 0、TAR 93.13%（旧默认，相当于白拒 6.9% 的本人）
    ///   旧写法是 `sim >= Threshold + GrayBand` 才通过 ⇒ 实际通过线 0.55 ⇒ TAR 仅 87.3%。
    /// 目标 FAR 1e-4 对应 0.267，取 0.30 是为了给 1:N（取 3 张模板的最大余弦）留余量。
    ///
    /// ⚠️ 阈值只对"同一条特征管线"有意义：换模型 ⇒ 全部历史模板作废，
    ///    因此 modelId 会随模板一起存（换模型后旧模板报"已作废"）。
    /// ⚠️ LFW 是简单集，这里的 FAR 不是线上估计，更不能当成 PAD / 识别认证的结论。
    /// </summary>
    public double Threshold { get; set; } = 0.30;

    /// <summary>
    /// 灰区半宽：相似度落在 [Threshold - GrayBand, Threshold) 内时判"灰区"，
    /// 既不签票也不直接计失败 —— 引导用户转用口令登录。
    ///
    /// 0.05 是**故意保留**的：灰区越宽，本人越不容易被锁（0.25–0.30 这段 LFW 上
    /// 攻击者命中率只有 1.6e-4，但本人掉进来并不罕见）；但灰区不计次 ⇒ 也给了
    /// 攻击者一块"试了不锁"的地带。0.05 是这两者之间留的窄带，不随阈值一起调。
    /// </summary>
    public double GrayBand { get; set; } = 0.05;

    /// <summary>每人的模板上限。纯人脸登录推荐 1 张，最多留 3 张压低误拒率。</summary>
    public int MaxTemplates { get; set; } = 3;

    /// <summary>
    /// 检测模型（YuNet）。与人脸 2FA 模块**共用同一个文件** —— 那是数据不是代码，
    /// 将来删除 2FA 模块时这个文件仍被本模块使用，不受影响。
    /// 相对路径按 exe 所在目录解析。
    /// </summary>
    public string DetectorModel { get; set; } = "face-models/face_detection_yunet_2023mar.onnx";

    /// <summary>
    /// 特征模型（ArcFace w600k_r50，Glint360K 训练，512 维输出）。
    /// ⚠️ 该权重上游仅授权**非商业研究**用途，因此**不进公开仓库**：
    ///    装机/评测需要时按 AuthServer/face-models/README.md 的说明下载并校验 SHA-256。
    ///    文件缺失时本模块引擎判不可用（fail closed），不影响其余功能。
    /// </summary>
    public string RecognizerModel { get; set; } = "face-models/face_recognition_arcface_w600k_r50.onnx";

    // ── 活体判定（PAD，P1b） ────────────────────────────────────────

    /// <summary>
    /// 是否启用活体判定。**默认关**（从"默认开"改回来的，理由必须写清楚）：
    ///   本项目的验收方式就是**手举照片对着镜头测**，默认开着会把这套流程整个堵死
    ///   —— 拿不到"能被识别"的画面，就测不了相似度、灰区、计次、锁定这些真正要验的东西。
    ///   所以这里把活体做成 **opt-in 硬化**：想演示"照片能不能过"时开一行环境变量即可：
    ///       AUTHBASELINE_FACEID_PAD_ENABLED=true
    ///   开启后的效果已标定过：阈值 0.70 下三类翻拍 0/120 通过、真人单帧 91% 通过
    ///   （见 docs/reports/FACEID-P1B-PAD-REPORT.md）。
    ///
    /// ⚠️ 口径：默认关闭意味着**本模块当前没有反欺骗能力** —— 照片对着镜头就能录、能登。
    ///    界面与文档都必须如实标"活体判定：关闭"，不能让人以为有 PAD 保护。
    /// </summary>
    public bool PadEnabled { get; set; } = false;

    /// <summary>
    /// 活体阈值：p(live) 低于它就判"疑似攻击"。
    ///
    /// ⚠️ 0.70 是**起点**，不是标定结论（同下面的质量闸门）：
    ///    方向已定（偏安全：宁可误拒真人、不让照片过关），具体数值要等真机样本扫。
    ///    真机样本上的实测分布见 docs/reports/FACEID-P1B-PAD-REPORT.md。
    /// </summary>
    public double PadMinLive { get; set; } = 0.70;

    /// <summary>
    /// 画面里出现**第二张脸**时是否直接拒绝。默认 true。
    ///
    /// 关掉只在"用照片做识别测试"的场景下成立：举着手机时操作者自己的脸很容易同框，
    /// 而测试集（不同人种 / 明星各年龄段 / 双胞胎 / 特殊人群）本来就找不到真人来配合。
    /// 关掉后取**面积最大**的那张脸。
    ///
    /// ⚠️ 关掉等于放弃"存进模板的是谁"这一保证（可能出现"想录 A、实际存了 B"）。
    ///    只在受控测试环境用；界面与日志都会标出这一点。
    /// </summary>
    public bool RejectMultipleFaces { get; set; } = true;

    /// <summary>
    /// 活体模型（MiniFASNetV2，80×80，三分类 [print, live, replay]）。
    /// Apache-2.0 ⇒ 可随仓库与安装包分发（与 ArcFace 的"仅非商业研究"不同）。
    /// ⚠️ 预处理红线见 CvFaceIdLiveness 的类头注释：除 255 会让真人永远录不进去。
    /// </summary>
    public string PadModel { get; set; } = "face-models/minifasnet_v2_80x80.onnx";

    public int CameraIndex { get; set; } = 0;

    /// <summary>
    /// 假引擎的"呈现身份"：等于待验证账号的用户名时相似度视为通过，否则判不匹配。
    /// 与 2FA 的假引擎同一手法，探针通过它确定性地走到"本人/非本人"两条分支。
    /// </summary>
    public string StubIdentity { get; set; } = string.Empty;

    /// <summary>
    /// 假引擎行为开关（仅测试用）：
    /// ok | mismatch | no_face | low_quality | engine_down | multi_face | blurry | turned。
    ///
    /// 后三个是 P1 为**录入质量闸门**补的：多脸 / 糊 / 侧脸这三条分支在有真摄像头的
    /// 机器上也难稳定复现，而它们恰恰是最该被回归钉住的（前两条涉及隐私与可用性）。
    /// </summary>
    public string StubBehavior { get; set; } = "ok";

    // ── 录入质量闸门（P1） ──────────────────────────────────────────
    // ⚠️ 下面四个阈值都是**起点**，不是结论：
    //    它们只被用来挡住"明显不能用的帧"（太远 / 糊了 / 侧脸），
    //    真正的定档要等 P1b 用真机样本扫（同 P3 的阈值定档逻辑）。
    //    所以这些值刻意留得宽 —— 宁可多让用户重试一次，也不要让正常人在
    //    光线一般的时候永远录不进去。

    /// <summary>脸宽至少占画面宽的比例。默认 0.12（640 宽 ⇒ 约 77 px）。</summary>
    public double MinFaceWidthRatio { get; set; } = 0.12;

    /// <summary>
    /// 清晰度下限：脸框内灰度拉普拉斯方差。默认 60。
    /// 引擎测不出来（假引擎 / 框越界）时这一项**跳过**，不按不合格处理。
    /// </summary>
    public double MinSharpness { get; set; } = 60.0;

    /// <summary>
    /// 正脸度：鼻尖相对双眼中点的水平偏移 / 双眼间距，绝对值超过它就判"侧脸"。
    /// 默认 0.35 —— 约相当于左右转头 30° 上下。
    /// </summary>
    public double MaxYawRatio { get; set; } = 0.35;

    /// <summary>
    /// 头部左右倾斜（滚转角）的容差：双眼连线 |dy| / |dx|。
    /// 默认 0.30（约 17°）。躺姿/趴桌拍出来的头会被它挡掉 —— 那类帧对齐后
    /// 特征质量很差，而且用户自己也不知道"哪里不对"。
    /// </summary>
    public double MaxRollRatio { get; set; } = 0.30;

    /// <summary>
    /// 一次录入尝试最多读多少帧。默认 15 帧（约 1 秒）。
    /// 为什么不是"只读一帧"：用户点下按钮时多半还没坐正，
    /// 一帧定生死会让首次录入的失败率高得离谱。读一小段再挑最好的一帧，
    /// 是"不多要用户耐心"与"不把不可用的帧存进去"之间的折中。
    /// </summary>
    public int EnrollMaxFrames { get; set; } = 15;

    /// <summary>读帧之间的间隔（毫秒）。给摄像头自动曝光/对焦留出收敛时间。</summary>
    public int EnrollFrameIntervalMs { get; set; } = 60;

    /// <summary>
    /// 采集分辨率。**必须与检测器预设尺寸一致**（同 2FA 模块的限制：
    /// FaceDetectorYN 没有暴露 setInputSize，尺寸不符会直接抛异常）。
    /// 反过来，尺寸固定带来一个好处：录入与验证永远走同一分辨率，
    /// 避免"换个摄像头/换台机器就认不出"。
    /// </summary>
    public int CaptureWidth { get; set; } = 640;
    public int CaptureHeight { get; set; } = 480;

    /// <summary>
    /// 特征维度。ArcFace w600k_r50 输出 512 维；假引擎也刻意派生 512 维，
    /// 两种引擎的模板因此共享同一套 dim 校验（见 StubFaceIdEngine.Derive）。
    /// </summary>
    public int EmbeddingDim { get; set; } = 512;

    /// <summary>
    /// 环境变量覆盖：安装目录里的配置文件会被覆盖安装冲掉，
    /// 而测试与排障需要"不改配置文件就换行为"。与 FaceOptions / EmailOptions 同手法。
    /// </summary>
    public void ApplyEnvironmentOverrides()
    {
        var enabled = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_ENABLED");
        if (!string.IsNullOrWhiteSpace(enabled))
            Enabled = !enabled.Trim().Equals("false", StringComparison.OrdinalIgnoreCase) && enabled.Trim() != "0";

        var engine = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_ENGINE");
        if (!string.IsNullOrWhiteSpace(engine)) Engine = engine.Trim();

        var threshold = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_THRESHOLD");
        if (!string.IsNullOrWhiteSpace(threshold)
            && double.TryParse(threshold.Trim(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var t))
            Threshold = t;

        var gray = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_GRAYBAND");
        if (!string.IsNullOrWhiteSpace(gray)
            && double.TryParse(gray.Trim(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var g))
            GrayBand = g;

        var stub = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_STUB_IDENTITY");
        if (stub is not null) StubIdentity = stub.Trim();

        var behavior = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_STUB_BEHAVIOR");
        if (behavior is not null) StubBehavior = behavior.Trim();

        // 录入闸门的三个旋钮也允许用环境变量临时改：探针要在**同一个二进制**上
        // 分别验证"闸门挡住"与"闸门放行"，改配置文件做不到（安装目录会被覆盖）。
        var minSharp = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_MIN_SHARPNESS");
        if (!string.IsNullOrWhiteSpace(minSharp)
            && double.TryParse(minSharp.Trim(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var ms))
            MinSharpness = ms;

        var maxYaw = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_MAX_YAW");
        if (!string.IsNullOrWhiteSpace(maxYaw)
            && double.TryParse(maxYaw.Trim(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var my))
            MaxYawRatio = my;

        var maxTemplates = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_MAX_TEMPLATES");
        if (!string.IsNullOrWhiteSpace(maxTemplates) && int.TryParse(maxTemplates.Trim(), out var mt) && mt > 0)
            MaxTemplates = mt;

        // 活体判定：探针需要验证"挡住"与"放行"两个方向，以及"模型缺失 ⇒ fail closed"，
        // 所以开关与阈值都必须能在同一次构建上用环境变量切换。
        var padEnabled = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_PAD_ENABLED");
        if (!string.IsNullOrWhiteSpace(padEnabled))
            PadEnabled = !padEnabled.Trim().Equals("false", StringComparison.OrdinalIgnoreCase)
                         && padEnabled.Trim() != "0";

        // 多脸放行：照片测试时需要（举手机的人自己会入镜）。
        var allowMulti = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_ALLOW_MULTI_FACE");
        if (!string.IsNullOrWhiteSpace(allowMulti))
            RejectMultipleFaces = !(allowMulti.Trim().Equals("true", StringComparison.OrdinalIgnoreCase)
                                    || allowMulti.Trim() == "1");

        var padMinLive = Environment.GetEnvironmentVariable("AUTHBASELINE_FACEID_PAD_MIN_LIVE");
        if (!string.IsNullOrWhiteSpace(padMinLive)
            && double.TryParse(padMinLive.Trim(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var pl))
            PadMinLive = pl;
    }

    /// <summary>是否走假引擎。</summary>
    public bool UseStubEngine => string.Equals(Engine, "stub", StringComparison.OrdinalIgnoreCase);

    /// <summary>把模型路径解析成绝对路径（相对路径按 exe 所在目录）。</summary>
    public string ResolveDetector() => Resolve(DetectorModel);
    public string ResolveRecognizer() => Resolve(RecognizerModel);
    public string ResolvePadModel() => Resolve(PadModel);

    private static string Resolve(string path) =>
        Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);
}
