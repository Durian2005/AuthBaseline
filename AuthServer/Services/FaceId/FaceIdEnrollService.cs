using AuthServer.Models;

namespace AuthServer.Services.FaceId;

/**
 * FaceId 录入的**编排层**：口令已验过之后，"开摄像头 → 采一小段 → 过质量闸门 →
 * 提特征 → 写模板"这一串动作收在这里。
 *
 * 为什么不写在控制器里：
 *   ① 控制器负责的是"谁在请求、票据是否有效、失败怎么记账（计次/审计）"，
 *      而"什么帧能存、存进去的是什么"属于算法策略。两者混在一起，
 *      策略就没法在没有 HttpContext 的环境里被单测或探针覆盖。
 *   ② 这条链路的每一步都有"环境可能不配合"的分支（摄像头打不开、模型没加载、
 *      密钥不可用），把它们收在一处才能保证**每一种失败都有确切的原因码**，
 *      而不是一律变成"录入失败"。
 *
 * 这一层刻意**不写审计、不碰票据、不改账号状态**：
 *   它只回答"这一帧能不能用、为什么不能用"，把"记什么"留给控制器 ——
 *   同一次失败由两个地方各写一条，只会导致两条记录迟早不一致。
 */
public sealed record FaceIdEnrollOutcome(
    bool Success,
    string BusinessCode,
    string AuditReason,
    string Message,
    string Diagnostic,
    long TemplateCount,
    long PurgedForeign,
    long Evicted);

public sealed class FaceIdEnrollService
{
    private readonly FaceIdOptions _opt;
    private readonly IFaceIdEngine _engine;
    private readonly FaceIdTemplateStore _store;

    public FaceIdEnrollService(FaceIdOptions opt, IFaceIdEngine engine, FaceIdTemplateStore store)
    {
        _opt = opt;
        _engine = engine;
        _store = store;
    }

    public bool Enabled => _opt.Enabled;
    public FaceIdEngineStatus EngineStatus => _engine.Status;
    public double Threshold => _opt.Threshold;
    public int MaxTemplates => _opt.MaxTemplates;
    public string ModelId => _store.ModelId;

    /// <summary>失败结果的统一构造（业务码 → 审计码的映射只走 FaceIdCodes）。</summary>
    private static FaceIdEnrollOutcome Fail(string businessCode, string diagnostic,
        string? message = null) =>
        new(false, businessCode,
            FaceIdCodes.ToAuditReason(businessCode),
            message ?? FaceIdCodes.MessageFor(businessCode),
            diagnostic, 0, 0, 0);

    private static FaceIdEnrollOutcome EngineUnavailable(string diagnostic) =>
        Fail(BusinessCode.FaceIdEngineUnavailable, diagnostic);

    /// <summary>
    /// 采集并写入一张模板。
    ///
    /// 采集策略：**读一小段帧，取第一张过闸门的**（不是"取全部帧里最好的一张"）。
    /// 原因：多帧打分需要把每帧都送进识别器（174MB 的模型每帧一次前向），
    /// 在低配笔记本上会把一次录入拖到几秒；而"过闸门"本身已经是"可用"的充分条件，
    /// 追求"最优"并不会让 P3 的阈值定档更好做 —— 那要靠数据集，不靠录入时的挑帧。
    ///
    /// 失败时报告**信息量最大**的那条原因（优先级见 Priority）：
    ///   MultipleFaces > TooSmall > NotFrontal > Blurry > NoFace。
    ///   例如"有一帧两张脸、其余帧没人脸"必须报多脸 —— 否则用户会一直
    ///   对着镜头调整距离，而真正的问题是画面里还有别人。
    /// </summary>
    public async Task<FaceIdEnrollOutcome> EnrollAsync(string userId, string username)
    {
        if (!_opt.Enabled) return Fail(BusinessCode.FaceIdDisabled, "模块关闭");

        if (!_engine.Status.Ready) return EngineUnavailable(_engine.Status.Message);

        // 密钥不可用 ⇒ 就算拍到了也存不了。提前拒绝，别让用户白对着镜头。
        if (!_store.KeyAvailable)
            return EngineUnavailable("本机模板加密密钥不可用");

        var openError = _engine.TryOpen();
        if (openError is not null) return EngineUnavailable(openError);

        FaceIdQualityVerdict worst = FaceIdQualityVerdict.Pass;
        var framesRead = 0;
        var diagnostics = new List<string>(3);
        double[]? feature = null;

        try
        {
            for (int i = 0; i < Math.Max(1, _opt.EnrollMaxFrames); i++)
            {
                var frame = _engine.ReadFrame();
                if (frame is null)
                {
                    // 摄像头还没吐出第一帧 / 读失败：继续试，但别把它记成"没人脸" ——
                    // 那是两件不同的事（设备问题 vs 用户没坐好）。
                    SleepBetweenFrames();
                    continue;
                }

                framesRead++;
                var boxes = _engine.DetectAll(frame);
                var box = Largest(boxes);

                var sample = new FaceIdQualitySample(
                    FaceCount: boxes.Count,
                    FrameWidth: frame.Width,
                    FrameHeight: frame.Height,
                    BoxWidth: box?.W ?? 0,
                    BoxHeight: box?.H ?? 0,
                    Points: box?.Points ?? Array.Empty<double>(),
                    Sharpness: box is null ? null : _engine.Sharpness(frame, box));

                var verdict = FaceIdQuality.Evaluate(sample, _opt);
                if (diagnostics.Count < 3) diagnostics.Add(verdict.Diagnostic);

                if (!verdict.Passed)
                {
                    worst = Worse(worst, verdict.Verdict);
                    SleepBetweenFrames();
                    continue;
                }

                // 闸门过了才提特征。提不出来（关键点退化/对齐失败）等同于"这一帧不可用"，
                // 但原因归到质量而不是"人脸不像"—— 录入阶段根本没有比对的语义。
                feature = _engine.Feature(frame, box!);
                if (feature is null)
                {
                    worst = Worse(worst, FaceIdQualityVerdict.Blurry);
                    SleepBetweenFrames();
                    continue;
                }
                break;
            }
        }
        finally
        {
            // 无论成败都释放摄像头：桌面端的约定是"操作结束即释放"，
            // 否则用户下次再点录入会拿到"设备被占用"这种假故障。
            _engine.Close();
        }

        var trace = $"frames={framesRead} worst={worst} | " + string.Join(" ; ", diagnostics);

        if (feature is null)
        {
            // 一帧都没读到：这更可能是设备问题（被占用/没插好），而不是用户没坐好。
            // 报"引擎不可用"比报"没检测到人脸"更接近事实。
            if (framesRead == 0)
                return EngineUnavailable("摄像头没有返回任何画面");

            var code = FaceIdCodes.BusinessCodeFor(worst == FaceIdQualityVerdict.Pass
                ? FaceIdQualityVerdict.NoFace   // 理论上到不了：Pass 却拿不到特征，按最保守的原因报
                : worst);
            return Fail(code, trace);
        }

        var (count, purged, evicted) = await _store.AddAsync(userId, username, feature);
        var message = count > 1
            ? $"已录入第 {count} 张可用于纯人脸登录的模板（上限 {_opt.MaxTemplates} 张，超出后自动淘汰最早的）"
            : "已录入用于纯人脸登录的人脸模板";

        return new FaceIdEnrollOutcome(true, string.Empty, string.Empty, message, trace, count, purged, evicted);
    }

    /// <summary>删除本人全部 FaceId 模板。返回删除条数。</summary>
    public Task<long> DeleteAllAsync(string userId) => _store.DeleteByUserIdAsync(userId);

    private void SleepBetweenFrames()
    {
        if (_opt.EnrollFrameIntervalMs > 0)
            Thread.Sleep(_opt.EnrollFrameIntervalMs);
    }

    private static FaceIdBox? Largest(IReadOnlyList<FaceIdBox> boxes)
    {
        FaceIdBox? best = null;
        foreach (var box in boxes)
            if (best is null || box.W * box.H > best.W * best.H) best = box;
        return best;
    }

    /// <summary>
    /// 保留"信息量更大"的那条原因。数值越大越优先：
    /// 多脸(5) > 太小(4) > 侧脸(3) > 糊(2) > 没人脸(1)。
    ///
    /// 顺序的取舍："多脸"排第一是因为它是唯一**涉及他人**的失败；
    /// "没人脸"排最后是因为它信息量最低 —— 用户自己也知道画面里没人。
    /// </summary>
    private static FaceIdQualityVerdict Worse(FaceIdQualityVerdict current, FaceIdQualityVerdict next) =>
        Priority(next) > Priority(current) ? next : current;

    private static int Priority(FaceIdQualityVerdict verdict) => verdict switch
    {
        FaceIdQualityVerdict.MultipleFaces => 5,
        FaceIdQualityVerdict.TooSmall => 4,
        FaceIdQualityVerdict.NotFrontal => 3,
        FaceIdQualityVerdict.Blurry => 2,
        FaceIdQualityVerdict.NoFace => 1,
        _ => 0
    };
}
