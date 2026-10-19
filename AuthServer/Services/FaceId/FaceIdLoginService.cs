using AuthServer.Models;

namespace AuthServer.Services.FaceId;

/**
 * 纯人脸登录的**比对与决策**：用户名 → 采集 → 特征 → 与模板取最大余弦 → 三途判定。
 *
 * 这一层刻意**不签票、不写审计、不改账号状态**（与 2FA 的 FaceLoginService 同分工）：
 *   它只回答"这次识别算不算通过、为什么"，把"记什么、计不计次、发不发票"留给控制器。
 *   理由很实际：这些判断要在没有摄像头、没有模型的机器上做回归，
 *   而签票与审计都依赖 HttpContext / 数据库，一旦混进来就一条都测不了。
 *
 * 三条与 2FA 不同的取舍：
 *   ① **没有动作挑战**。本模块是"用户名 + 一张脸"的唯一因子，不是第二因子；
 *      挑战机制属于 2FA，硬搬过来会让两个模块互相引用，删除时互相牵连。
 *   ② **取多张模板的最大余弦**。每人最多 3 张模板（不同角度/光线），
 *      与"最像的那一张"比才是用户直觉上的"是不是本人"；取平均会把
 *      一张好模板和一张废模板平均成"谁都不像"。
 *   ③ **早停**。一旦某帧已达到 Pass，立刻停止采集 —— 登录是交互路径，
 *      多跑几帧只会让用户多等一秒，不会改变结论。
 *
 * ⚠️ 照片能不能过，由 FaceIdOptions.PadEnabled 决定，默认**关**。
 *    本项目要做"不同人种 / 明星各年龄段 / 双胞胎"的照片测试，找不到真人配合，
 *    所以默认不拦照片；开启后走与录入同一套活体判定。
 */
public sealed record FaceIdLoginOutcome(
    bool Success,
    string BusinessCode,
    string Message,
    string Diagnostic,
    double? Similarity);

public sealed class FaceIdLoginService
{
    private readonly FaceIdOptions _opt;
    private readonly IFaceIdEngine _engine;
    private readonly IFaceIdLiveness _liveness;
    private readonly FaceIdTemplateStore _store;

    public FaceIdLoginService(FaceIdOptions opt, IFaceIdEngine engine,
        IFaceIdLiveness liveness, FaceIdTemplateStore store)
    {
        _opt = opt;
        _engine = engine;
        _liveness = liveness;
        _store = store;
    }

    public bool Enabled => _opt.Enabled;
    public double Threshold => _opt.Threshold;
    public double GrayBand => _opt.GrayBand;

    /// <summary>
    /// 对一个**已经确定存在的账号**做一次人脸登录。
    ///
    /// 用户名是否存在由控制器判定（它要写审计、要区分禁用/锁定），
    /// 这里只管"这张脸像不像这个人"。
    /// </summary>
    public async Task<FaceIdLoginOutcome> LoginAsync(string userId)
    {
        if (!_opt.Enabled) return Fail(BusinessCode.FaceIdDisabled, "模块关闭");

        if (!_engine.Status.Ready) return Fail(BusinessCode.FaceIdEngineUnavailable, _engine.Status.Message);

        // 密钥不可用 ⇒ 模板全都读不出来。这是本机故障，**不能**报成"人脸不对"
        // （那会让用户反复重试一张根本读不到的模板）。
        if (!_store.KeyAvailable)
            return Fail(BusinessCode.FaceIdEngineUnavailable, "本机模板加密密钥不可用");

        if (_opt.PadEnabled && !_liveness.Status.Ready)
            return Fail(BusinessCode.FaceIdEngineUnavailable, $"活体判定不可用：{_liveness.Status.Message}");

        var (features, foreign, unreadable) = await _store.LoadFeaturesAsync(userId);
        if (features.Count == 0)
        {
            // "没录过"与"录过但模型换了"必须分开报 —— 前者引导去录入，后者要让用户重新录，
            // 否则他只会对着一个永远失败的人脸登录猜原因。
            return foreign > 0
                ? Fail(BusinessCode.FaceIdModelMismatch, $"共 {foreign} 张模板属于旧模型")
                : Fail(BusinessCode.FaceIdNotEnrolled,
                    unreadable > 0 ? $"共 {unreadable} 张模板读不出来" : "没有任何模板");
        }

        var openError = _engine.TryOpen();
        if (openError is not null) return Fail(BusinessCode.FaceIdEngineUnavailable, openError);

        FaceIdQualityVerdict worst = FaceIdQualityVerdict.Pass;
        var framesRead = 0;
        var padRejected = 0;
        var compared = 0;
        var best = double.NegativeInfinity;
        var diagnostics = new List<string>(3);

        try
        {
            for (int i = 0; i < Math.Max(1, _opt.EnrollMaxFrames); i++)
            {
                var frame = _engine.ReadFrame();
                if (frame is null)
                {
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

                // 活体与录入同一条红线：开了就必须过，模型不可用则 fail closed。
                if (_opt.PadEnabled)
                {
                    var live = _liveness.Score(frame, box!);
                    if (live is null)
                        return Fail(BusinessCode.FaceIdEngineUnavailable, "活体判定没有给出结论");
                    if (live.Value < _opt.PadMinLive)
                    {
                        padRejected++;
                        if (diagnostics.Count < 3)
                            diagnostics.Add($"liveness={live.Value:F3}<{_opt.PadMinLive:F2}");
                        SleepBetweenFrames();
                        continue;
                    }
                }

                var feature = _engine.Feature(frame, box!);
                if (feature is null)
                {
                    worst = Worse(worst, FaceIdQualityVerdict.Blurry);
                    SleepBetweenFrames();
                    continue;
                }

                compared++;
                foreach (var template in features)
                {
                    var sim = _engine.Similarity(feature, template);
                    if (sim > best) best = sim;
                }

                // 早停：够 Pass 了就不必再采。
                if (best >= _opt.Threshold + Math.Max(0, _opt.GrayBand)) break;
            }
        }
        finally
        {
            // 无论成败都释放摄像头：否则用户下一次再点会拿到"设备被占用"这种假故障。
            _engine.Close();
        }

        var trace = $"frames={framesRead} compared={compared} worst={worst}"
            + $" pad_rejected={padRejected}"
            + (double.IsNegativeInfinity(best) ? string.Empty : $" best_sim={best:F4}")
            + " | " + string.Join(" ; ", diagnostics);

        if (double.IsNegativeInfinity(best))
        {
            if (framesRead == 0)
                return Fail(BusinessCode.FaceIdEngineUnavailable, "摄像头没有返回任何画面：" + trace);

            // 有帧过了质量闸门却没通过活体 ⇒ 报活体失败，优先于质量类原因
            // （理由同录入：能过质量闸门的脸已经"干净"，剩下的解释只有"不像真的"）。
            if (padRejected > 0) return Finish(BusinessCode.FaceIdLivenessFailed, trace, null);

            var code = FaceIdCodes.BusinessCodeFor(worst == FaceIdQualityVerdict.Pass
                ? FaceIdQualityVerdict.NoFace
                : worst);
            return Finish(code, trace, null);
        }

        var decision = FaceIdDecision.Classify(best, _opt.Threshold, _opt.GrayBand);
        return decision switch
        {
            // 通过：控制器据此签票。相似度一并回传，便于审计留痕（只进审计，不进响应体）。
            FaceIdVerdict.Pass => new FaceIdLoginOutcome(true, string.Empty, "登录成功", trace, best),
            FaceIdVerdict.GrayZone => Finish(BusinessCode.FaceIdGrayZone, trace, best),
            _ => Finish(BusinessCode.FaceIdMismatch, trace, best)
        };
    }

    private static FaceIdLoginOutcome Fail(string businessCode, string diagnostic) =>
        Finish(businessCode, diagnostic, null);

    private static FaceIdLoginOutcome Finish(string businessCode, string diagnostic, double? similarity) =>
        new(false, businessCode, FaceIdCodes.MessageFor(businessCode), diagnostic, similarity);

    private void SleepBetweenFrames()
    {
        if (_opt.EnrollFrameIntervalMs > 0) Thread.Sleep(_opt.EnrollFrameIntervalMs);
    }

    private static FaceIdBox? Largest(IReadOnlyList<FaceIdBox> boxes)
    {
        FaceIdBox? best = null;
        foreach (var box in boxes)
            if (best is null || box.W * box.H > best.W * best.H) best = box;
        return best;
    }

    /// <summary>与录入同一套优先级：多脸 > 太小 > 侧脸 > 糊 > 没人脸。</summary>
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
