using AuthServer.Models;
using MongoDB.Driver;

namespace AuthServer.Services.Face;

/**
 * 登录第二因子的**决策层**：这个账号该不该要人脸、要什么动作、
 * 这一轮人脸没过算不算一次失败。
 *
 * 为什么不把这段逻辑写在 AuthController 里：
 *   ① 控制器已经很长，而"要不要第二因子""这轮算不算失败"是**策略**，
 *      策略需要能被单独读完、单独解释（答辩时会被逐条问）。
 *   ② 回归探针要在没有摄像头的环境里覆盖这些分支，把它们收在一个
 *      不依赖 HttpContext 的类里，探针可以直接构造它。
 *
 * 这一层刻意**不写审计、不碰票据、不改账号状态** ——
 *   它只回答"是/否/为什么"，把"记什么、锁不锁、发不发票"留给控制器。
 *   一旦这里也写审计，同一次失败就会有两个地方各写一条，重复且迟早会不一致。
 */
public sealed class FaceLoginService
{
    /// <summary>口令通过之后，该账号的第二因子处境。</summary>
    public enum Requirement
    {
        /// <summary>不需要第二因子（模块关闭 / 该账号没录人脸）。</summary>
        NotRequired,

        /// <summary>需要，且引擎就绪，可以下发挑战。</summary>
        Challenge,

        /// <summary>需要，但引擎不可用 —— 必须**拒绝**而不是跳过（见 AssessAsync 注释）。</summary>
        EngineUnavailable
    }

    public sealed record Decision(Requirement Requirement, string Message);

    private readonly FaceOptions _opt;
    private readonly IFaceEngine _engine;
    private readonly FaceTemplateStore _templates;
    private readonly FaceChallengeStore _challenges;
    private readonly MongoDbService _db;

    public FaceLoginService(FaceOptions opt, IFaceEngine engine, FaceTemplateStore templates,
        FaceChallengeStore challenges, MongoDbService db)
    {
        _opt = opt;
        _engine = engine;
        _templates = templates;
        _challenges = challenges;
        _db = db;
    }

    public bool Enabled => _opt.Enabled;
    public double Threshold => _opt.Threshold;
    public int ChallengeTtlSeconds => _opt.ChallengeTtlSeconds;
    public int MaxTemplates => _opt.MaxTemplates;
    public FaceEngineStatus EngineStatus => _engine.Status;

    /// <summary>
    /// 判断该账号在口令通过之后是否还需要人脸。三条判据，顺序不能换：
    ///   ① 模块关闭 ⇒ 一律不要（这是"等价于从未实现过"的总开关）。
    ///   ② 该账号**没有任何模板** ⇒ 不要。这条是产品约定：
    ///      不导入人脸完全不影响正常使用，未录入的账号行为与改造前逐字一致。
    ///   ③ 引擎不可用 ⇒ **要**，但以"不可用"的形式拒绝（fail closed）。
    ///
    /// 第 ③ 条为什么是拒绝、而不是"引擎不可用就跳过第二因子"：
    ///   本项目的既有约定是"安全能力不可用就拒绝"（TLS 证书不可用拒绝启动、
    ///   读不到 pepper 拒绝启动）。若这里改成跳过，那么"把摄像头占用 / 弄坏"
    ///   就成了一条**比删模板还廉价的静默降级通道** —— 删模板至少还要口令二次确认。
    ///   代价是：已录入的账号在摄像头故障的机器上登不进来；
    ///   恢复路径是管理员重置其人脸模板（FACE_TEMPLATE_RESET），
    ///   与"丢失 2FA 设备必须找管理员重置、不能自助绕过"是同一类设计。
    /// </summary>
    public async Task<Decision> AssessAsync(User user)
    {
        if (!_opt.Enabled) return new Decision(Requirement.NotRequired, string.Empty);

        if (await _templates.CountAsync(user.Id) == 0)
            return new Decision(Requirement.NotRequired, string.Empty);

        var status = _engine.Status;
        if (!status.Ready)
            return new Decision(Requirement.EngineUnavailable, status.Message);

        return new Decision(Requirement.Challenge, string.Empty);
    }

    /// <summary>下发一张**登录用**的一次性挑战。</summary>
    public (string Token, string Action) Issue(string username) =>
        _challenges.Issue(username, FaceChallengeStore.PurposeLogin);

    /// <summary>
    /// 消费挑战 token，解析出这次要验证的账号。
    /// 返回的 Error 非 null 表示这张票不可用（码与 BusinessCodes.FaceChallengeInvalid 对齐）。
    ///
    /// 用途必须是 <c>PurposeLogin</c>：录入时签发的挑战**不能**拿来当登录通行证，
    /// 哪怕它属于同一个账号、动作也合法。
    ///
    /// 注意：token 无效时**解析不出用户名** —— 因此这一次失败在控制器那边
    /// 无法归属到任何账号，也就不可能累加计数（计数是账号级的量，无主的失败没有累加对象）。
    /// 这不构成绕过：要拿到 token 必须先过口令，重放一张已消费的票并不能推进攻击。
    /// </summary>
    public async Task<(User? User, string? Action, string? Error)> BeginVerifyAsync(string challengeToken)
    {
        var (username, action, purpose, error) = _challenges.Consume(challengeToken);
        if (error is not null || username is null || action is null) return (null, null, "FACE_CHALLENGE_INVALID");

        if (!string.Equals(purpose, FaceChallengeStore.PurposeLogin, StringComparison.Ordinal))
            return (null, null, "FACE_CHALLENGE_INVALID");

        var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
        if (user is null) return (null, null, "FACE_CHALLENGE_INVALID");

        return (user, action, null);
    }

    /// <summary>
    /// 录入 / 更换人脸时消费挑战并跑一次活体挑战，返回采集到的特征。
    /// 与登录的区别只有一处：**不比对任何模板** —— 录入的语义就是"把这张脸存下来"。
    ///
    /// 用途必须是 <c>PurposeEnroll</c>（反之亦然），两种挑战不可互换。
    /// </summary>
    public (string? Username, ChallengeOutcome? Outcome, string? Error) CaptureForEnroll(string challengeToken)
    {
        var (username, action, purpose, error) = _challenges.Consume(challengeToken);
        if (error is not null || username is null || action is null) return (null, null, "FACE_CHALLENGE_INVALID");

        if (!string.Equals(purpose, FaceChallengeStore.PurposeEnroll, StringComparison.Ordinal))
            return (null, null, "FACE_CHALLENGE_INVALID");

        return (username, _engine.RunChallenge(action), null);
    }

    /// <summary>下发一张**录入用**的一次性挑战。</summary>
    public (string Token, string Action) IssueForEnroll(string username) =>
        _challenges.Issue(username, FaceChallengeStore.PurposeEnroll);

    /// <summary>一次人脸验证的结论，已含"要不要计入失败窗口"。</summary>
    public sealed record VerifyResult
    {
        public bool Passed { get; init; }
        public string Username { get; init; } = string.Empty;
        public string BusinessCode { get; init; } = string.Empty;
        public string AuditReason { get; init; } = string.Empty;
        public string Message { get; init; } = string.Empty;

        /// <summary>是否计入 3 分钟失败窗口。**只进审计，不回给客户端**（见控制器注释）。</summary>
        public bool Counted { get; init; }

        /// <summary>通过时才有：本次比对得到的最高余弦相似度。</summary>
        public double? Similarity { get; init; }

        /// <summary>压成一行，写进审计的 request/response JSON 袋（绝不单独加列）。</summary>
        public string Diagnostic { get; init; } = string.Empty;
    }

    private static VerifyResult Reject(string businessCode, string diagnostic, string username = "",
        string? message = null)
    {
        // 组别只由业务码决定，不在这里再判一次 —— 见 FaceCodes.IsCounted 的说明：
        // "这次算不算失败"必须钉在码上，否则新增一个判定就多一处漏判的机会。
        var reason = FaceCodes.ToAuditReason(businessCode);
        return new VerifyResult
        {
            Passed = false,
            Username = username,
            BusinessCode = businessCode,
            AuditReason = reason,
            Counted = FaceCodes.IsCounted(reason),
            Message = message ?? FaceCodes.MessageFor(businessCode),
            Diagnostic = diagnostic
        };
    }

    /// <summary>
    /// 跑一次完整验证：活体动作挑战 → 取回正帧特征 → 与该账号全部模板比对取最高相似度。
    ///
    /// 三种"失败"在这里被刻意分开，因为它们对用户和审计的意义完全不同：
    ///   · 挑战没过（FACE_LIVENESS_FAILED / FACE_NO_FACE / ...）—— 连特征都没拿到；
    ///   · 特征读不出来 / 模板解密不了（FACE_ENGINE_UNAVAILABLE）—— 本机故障，**不是"不像"**；
    ///   · 相似度低于阈值（FACE_MISMATCH）—— 才是"这张脸对不上"。
    /// 把第 2 种混进第 3 种，会把一次环境事故伪装成一次认证失败，
    /// 而且会把用户锁在门外却查不出原因。
    /// </summary>
    public async Task<VerifyResult> EvaluateAsync(User user, string action)
    {
        var outcome = _engine.RunChallenge(action);
        if (!outcome.Passed)
            return Reject(outcome.BusinessCode, outcome.Diagnostic, user.Username);

        if (outcome.Feature is null)
            return Reject("FACE_ENGINE_UNAVAILABLE", "挑战通过但未取到特征", user.Username);

        if (!_templates.KeyAvailable)
            return Reject("FACE_ENGINE_UNAVAILABLE", "本机人脸模板解密密钥不可用", user.Username);

        var (best, usable, unreadable) = await _templates.TryVerifyAsync(user.Id, outcome.Feature, _engine);

        // 有模板记录、却一张都解不出来 ⇒ 密钥换了或密文被改动。这是本机故障，
        // 不能按"对不上"处理：那样用户会一直试一张"正确但读不出来"的脸。
        if (usable == 0 || best is null)
            return Reject("FACE_ENGINE_UNAVAILABLE",
                $"无可用模板（共 {unreadable} 张不可读）", user.Username);

        var similarity = best.Value;
        var diagnostic = $"{outcome.Diagnostic} sim {similarity:F4} thr {_opt.Threshold:F2} templates {usable}";

        if (similarity < _opt.Threshold)
            return Reject("FACE_MISMATCH", diagnostic, user.Username);

        return new VerifyResult
        {
            Passed = true,
            Username = user.Username,
            Message = "人脸验证通过",
            Similarity = similarity,
            Diagnostic = diagnostic
        };
    }
}
