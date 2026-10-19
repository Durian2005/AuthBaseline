using AuthServer.Models;

namespace AuthServer.Services.FaceId;

/**
 * FaceId 模块的**两套码**之间的映射，以及"这次失败要不要计入失败窗口"的唯一判据。
 *
 * 与 <see cref="AuthServer.Services.Face.FaceCodes"/> 同套路、**代码独立**：
 *   业务码（BusinessCode.FaceId*）→ HTTP 响应，给用户看；
 *   审计码（AuditReason.FaceId*）→ 只进审计库，给审计员筛。
 *   映射只写在这一个文件里，别处不许自己拼字符串。
 *
 * 与 2FA 的差异（本模块特有的取舍）：
 *   2FA 的 A 组包含 MISMATCH / LIVENESS / CHALLENGE_INVALID —— 那是登录链路上的
 *   欺骗信号。本模块 P1a 只有**录入**，而录入发生在已登录之后，失败没有安全含义，
 *   所以当时全部归 B 组（不计次）。P1b 补了活体判定之后，多了一条**计次**的码
 *   （LIVENESS_FAILED）—— 它的理由不是"录入本身危险"，而是"连续失败说明有人在拿照片试"。
 *   P2（见下）补上了登录侧的两个码：MISMATCH 计次（等价于口令错），
 *   GRAY_ZONE 不计（证据不足 ≠ 证明不是）。扩展方式仍是"码决定分组"，计数逻辑一行没动。
 */
public static class FaceIdCodes
{
    /// <summary>处理结果里"业务码 + 审计码 + 话术"的三元组。</summary>
    public sealed record Outcome(bool Success, string BusinessCode, string AuditReason, string Message);

    public static Outcome Ok(string message = "人脸录入成功")
        => new(true, string.Empty, string.Empty, message);

    public static Outcome Fail(string businessCode, string message)
        => new(false, businessCode, ToAuditReason(businessCode), message);

    /// <summary>
    /// 业务码 → 审计原因码。
    ///
    /// ⚠️ 兜底分支刻意落到 **FaceIdEnrollRejected（B 组·不计）** 而不是某个"计次"的码：
    ///    本模块的默认处境是"已登录用户在录人脸"，未知原因多计一次只会误伤本人；
    ///    而真正的口令猜测有它自己的码（FaceIdWrongPassword），不依赖兜底。
    ///    这与 2FA 的兜底方向（落 A 组）**刻意的不同**，因为两条链路的默认处境相反：
    ///    2FA 的未知码出现在登录路径上，宁可多计；这里出现在录入路径上，宁可少计。
    /// </summary>
    public static string ToAuditReason(string businessCode) => businessCode switch
    {
        "FACEID_ENGINE_UNAVAILABLE" => AuditReason.FaceIdEngineUnavailable,
        "FACEID_DISABLED" => AuditReason.FaceIdEngineUnavailable,
        "FACEID_NO_FACE" => AuditReason.FaceIdEnrollRejected,
        "FACEID_MULTIPLE_FACES" => AuditReason.FaceIdEnrollRejected,
        "FACEID_FACE_TOO_SMALL" => AuditReason.FaceIdEnrollRejected,
        "FACEID_NOT_FRONTAL" => AuditReason.FaceIdEnrollRejected,
        "FACEID_LOW_QUALITY" => AuditReason.FaceIdEnrollRejected,
        "FACEID_ENROLL_FAILED" => AuditReason.FaceIdEnrollRejected,
        "FACEID_MODEL_MISMATCH" => AuditReason.FaceIdModelMismatch,
        "FACEID_LIVENESS_FAILED" => AuditReason.FaceIdLivenessFailed,
        "FACEID_NOT_ENROLLED" => AuditReason.FaceIdNoTemplate,
        "FACEID_MISMATCH" => AuditReason.FaceIdMismatch,
        "FACEID_GRAY_ZONE" => AuditReason.FaceIdGrayZone,
        _ => AuditReason.FaceIdEnrollRejected
    };

    /// <summary>
    /// 这条审计原因码是否应当**计入 3 分钟失败窗口**。
    ///
    /// 规则钉在码上（同 2FA）：新增判定时选了哪一组的码，就自动获得哪一组的语义，
    /// 调用点不需要、也不允许自己传一个 bool。
    /// </summary>
    public static bool IsCounted(string auditReason) => auditReason switch
    {
        AuditReason.FaceIdWrongPassword => true,
        AuditReason.FaceIdLivenessFailed => true,
        // 登录侧：明确不是本人 ⇒ 计次（与口令错同等地位）；灰区不计。
        AuditReason.FaceIdMismatch => true,
        _ => false
    };

    /// <summary>质量闸门结论 → 业务码。Pass 不会走到这里（调用方先判 Passed）。</summary>
    public static string BusinessCodeFor(FaceIdQualityVerdict verdict) => verdict switch
    {
        FaceIdQualityVerdict.NoFace => BusinessCode.FaceIdNoFace,
        FaceIdQualityVerdict.MultipleFaces => BusinessCode.FaceIdMultipleFaces,
        FaceIdQualityVerdict.TooSmall => BusinessCode.FaceIdTooSmall,
        FaceIdQualityVerdict.NotFrontal => BusinessCode.FaceIdNotFrontal,
        FaceIdQualityVerdict.Blurry => BusinessCode.FaceIdLowQuality,
        _ => BusinessCode.FaceIdEnrollFailed
    };

    /// <summary>
    /// 把内部原因串成对外话术。
    ///
    /// 质量类提示刻意**说清下一步该做什么**（靠近 / 擦镜头 / 只留一个人），
    /// 因为录入失败几乎全是配合问题；而"多脸"那条要说得克制 ——
    /// 不要让人误以为系统在拍别人，只说明"画面里只能有一个人"。
    /// </summary>
    public static string MessageFor(string businessCode) => businessCode switch
    {
        "FACEID_DISABLED" => "本系统的纯人脸登录当前未启用",
        "FACEID_ENGINE_UNAVAILABLE" => "本机人脸引擎不可用（未检测到摄像头或模型缺失）",
        "FACEID_NO_FACE" => "没有检测到人脸，请正对摄像头再试一次",
        "FACEID_MULTIPLE_FACES" => "画面里只能有一个人，请确保其他人都离开镜头范围",
        "FACEID_FACE_TOO_SMALL" => "人脸太小，请坐近一点再试",
        "FACEID_NOT_FRONTAL" => "请正对摄像头，不要侧脸或歪头",
        "FACEID_LOW_QUALITY" => "画面不够清晰，请保持不动或调整光线后再试",
        "FACEID_ENROLL_FAILED" => "人脸录入未通过，请重新尝试",
        "FACEID_NOT_ENROLLED" => "该账号尚未录入可用于登录的人脸",
        "FACEID_MODEL_MISMATCH" => "已录入的人脸模板与当前模型不匹配，请重新录入",
        "FACEID_LIVENESS_FAILED" => "未通过活体检测：画面里像是照片或屏幕，请由本人现场正对摄像头",
        "FACEID_MISMATCH" => "人脸与已录入的模板不匹配，请正对摄像头重试，或改用口令登录",
        "FACEID_GRAY_ZONE" => "这次识别把握不足（可能是光线或角度问题），请改用口令登录，或调整后重试",
        _ => "人脸录入未通过"
    };
}
