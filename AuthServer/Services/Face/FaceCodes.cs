using AuthServer.Models;

namespace AuthServer.Services.Face;

/**
 * 人脸模块的**两套码**之间的映射，以及"这次失败要不要计入锁定窗口"的唯一判据。
 *
 * 与 VerifyCodeReason / SendCodeReason 同套路，刻意不合并：
 *   - BusinessCodes.Face*    出 HTTP 响应，**给用户看**；
 *   - AuditReason.Face*      只进审计库，**给审计员筛**；
 *   - 两者之间的映射只写在这一个文件里。
 *
 * 本文件还承担第二件事：**把"是否计失败"这条规则钉在审计码上**。
 * 详见下面 IsCounted 的注释 —— 这是这个模块最容易被写错、且写错后果最重的一处。
 */
public static class FaceCodes
{
    /// <summary>处理结果里除了特征之外的部分。</summary>
    public sealed record Outcome(bool Success, string BusinessCode, string AuditReason, string Message);

    public static Outcome Ok(string message = "人脸验证通过")
        => new(true, string.Empty, string.Empty, message);

    public static Outcome Fail(string businessCode, string message)
        => new(false, businessCode, ToAuditReason(businessCode), message);

    /// <summary>
    /// 业务 code → 审计原因码。
    ///
    /// ⚠️ 兜底分支刻意落到 **FaceMismatch（A 组 · 计次）**：
    /// 未知码意味着"有人新写了一个判定但忘了在这里登记"。这种时候宁可多计一次
    /// （代价是用户多试两次），也不要让它悄悄按"不计次"处理
    /// （代价是一个新加入的绕过路径永远不会被锁定）。
    /// 可用性损失可恢复，安全性损失不可恢复。
    /// </summary>
    public static string ToAuditReason(string businessCode) => businessCode switch
    {
        "FACE_MISMATCH" => AuditReason.FaceMismatch,
        "FACE_LIVENESS_FAILED" => AuditReason.FaceLivenessFailed,
        "FACE_CHALLENGE_INVALID" => AuditReason.FaceChallengeInvalid,
        "FACE_NO_FACE" => AuditReason.FaceNoFace,
        "FACE_LOW_QUALITY" => AuditReason.FaceLowQuality,
        "FACE_NOT_RETURNED" => AuditReason.FaceNotReturned,
        "FACE_ENGINE_UNAVAILABLE" => AuditReason.FaceEngineUnavailable,
        // 录入失败有自己的原因码：录入发生在**已登录之后**，一次录不上人脸没有安全含义，
        // 不该混进"本账号被连续判失败"的统计（详见 AuditReason.FaceEnrollRejected 的注释）。
        "FACE_ENROLL_FAILED" => AuditReason.FaceEnrollRejected,
        "FACE_NOT_ENROLLED" => AuditReason.FaceNoTemplate,
        _ => AuditReason.FaceMismatch
    };

    /// <summary>
    /// 这条审计原因码是否应当**计入 3 分钟失败窗口**。
    ///
    /// 为什么把规则钉在码上、而不是让每个调用点自己传一个 bool：
    ///   录了人脸的账号，在"口令对 + 人脸不过"时会走和口令错误同一条计数路径。
    ///   而人脸天生有一批**根本不是攻击**的失败（离太远、背光、动作没做完就凑上去、
    ///   做完没转回来）。如果靠调用点各自记得"这次别计数"，只要漏一处，
    ///   正常用户就会被自己的摄像头误伤到锁号 —— 这是这类功能最典型的翻车方式，
    ///   而且症状（"我明明是对的脸却登不上"）极难归因。
    ///   把规则定在码的分组上，新增判定时**选了哪一组的码就自动获得哪一组的语义**。
    ///
    ///   A 组（欺骗信号 / 主动绕过）：计次
    ///   B 组（质量与配合问题）  ：不计
    /// </summary>
    public static bool IsCounted(string auditReason) => auditReason switch
    {
        AuditReason.FaceMismatch => true,
        AuditReason.FaceLivenessFailed => true,
        AuditReason.FaceChallengeInvalid => true,
        AuditReason.FaceWrongPassword => true,
        _ => false
    };

    /// <summary>
    /// 把引擎/挑战层的内部原因串成对外话术。
    ///
    /// 措辞刻意区分"你该怎么做"和"这不是你的问题"，好让用户知道下一次该改什么：
    /// 质量问题 → 告诉他怎么调整；欺骗信号 → 不提示细节（否则等于告诉攻击者差在哪）。
    /// </summary>
    public static string MessageFor(string businessCode) => businessCode switch
    {
        "FACE_NO_FACE" => "没有检测到人脸，请正对摄像头再试一次",
        "FACE_LOW_QUALITY" => "画面质量不足，请靠近一些并保证光线充足",
        "FACE_NOT_RETURNED" => "动作完成后请转回正对摄像头",
        "FACE_MISMATCH" => "人脸验证未通过",
        "FACE_LIVENESS_FAILED" => "活体检测未通过，请按提示完成动作",
        "FACE_CHALLENGE_INVALID" => "本次验证已过期，请重新登录",
        "FACE_ENGINE_UNAVAILABLE" => "本机人脸引擎不可用（未检测到摄像头或模型缺失）",
        "FACE_NOT_ENROLLED" => "该账号尚未录入人脸",
        _ => "人脸验证未通过"
    };
}
