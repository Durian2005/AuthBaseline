namespace AuthServer.Models;

/**
 * 纯人脸登录（FaceId）的请求 / 响应 DTO。
 *
 * 与 <see cref="FaceChallengeResponse"/> 那一套（2FA）**刻意分开**：
 *   本模块没有动作挑战、没有预览、没有帧传输 —— 请求体里只有口令，
 *   因为在"服务端自己开摄像头"的前提下，把画面或特征交给前端再传回来
 *   就等于给攻击者开了一条"完全绕开摄像头"的伪造入口。
 *
 * 人脸录入（P1）只做两件事：确认操作者知道当前口令、采集并保存一张模板。
 * 登录侧（P2）的 DTO 会另建一套，不复用这里的类型 ——
 * 与 2FA 当初"登录请求和录入请求刻意分成两个类型"的理由相同。
 */

/// <summary>
/// 录入 / 删除 FaceId 模板时的二次口令。
///
/// **必须重新输入当前口令**，首次录入也不例外：
///   纯人脸登录是"用户名 + 人脸"的完整登录方式，若拿到会话就能给自己加一张模板，
///   那么一个同时拿到口令与会话的人可以把自己的脸录进去，从此只需刷脸即可登录 ——
///   而且改口令之后**依然有效**（模板不会随改口令消失）。
///   这条路径的门槛因此与"改口令"同级，而不是与"看状态"同级。
/// </summary>
public class FaceIdPasswordRequest
{
    public string Password { get; set; } = string.Empty;
}

/// <summary>本人 FaceId 状态。用于账号页显示"能不能用、录了几张、为什么不能用"。</summary>
public class FaceIdStatusResponse
{
    /// <summary>模块是否启用（关闭时整块界面应当只显示一行说明）。</summary>
    public bool Enabled { get; set; }

    /// <summary>是否存在模板（含已作废的旧模型模板）。</summary>
    public bool Enrolled { get; set; }

    /// <summary>模板总数（含旧模型）。</summary>
    public int TemplateCount { get; set; }

    /// <summary>当前模型下**可用**的模板数。0 而 TemplateCount &gt; 0 ⇒ 模型换了，需重新录入。</summary>
    public int UsableCount { get; set; }

    /// <summary>因模型不匹配而作废的模板数。</summary>
    public int ModelMismatchCount { get; set; }

    /// <summary>最近一次录入时刻（UTC）。未录入为 null。</summary>
    public DateTime? EnrolledAt { get; set; }

    /// <summary>每人模板上限（安全参数，不是性能参数）。</summary>
    public int MaxTemplates { get; set; }

    /// <summary>当前判定阈值（P3 定档前只是起点）。</summary>
    public double Threshold { get; set; }

    /// <summary>当前模型身份（模板与它绑定；换模型 ⇒ 旧模板作废）。</summary>
    public string ModelId { get; set; } = string.Empty;

    /// <summary>本机引擎是否可用。</summary>
    public bool EngineReady { get; set; }

    /// <summary>引擎不可用时的原因（直接显示给用户）。</summary>
    public string EngineMessage { get; set; } = string.Empty;
}
