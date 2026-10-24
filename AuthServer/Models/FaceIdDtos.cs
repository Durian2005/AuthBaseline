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
 * 登录侧（P2）的请求体另建一个类型（<see cref="FaceIdLoginRequest"/>），不复用录入请求 ——
 * 与 2FA 当初"登录请求和录入请求刻意分成两个类型"的理由相同：
 * 两种请求的字段集不同，混用会让"某个字段在另一条路径上被忽略"这种事没人看得出。
 */

/// <summary>
/// 纯人脸登录的请求体：**只有用户名**。
/// 画面由服务端自己采集 —— 接口上不存在"传一张图 / 传一个特征"这种形状，
/// 所以"前端伪造向量直接登录"在类型层面就不可能。
/// </summary>
public class FaceIdLoginRequest
{
    public string Username { get; set; } = string.Empty;
}

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

    /// <summary>
    /// 主模型（ArcFace）的判定阈值 —— 通过线本身（P3 定档 0.30）。
    /// ⚠️ 阶段 2 起判定是**两个模型相与**，只报这一个数会让界面少说一半：
    ///    通过还需要 <see cref="SfaceThreshold"/> 那条线。
    /// </summary>
    public double Threshold { get; set; }

    /// <summary>
    /// 第二模型（SFace）的通过线（阶段 2 定档 0.46，独立标定，与 2FA 的 0.50 不同）。
    /// 与 <see cref="Threshold"/> 一起构成 AND：两个都要过才签票。
    ///
    /// ⚠️ 属性名刻意写作 `SfaceThreshold`（而不是 SFaceThreshold）：默认的 camelCase
    ///    策略只小写**首字母**，`SFace...` 会序列化成 `sFace...`，前端写 `sface...`
    ///    就永远读到 undefined 且不报错。
    /// </summary>
    public double SfaceThreshold { get; set; }

    /// <summary>当前模型身份（模板与它绑定；换模型 ⇒ 旧模板作废）。</summary>
    public string ModelId { get; set; } = string.Empty;

    /// <summary>本机引擎是否可用。</summary>
    public bool EngineReady { get; set; }

    /// <summary>引擎不可用时的原因（直接显示给用户）。</summary>
    public string EngineMessage { get; set; } = string.Empty;

    /// <summary>
    /// 活体判定（PAD）是否启用。
    /// 单独下发而不并进 EngineReady：两者是**独立的两件事**，
    /// 引擎好、活体模型缺失时用户看到的原因必须准确（否则会去反复调摄像头）。
    /// </summary>
    public bool PadEnabled { get; set; }

    /// <summary>活体模型是否就绪。PadEnabled 为 true 而它为 false ⇒ 录入会被 fail closed 拒绝。</summary>
    public bool PadReady { get; set; }

    /// <summary>活体判定当前阈值（已按 46 活人 + 120 攻击标定，见 FACEID-P1B-PAD-REPORT）。</summary>
    public double PadMinLive { get; set; }

    /// <summary>
    /// 是否拒绝"画面里有多张脸"。默认 true；为 false 时取面积最大那张
    /// （用照片做识别测试时需要 —— 举手机的人自己容易同框）。
    /// </summary>
    public bool RejectMultipleFaces { get; set; }
}
