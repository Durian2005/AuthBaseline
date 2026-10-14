namespace AuthServer.Models;

/**
 * 人脸模块的请求 / 响应 DTO。
 *
 * 一个刻意的共同点：**这些对象里从头到尾不出现特征向量、不出现画面。**
 * 前端不需要、也拿不到特征 —— 采集与特征提取全在服务端完成
 * （理由见 docs/design/FACE-AUTH-DESIGN.md §四：一旦让浏览器上送特征，
 *   攻击者就能完全不碰摄像头，直接伪造一个向量提交，活体挑战形同虚设）。
 */

/// <summary>
/// 服务端下发的活体挑战。动作**只随机、不加密** —— 用户必须知道要做什么；
/// 安全性来自"随机 + 新鲜 + 一次有效"，而不是来自保密。
/// </summary>
public class FaceChallengeResponse
{
    /// <summary>一次性挑战 token。与登录票据是两套东西，不可互换。</summary>
    public string ChallengeToken { get; set; } = string.Empty;

    /// <summary>动作标识：left / right / up / down。</summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>动作的中文指令，直接显示给用户（如"把头转向你的左侧"）。</summary>
    public string ActionText { get; set; } = string.Empty;

    /// <summary>动作提示（幅度、保持时间）。</summary>
    public string ActionHint { get; set; } = string.Empty;

    /// <summary>挑战剩余有效秒数。过期的挑战一律作废，不续期。</summary>
    public int ExpiresInSeconds { get; set; }

    /// <summary>
    /// 本机当前判定阈值（余弦相似度）。随挑战一起下发，是为了让识别画面上能显示
    /// "本机按 0.50 判定"这类**可核对的数字**，而不是让阈值变成一个只存在于代码里的魔数。
    /// 它不是秘密：拿到它同样要先通过口令。
    /// </summary>
    public double Threshold { get; set; }
}

/// <summary>登录第二阶段：提交人脸验证。只需挑战 token，画面由服务端自己采。</summary>
public class FaceVerifyRequest
{
    public string ChallengeToken { get; set; } = string.Empty;
}

/// <summary>
/// 本人录入人脸（第一步：申请动作挑战）。
///
/// **必须重新输入当前口令**，首次录入也不例外。理由是一条具体的绕过路径：
///   人脸是与口令**同时**成立的第二因子。若"加一张模板"不需要口令，那么一个
///   同时拿到口令与一个有效会话的人，就能把自己的脸录进去 ——
///   从此他既知道口令、又能过人脸，第二因子被完整绕开，而且**改成新口令也甩不掉**
///   （模板不会随改口令消失）。
///   也就是说：这条路径的代价比"删模板"那条更高，闸门至少不能更松。
///   与 create-account / set-role 的二次口令是同一个套路。
/// </summary>
public class FaceEnrollRequest
{
    /// <summary>
    /// 当前登录口令（必填）。校验通过后才签发本轮的录入挑战。
    /// </summary>
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// 本人录入人脸（第二步：提交上一步拿到的挑战）。
///
/// 与登录第二阶段的请求**刻意分成两个类型**，尽管字段一模一样：
///   两者的挑战用途不同（enroll / login），服务端会核对，
///   而类型分开能让"把录入的请求体丢给登录接口"这件事在编译期就显得别扭。
/// </summary>
public class FaceEnrollCompleteRequest
{
    /// <summary>第一步 <c>POST face/enroll</c> 返回的一次性挑战 token。</summary>
    public string ChallengeToken { get; set; } = string.Empty;
}

/// <summary>
/// 删除本人的人脸模板。**必须重新输入口令** ——
/// 这是"可选"这条设计自带的降级通道上唯一的闸门：
/// 拿到一个有效会话的人，若能顺手把模板删掉，该账号就永久退回单因子。
/// </summary>
public class FaceDeleteRequest
{
    public string Password { get; set; } = string.Empty;
}

/// <summary>本人人脸状态。用于账号页显示"有没有录、录了几张、什么时候录的"。</summary>
public class FaceStatusResponse
{
    /// <summary>是否已录入（至少有一张可用模板）。</summary>
    public bool Enrolled { get; set; }

    /// <summary>当前模板张数（上限 8）。</summary>
    public int TemplateCount { get; set; }

    /// <summary>最近一次录入时刻（UTC）。未录入时为 null。</summary>
    public DateTime? EnrolledAt { get; set; }

    /// <summary>
    /// 当前判定阈值（余弦相似度）。下发它是为了让界面上能显示
    /// "本机当前按 0.50 判定"这类可核对的数字，而不是让阈值变成一个只存在于代码里的魔数。
    /// </summary>
    public double Threshold { get; set; }

    /// <summary>本机人脸引擎当前是否可用（模型加载成功、摄像头可打开）。</summary>
    public bool EngineReady { get; set; }

    /// <summary>引擎不可用时的原因，直接显示给用户（如"未检测到摄像头"）。</summary>
    public string EngineMessage { get; set; } = string.Empty;
}

/// <summary>
/// 管理员重置某账号的人脸（用于"换人 / 设备更换 / 疑似泄露后作废"）。
/// 与注销同属**处置**类操作，走同一个权限出口 <c>UserRoles.CanBeManagedBy</c>。
/// </summary>
public class ResetFaceRequest
{
    /// <summary>目标账号用户名。</summary>
    public string Username { get; set; } = string.Empty;
}
