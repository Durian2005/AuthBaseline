using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthServer.Models;

public class AuditLog
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = string.Empty;

    [BsonElement("operatorId")]
    public string OperatorId { get; set; } = string.Empty;

    [BsonElement("operatorName")]
    public string OperatorName { get; set; } = string.Empty;

    [BsonElement("action")]
    public string Action { get; set; } = string.Empty;

    [BsonElement("statusBefore")]
    public string StatusBefore { get; set; } = string.Empty;

    // 存 JSON 字符串，避免 MongoDB ObjectSerializer 拒绝序列化自定义类型
    [BsonElement("request")]
    public string Request { get; set; } = string.Empty;

    [BsonElement("response")]
    public string Response { get; set; } = string.Empty;

    [BsonElement("statusAfter")]
    public string StatusAfter { get; set; } = string.Empty;

    /// <summary>
    /// 操作结果：成功 / 失败。
    /// 仅看 Action 无法判断操作是否被拒绝（例如 LOGIN 既可能是成功也可能是口令错误），
    /// 因此结果必须独立成列，审计时才能真正区分"登录成功"与"登录失败"。
    /// </summary>
    [BsonElement("result")]
    public string Result { get; set; } = AuditResult.Success;

    /// <summary>被操作的对象用户名（注册/审核/解锁/注销/转让等场景），便于按对象检索。</summary>
    [BsonElement("target")]
    public string Target { get; set; } = string.Empty;

    [BsonElement("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /* ==================== 实验二新增：追责维度 ==================== */

    /// <summary>
    /// 失败 / 拒绝的原因码（如 ACCOUNT_LOCKED、UNAUTHORIZED、WEAK_PASSWORD）。
    /// 成功事件为空串。
    ///
    /// 为什么必须独立成列：只有 result=失败 时，审计员仍不知道"为什么失败"——
    /// 是口令错了、账号被锁，还是越权尝试？原因码把这三者区分开，
    /// 且使"越权尝试"这类高价值线索可以被直接检索出来。
    ///
    /// 兼容性：改造前的老记录没有该字段，读出来是空串，不影响既有界面与筛选。
    /// </summary>
    [BsonElement("reasonCode")]
    public string ReasonCode { get; set; } = string.Empty;

    /// <summary>
    /// 发起本次操作的主体类型：user（已认证）/ anonymous（未认证或身份不可信）/ system（系统自动触发）。
    /// 改造前的老记录该字段为空串，由前端按 operatorId 是否为 anonymous 兜底推断。
    /// </summary>
    [BsonElement("actorType")]
    public string ActorType { get; set; } = string.Empty;

    /// <summary>来源信息（IP + UserAgent），用于回答"这次越权尝试是从哪里发起的"。</summary>
    [BsonElement("sourceIp")]
    public string SourceIp { get; set; } = string.Empty;

    [BsonElement("sourceUserAgent")]
    public string SourceUserAgent { get; set; } = string.Empty;

    /* ==================== 实验二新增：防篡改哈希链 ==================== */

    /// <summary>
    /// 本条记录的自哈希（SHA-256，64 位小写十六进制）。
    /// 输入为"规范化字段串"，见 AuditService.ComputeHash。
    /// 空串表示该记录产生于哈希链上线之前（老数据），完整性校验会跳过它。
    /// </summary>
    [BsonElement("selfHash")]
    public string SelfHash { get; set; } = string.Empty;

    /// <summary>
    /// 前一条记录的 selfHash，链首为 64 个 0。
    ///
    /// 该字段把"单条被改"升级为"整链可验"：
    ///   - 改了本条内容 → 本条 selfHash 与存储值不符；
    ///   - 删了中间一条 → 后一条的 prevHash 对不上，断点立刻暴露；
    ///   - 调换两条顺序 → 两条的 prevHash 同时错位。
    /// </summary>
    [BsonElement("prevHash")]
    public string PrevHash { get; set; } = string.Empty;

    /// <summary>链内严格递增序号，用于定位断点与跨分片排序（时间戳可能重复，不能作序）。</summary>
    [BsonElement("seq")]
    public long Seq { get; set; }

    /// <summary>所在分片集合名，如 AuditLogs_202609。便于归档后按片检索与校验。</summary>
    [BsonElement("shard")]
    public string Shard { get; set; } = string.Empty;
}

/// <summary>主体类型取值。</summary>
public static class ActorType
{
    public const string User = "user";
    public const string Anonymous = "anonymous";
    public const string System = "system";
}

/// <summary>审计结果取值，避免各处硬编码字符串不一致。</summary>
public static class AuditResult
{
    public const string Success = "成功";
    public const string Failed = "失败";
}

/// <summary>审计动作取值。</summary>
public static class AuditAction
{
    public const string Register = "REGISTER";
    public const string LoginSuccess = "LOGIN_SUCCESS";
    public const string LoginFailed = "LOGIN_FAILED";
    public const string Login = "LOGIN"; // 历史数据沿用，新日志已拆分为上面两项

    /// <summary>
    /// 口令修改**失败**。与 ChangePassword 分开的理由：
    ///   "改密成功"是普通操作，"改密被拒"是安全事件 ——
    ///   admin 反复提交不合规的口令、或反复猜自己的旧口令，都属于后者。
    ///   若沿用同一个 action，只能靠 result=失败 间接区分，
    ///   审计员无法用一条查询把"全部改密失败"单独列出来定级。
    /// </summary>
    public const string ChangePasswordFailed = "CHANGE_PASSWORD_FAILED";

    public const string Approve = "APPROVE";
    public const string Unlock = "UNLOCK";
    public const string DeleteUser = "DELETE_USER";
    public const string ChangePassword = "CHANGE_PASSWORD";
    public const string TransferAdmin = "TRANSFER_ADMIN"; // 历史数据沿用，新版本已废弃该功能

    // ---- 角色分离：账号创建与角色任免 ----
    public const string CreateAccount = "CREATE_ACCOUNT";  // 管理员创建账号（含目标角色）
    public const string SetRole = "SET_ROLE";              // 变更他人角色（如任命审计管理员）

    // ---- 邮箱验证码相关 ----
    public const string SendEmailCode = "SEND_EMAIL_CODE";
    public const string ResetPassword = "RESET_PASSWORD";

    /// <summary>重置口令失败（验证码错 / 状态不允许 / 邮箱不匹配）。与上者同理：失败即安全事件。</summary>
    public const string ResetPasswordFailed = "RESET_PASSWORD_FAILED";

    /// <summary>发送验证码被拒（邮箱不存在 / 状态不允许 / 触发限流）。</summary>
    public const string SendEmailCodeFailed = "SEND_EMAIL_CODE_FAILED";

    // ---- 实验二：会话与审计查询相关 ----
    public const string Logout = "LOGOUT";                 // 主动登出，吊销票据
    public const string AuditQuery = "AUDIT_QUERY";        // 查询审计日志（成功也留痕）
    public const string AuditVerify = "AUDIT_VERIFY";      // 执行完整性校验
    public const string AuditAccessDenied = "AUDIT_ACCESS_DENIED"; // 无权限访问审计数据
    public const string AuditTampered = "AUDIT_TAMPERED";  // 校验发现链断裂
    /// <summary>职责分离绕过线索扫描：检测动作本身也要留痕。</summary>
    public const string SodScan = "SOD_SCAN";              // 职责分离绕过（检测层自身留痕）

    /// <summary>
    /// 检测到系统时钟被拨动（墙钟与本机运行时长两条时间线背离）。
    ///
    /// 为什么要独立成一个动作：加固前，靠拨钟解开锁定是**完全静默**的 ——
    /// 锁定到期走的是登录里的"自动恢复"分支，而那个分支不写任何审计。
    /// 事后翻日志，看不出这个账号曾被"用改时间的方式"放进去过。
    /// 有了这条记录，"有人动过时钟"本身就成为可检索的事件。
    ///
    /// 注意一个诚实的限度：这条记录自己的 timestamp 也来自那个被拨动的时钟，
    /// 所以它的**时间**同样不可信；可信的是"背离量"与两个时间线的读数
    /// （写在 request 报文里），那才是判断拨了多少的依据。
    /// </summary>
    public const string ClockAnomaly = "CLOCK_ANOMALY";

    /// <summary>
    /// 口令哈希的存储格式已升级：旧格式（无 pepper）→ 新格式（含 pepper）。
    ///
    /// 为什么要单独留痕，而不是"悄悄改掉就算了"：
    /// 这条记录回答的是"这个账号的口令从什么时候开始受 pepper 保护"。
    /// 迁移期结束后，凡是**没有**这条记录的账号，其口令仍是旧格式 ——
    /// 也就是说，一条查询就能拉出"还没升级的存量清单"。
    /// 没有它的话，"还有多少账号没升级"只能靠直连数据库统计，审计员无从下手。
    /// </summary>
    public const string PasswordHashUpgraded = "PASSWORD_HASH_UPGRADED";

    // ---- 沉睡（僵尸）账号治理 ----
    // 为什么冻结沿用 Unlock 的反向动作而不复用 SetRole / DeleteUser：
    // 治理动作必须在审计里与"日常管理"分得开 —— 审计员要能一条查询
    // 捞出"全部因沉睡治理而冻结/解冻的账号"，否则这类批量处置会淹没在普通操作里。

    /// <summary>因沉睡治理冻结账号（置 Disabled，登录被拒，可解冻）。</summary>
    public const string DormantFreeze = "DORMANT_FREEZE";

    /// <summary>解除冻结（Disabled → Enabled），账号恢复可登录。</summary>
    public const string DormantRestore = "DORMANT_RESTORE";

    /* ==================== 人脸（可选第二因子） ==================== */
    // 为什么人脸要占这么多独立动作码、而不是塞进 LOGIN_* 里：
    // 人脸是**可选**启用的，于是"一个账号有没有这道防线"本身就是可以变化的事实。
    // 审计员必须能用一条查询捞出"哪些账号刚把这道防线加上 / 拿掉"——
    // 若与普通登录事件混在一起，"某账号在 3 分钟前被删掉了人脸"就会被淹没。
    //
    // ⚠️ 这些常量只出现在 AuditLog.Action 的**取值**里，
    //    没有给 AuditLog 加任何字段 —— 哈希链的输入字段是锁死的（见 AuditService.ComputeHash），
    //    人脸的所有细节走 request / response 的 JSON 袋。

    /// <summary>本人录入人脸模板成功（首次录入或更换）。</summary>
    public const string FaceEnroll = "FACE_ENROLL";

    /// <summary>录入被拒（活体未过 / 质量问题 / 引擎不可用）。</summary>
    public const string FaceEnrollFailed = "FACE_ENROLL_FAILED";

    /// <summary>
    /// 口令已通过、按策略要求第二因子，但**尚未签发任何票据**。
    ///
    /// 这条记录是"半程登录"的留痕点：它证明口令那一因子确实过了。
    /// 有了它，"口令对了但人脸一直不过"这种形态才可能在审计里被数出来 ——
    /// 否则这段过程在库里完全隐形（既没有 LOGIN_SUCCESS 也没有 LOGIN_FAILED）。
    /// </summary>
    public const string FaceLoginRequired = "FACE_LOGIN_REQUIRED";

    /// <summary>人脸通过，登录完成（与 LOGIN_SUCCESS 同时产生，两条各记一次）。</summary>
    public const string FaceLoginSuccess = "FACE_LOGIN_SUCCESS";

    /// <summary>人脸未通过，登录失败。</summary>
    public const string FaceLoginFailed = "FACE_LOGIN_FAILED";

    /// <summary>
    /// 本人删除自己的人脸模板。
    ///
    /// 独立成码而不是并入注销/改密：删除模板等于**主动把自己降级成单因子**。
    /// 这条流水单独可查，才能回答"某个账号的防护强度是什么时候被削弱的"。
    /// </summary>
    public const string FaceTemplateDeleted = "FACE_TEMPLATE_DELETED";

    /// <summary>管理员重置他人人脸模板（处置类操作，与注销同权限出口）。</summary>
    public const string FaceTemplateReset = "FACE_TEMPLATE_RESET";

    /* ==================== 纯人脸登录（FaceId） ==================== */
    // 与上面 FACE_* 是**两条链路**的动作码，刻意不共用（理由同 BusinessCode 的注释）：
    //   FACE_*   是"口令之后的第二因子"；
    //   FACEID_* 是"用户名 + 人脸"的独立登录方式（P2 会补齐登录侧的动作码）。
    // 混用会让"这个账号的哪条链路被削弱了"变成一道需要靠上下文推断的题。

    /// <summary>本人录入 FaceId 模板成功。</summary>
    public const string FaceIdEnroll = "FACEID_ENROLL";

    /// <summary>FaceId 录入被拒（质量 / 引擎 / 口令二次确认失败）。</summary>
    public const string FaceIdEnrollFailed = "FACEID_ENROLL_FAILED";

    /// <summary>本人删除 FaceId 模板（等于主动放弃这种登录方式）。</summary>
    public const string FaceIdTemplateDeleted = "FACEID_TEMPLATE_DELETED";
}

/// <summary>
/// 失败 / 拒绝的原因码。
///
/// 与 HTTP 状态码、业务 code 的区别：
///   - HTTP 状态码表达"传输层结果"；
///   - 业务 code 表达"接口层面的业务判定"；
///   - reasonCode 是**审计语义**上的归类，专门回答"这次操作为什么没成功"，
///     并且要让"越权"和"口令错误"能被一条查询直接分开。
/// </summary>
public static class AuditReason
{
    // 会话 / 授权
    public const string NoTicket = "NO_TICKET";
    public const string SessionInvalid = "SESSION_INVALID";
    public const string SessionExpired = "SESSION_EXPIRED";
    public const string SessionRevoked = "SESSION_REVOKED";
    public const string NotAdmin = "NOT_ADMIN";

    /// <summary>
    /// 有登录身份，但不是审计管理员，因此无权查看审计数据。
    ///
    /// 与 NotAdmin 分开的理由：管理员访问审计接口时，若只回 NOT_ADMIN，
    /// 审计员看到的线索是"某个非管理员在试探"，而真实情况是
    /// "一个正常管理员越过了职责边界去够审计数据" —— 这是职责分离
    /// 被破坏的直接证据，价值远高于普通的权限不足，必须能单独检索出来。
    /// </summary>
    public const string NotAuditAdmin = "NOT_AUDIT_ADMIN";

    /// <summary>越界提权：试图把自己或他人设为无权设定的角色（如自封管理员）。</summary>
    public const string ForbiddenRole = "FORBIDDEN_ROLE";

    /// <summary>越界处置：试图操作自己无权处置的目标（如管理员去动另一个管理员）。</summary>
    public const string ForbiddenTarget = "FORBIDDEN_TARGET";

    public const string AccountNotEnabled = "ACCOUNT_NOT_ENABLED";

    // 业务
    public const string InvalidCredentials = "INVALID_CREDENTIALS";

    /// <summary>
    /// 旧口令错误。
    ///
    /// 与 InvalidCredentials 分开的理由：两者都会返回同一个业务 code
    /// （对外统一话术，不透露用户名是否存在），但审计语义完全不同 ——
    /// INVALID_CREDENTIALS 是"账号根本不存在"，本码是"账号存在、登录口令不符"。
    /// 后者是口令猜测攻击的直接指纹，必须能单独检索。
    /// </summary>
    public const string WrongOldPassword = "WRONG_OLD_PASSWORD";

    /// <summary>新旧口令完全相同，被策略拒绝（改密后等于没改）。</summary>
    public const string PasswordReused = "PASSWORD_REUSED";

    public const string AccountLocked = "ACCOUNT_LOCKED";
    public const string PendingApproval = "PENDING_APPROVAL";
    public const string AccountDisabled = "ACCOUNT_DISABLED";
    public const string WeakPassword = "WEAK_PASSWORD";
    public const string EmptyFields = "EMPTY_FIELDS";
    public const string DuplicateUsername = "DUPLICATE_USERNAME";
    public const string InvalidEmail = "INVALID_EMAIL";
    public const string NotFound = "NOT_FOUND";
    public const string NotPending = "NOT_PENDING";
    public const string NotLocked = "NOT_LOCKED";

    /// <summary>目标未被冻结，因此"解除冻结"无从下手（与 NotLocked 同理，但针对治理冻结）。</summary>
    public const string NotFrozen = "NOT_FROZEN";

    /// <summary>
    /// 目标角色受保护，不参与沉睡冻结（Admin / UserAdmin / AuditAdmin）。
    ///
    /// 独立成码而不是共用 ForbiddenTarget：两者含义不同 ——
    /// ForbiddenTarget 是"你没有资格处置他"（关系问题，换个人就能办），
    /// 本码是"**谁都不能**冻结这个角色"（结构性问题，换谁都不行）。
    /// 混在一起会让审计员误以为换个管理员就能冻结管理账号。
    /// </summary>
    public const string DormantProtectedRole = "DORMANT_PROTECTED_ROLE";
    public const string CodeInvalid = "CODE_INVALID";

    /// <summary>验证码与所填邮箱不是同一封信。</summary>
    public const string EmailMismatch = "EMAIL_MISMATCH";

    /// <summary>验证码已过期。</summary>
    public const string CodeExpired = "CODE_EXPIRED";

    /// <summary>验证码错误次数用尽，记录已作废。</summary>
    public const string CodeTooManyAttempts = "CODE_TOO_MANY_ATTEMPTS";

    /// <summary>验证码已使用过（一次性，用过即废）。</summary>
    public const string CodeUsed = "CODE_USED";

    /// <summary>未填验证码。</summary>
    public const string CodeRequired = "CODE_REQUIRED";

    /// <summary>发码过于频繁，触发 60 秒冷却。</summary>
    public const string ResendTooSoon = "RESEND_TOO_SOON";

    /// <summary>发信通道未启用（EMAIL_DISABLED），口令找回链路整体不可用。</summary>
    public const string EmailDisabled = "EMAIL_DISABLED";

    /// <summary>发码用途不合法（既不是 REGISTER 也不是 RESET）。</summary>
    public const string InvalidPurpose = "INVALID_PURPOSE";

    /// <summary>发信失败（SMTP / 通道异常），验证码未能送达。</summary>
    public const string EmailSendFailed = "EMAIL_SEND_FAILED";

    /// <summary>目标邮箱已被其它账号绑定，不能再用于注册。</summary>
    public const string EmailAlreadyBound = "EMAIL_ALREADY_BOUND";

    /// <summary>角色未发生变化（请求的新角色与目标当前角色一致，无需变更）。</summary>
    public const string RoleUnchanged = "ROLE_UNCHANGED";

    // 完整性
    public const string ChainBroken = "CHAIN_BROKEN";

    // ---- 时钟背离（配合 AuditAction.ClockAnomaly） ----

    /// <summary>
    /// 墙钟快于单调线 —— 被**前拨**了。
    /// 这是"想靠改时间提前解开锁定"的直接指纹，也是本次加固要盯住的那一类。
    /// </summary>
    public const string ClockRolledForward = "CLOCK_ROLLED_FORWARD";

    /// <summary>
    /// 墙钟慢于单调线 —— 被**回拨**了。
    ///
    /// 与上者分开的理由：两者的安全含义完全不同。前拨是**攻击**（试图提前解锁）；
    /// 回拨通常是**事故**（主板电池耗尽、虚拟机快照回滚），后果是把锁定拖得极长。
    /// 混在一个码里，审计员无法区分"有人在攻击"和"有台机器坏了"。
    /// </summary>
    public const string ClockRolledBackward = "CLOCK_ROLLED_BACKWARD";

    /* ==================== 人脸：原因码按"是否计失败"分成两组 ====================
     *
     * 为什么必须分组，而不是笼统给一个 FACE_FAILED：
     *
     * 录了人脸的账号，在"口令对 + 人脸不过"时会走和口令错误同一条失败计数路径。
     * 于是人脸天生的**质量问题**（离得太远、背光、动作没做完就凑上去）会被
     * 当成攻击来罚 —— 正常人被自己的摄像头误伤到锁号，是这类功能最常见的翻车方式。
     *
     * 所以两组码从**语义**上就分开，而不是靠调用方各自记得"这次要不要计数"：
     *   · A 组（欺骗信号 / 明确的绕过尝试）→ **计入 3 分钟失败窗口**
     *   · B 组（质量问题 / 交互没配合好）  → **不计**
     * 把这条规则写在码的分组上，任何新加的判定只要选了 A 组就自动获得计数语义，
     * 不必再去改计数逻辑。
     */

    // ---- A 组：计入失败窗口 ----

    /// <summary>相似度低于阈值：人脸对不上。（A 组 · 计次）</summary>
    public const string FaceMismatch = "FACE_MISMATCH";

    /// <summary>
    /// 动作挑战未通过 / 采样期间人脸发生明显跳变。
    /// 这是"拿照片或预录视频来糊弄"的直接指纹。（A 组 · 计次）
    /// </summary>
    public const string FaceLivenessFailed = "FACE_LIVENESS_FAILED";

    /// <summary>
    /// 挑战 token 无效：过期、已被消费、或不属于本次登录尝试。
    ///
    /// 单独成码的理由：这三种情况的共同点是"绕过正常交互去用这张票"，
    /// 是主动构造出来的请求，不是手滑。（A 组 · 计次）
    /// </summary>
    public const string FaceChallengeInvalid = "FACE_CHALLENGE_INVALID";

    // ---- B 组：**不计入**失败窗口 ----

    /// <summary>画面里没检测到人脸（人还没坐好）。（B 组 · 不计）</summary>
    public const string FaceNoFace = "FACE_NO_FACE";

    /// <summary>人脸质量不达标：离镜头太远、光照不足、侧脸过大。（B 组 · 不计）</summary>
    public const string FaceLowQuality = "FACE_LOW_QUALITY";

    /// <summary>动作做完了但没有回正对镜头，拿不到可比较的那一帧。（B 组 · 不计）</summary>
    public const string FaceNotReturned = "FACE_NOT_RETURNED";

    // ---- 与失败计数无关的两条 ----

    /// <summary>
    /// 账号本身没有模板，却被要求过人脸 —— 说明流程判断出了问题，
    /// 不是用户的行为，所以既不算失败也不该出现。
    /// </summary>
    public const string FaceNoTemplate = "FACE_NO_TEMPLATE";

    /// <summary>人脸引擎不可用（模型加载失败 / 摄像头打不开）。属于本机环境问题，不是攻击。</summary>
    public const string FaceEngineUnavailable = "FACE_ENGINE_UNAVAILABLE";

    /// <summary>删除 / 更换人脸时二次口令不符。（A 组 · 计次 —— 它本身就是对本人口令的一次猜测）</summary>
    public const string FaceWrongPassword = "FACE_WRONG_PASSWORD";

    /// <summary>
    /// 录入过程未通过（活体或质量原因），模板没有被写入。（B 组 · 不计）
    ///
    /// 为什么单独占一个码、而不是复用 FaceLivenessFailed / FaceNoFace：
    ///   录入发生在**已登录之后**。这里的失败与"登录被判失败"是完全不同的处境 ——
    ///   用户手里已经有会话了，一次录不上人脸没有任何安全含义，
    ///   也不该出现在"本账号被连续判失败"的统计里。
    ///   给它一个独立码，"过程失败"与"认证失败"就不会在审计里混成一类。
    /// </summary>
    public const string FaceEnrollRejected = "FACE_ENROLL_REJECTED";

    /* ==================== 纯人脸登录（FaceId）的原因码 ====================
     *
     * 分组规则与 2FA 一致：**A 组计次、B 组不计**。
     * 但本模块的"计次"语义更窄 —— P1 只有录入这一条路径，
     * 而录入发生在**已登录之后**，一次录不上没有任何安全含义。
     * 唯一计次的是"口令二次确认失败"（它本身就是对账号口令的一次在线猜测）。
     * P2 的登录路径会补上 FACEID_MISMATCH 等 A 组码，届时分组规则不变。
     */

    /// <summary>录入 / 删除 FaceId 模板时二次口令不符。（A 组 · 计次）</summary>
    public const string FaceIdWrongPassword = "FACEID_WRONG_PASSWORD";

    /// <summary>
    /// 录入过程未通过（单脸 / 尺寸 / 清晰度 / 正脸度），模板没有写入。（B 组 · 不计）
    ///
    /// 与 FACE_ENROLL_REJECTED 分开的理由：两条链路的模板各自独立，
    /// 审计员要能分别回答"2FA 那边录失败几次"和"纯人脸这边录失败几次"。
    /// </summary>
    public const string FaceIdEnrollRejected = "FACEID_ENROLL_REJECTED";

    /// <summary>该账号没有可用的 FaceId 模板（未录入 / 模板属于旧模型）。（不计）</summary>
    public const string FaceIdNoTemplate = "FACEID_NO_TEMPLATE";

    /// <summary>FaceId 引擎不可用（模型缺失 / 摄像头打不开）。本机环境问题，不是攻击。（不计）</summary>
    public const string FaceIdEngineUnavailable = "FACEID_ENGINE_UNAVAILABLE";

    /// <summary>
    /// 模板与当前模型不匹配（换过权重）。这不是"不像"，而是"没法比" ——
    /// 必须与 QUALITY / MISMATCH 区分开，否则排查会一路往摄像头和光线方向跑。（不计）
    /// </summary>
    public const string FaceIdModelMismatch = "FACEID_MODEL_MISMATCH";

    /// <summary>
    /// 未通过活体判定（照片 / 屏幕回放）。（**A 组 · 计次**）
    ///
    /// 这是本模块第一个计次的录入侧原因码，理由：
    ///   一次活体失败可能只是光线，但**连续多次**只有一个解释 —— 有人拿着照片在试。
    ///   与二级口令错、2FA 的 LIVENESS_FAILED 归同一组，语义一致：
    ///   它们都是"正在被试探"的直接证据，而不是配合问题。
    /// </summary>
    public const string FaceIdLivenessFailed = "FACEID_LIVENESS_FAILED";

    /// <summary>纯人脸登录：相似度明确低于阈值，判为不是本人。（A 组 · 计次）</summary>
    public const string FaceIdMismatch = "FACEID_MISMATCH";

    /// <summary>
    /// 纯人脸登录：相似度落在灰区。（B 组 · **不计次**）
    /// 灰区是"证据不足"，不是"证明不是"；计次等于让光线问题积累成锁定。
    /// </summary>
    public const string FaceIdGrayZone = "FACEID_GRAY_ZONE";
}
