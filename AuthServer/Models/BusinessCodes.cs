namespace AuthServer.Models;

/// <summary>
/// 业务响应码 —— 出现在 <see cref="ApiResponse.Code"/> 里、**返回给前端**的那一套码。
///
/// 与 <see cref="AuditReason"/> / <see cref="AuditAction"/> 的关系
/// ==========================================================
/// **两套码、刻意不合并**，只是偶尔字面量相同：
///
/// | | 本类（业务码） | <c>AuditReason</c>（审计原因码） |
/// |---|---|---|
/// | 去哪 | 响应体，用户看得到 | 审计库，只进不出 |
/// | 用途 | 前端据此决定提示文案 | 支撑"反复弱口令/口令猜测"这类检索 |
/// | 粒度 | 按**用户可理解**划分 | 按**可检索的安全事实**划分 |
///
/// 所以不能合并成一套：
///   · 同一个业务码可能对应多个原因码（"新旧密码相同"从用户角度是一件事，
///     但审计要区分"旧口令验过之后才发现"与"没验就报"，后者会变成口令探针）；
///   · 同一个原因码也可能出现在多个业务码下（`InvalidCredentials` 在登录、
///     重置口令、管理员口令校验三处都可能是不同的对外话术）。
///
/// 两者的转换一律走**显式映射**（如 `VerifyCodeReason.From()`），
/// 不要为了省事直接把业务码透传给审计，那样会把"给用户看的话术"
/// 和"可检索的安全事实"混成一锅，两边都失去意义。
///
/// 改这里的值 = 改前端契约
/// =======================
/// 常量值就是前端 `format.js` 里比对的字符串。改名或改值必须同步前端，
/// 否则前端会落到"未知错误"的兜底分支（不会崩，但提示文案会退化成默认值）。
/// 这正是把字面量收口到常量类的价值：全局搜索一次就能找全。
public static class BusinessCode
{
    /// <summary>成功。所有正常返回都用它。</summary>
    public const string Ok = "OK";

    // ── 批量处置 ────────────────────────────────────────────────
    // 批量不是第七种业务能力，而是六种既有动作的多次调用；
    // 这四个码只描述"这一次批量调用整体怎么样"，单条结果沿用各动作自己的码。

    /// <summary>部分成功：至少一条执行、至少一条被拒。明细在 data.items 里。</summary>
    public const string BatchPartial = "BATCH_PARTIAL";

    /// <summary>一条都没做成。整体 success=false，明细仍在 data.items 里。</summary>
    public const string BatchAllFailed = "BATCH_ALL_FAILED";

    /// <summary>动作名不在允许清单内（防止前端笔误被静默当成某个动作执行）。</summary>
    public const string BatchUnknownAction = "BATCH_UNKNOWN_ACTION";

    /// <summary>目标数量超过单次上限。</summary>
    public const string BatchTooMany = "BATCH_TOO_MANY";

    // ── 通用校验 ────────────────────────────────────────────────
    public const string EmptyFields = "EMPTY_FIELDS";
    public const string NotFound = "NOT_FOUND";
    public const string InvalidEmail = "INVALID_EMAIL";

    // ── 账号 / 口令 ─────────────────────────────────────────────
    /// <summary>
    /// 账号不存在，或凭据不匹配 —— 对外**统一话术**，防枚举。
    /// 注意它同时是审计原因码的字面量，但那是另一套码，别互相引用。
    /// </summary>
    public const string InvalidCredentials = "INVALID_CREDENTIALS";
    public const string WeakPassword = "WEAK_PASSWORD";
    public const string PasswordReused = "PASSWORD_REUSED";
    public const string DuplicateUsername = "DUPLICATE_USERNAME";
    public const string AccountDisabled = "ACCOUNT_DISABLED";
    public const string AccountNotEnabled = "ACCOUNT_NOT_ENABLED";
    public const string AccountLocked = "ACCOUNT_LOCKED";
    public const string PendingApproval = "PENDING_APPROVAL";
    public const string NotPending = "NOT_PENDING";
    public const string NotLocked = "NOT_LOCKED";
    public const string AlreadyFrozen = "ALREADY_FROZEN";

    // ── 邮件验证码 ──────────────────────────────────────────────
    public const string EmailDisabled = "EMAIL_DISABLED";
    public const string EmailAlreadyBound = "EMAIL_ALREADY_BOUND";
    public const string InvalidPurpose = "INVALID_PURPOSE";

    // ── 角色 / 权限 ─────────────────────────────────────────────
    public const string InvalidRole = "INVALID_ROLE";
    public const string ForbiddenRole = "FORBIDDEN_ROLE";
    public const string ForbiddenTarget = "FORBIDDEN_TARGET";
    public const string RoleUnchanged = "ROLE_UNCHANGED";
    public const string CannotSetOwnRole = "CANNOT_SET_OWN_ROLE";
    /// <summary>管理角色不参与沉睡账号冻结（防权力真空）。</summary>
    public const string DormantProtectedRole = "DORMANT_PROTECTED_ROLE";

    // ── 时间源加固 ──────────────────────────────────────────────
    /// <summary>检测到墙钟被拨动。</summary>
    public const string ClockAnomaly = "CLOCK_ANOMALY";

    // ── 人脸（可选第二因子） ─────────────────────────────────────
    // 与 AuditReason.Face* 是**两套码**（见本类顶部说明），只是偶尔字面量相近：
    // 这里的码决定前端显示什么话术，那边的码决定审计怎么归类。
    // 例如"人脸没对上"在界面上要说人话（"人脸与录入时不匹配，请正对摄像头"），
    // 而审计里要的是可检索的事实（FACE_MISMATCH）。

    /// <summary>
    /// 口令已通过，但该账号启用了人脸，**尚未签发任何票据**。
    ///
    /// 这不是错误，而是登录流程的中间态 —— 前端收到它应该切到人脸步骤，
    /// 而不是弹一条"登录失败"。用 200 + Success=false + 本码表达，
    /// 刻意**不用 401**：401 在前端会被当作"账号或口令不对"，
    /// 那会让用户以为自己口令输了。
    /// </summary>
    public const string FaceRequired = "FACE_REQUIRED";

    /// <summary>人脸未达阈值。</summary>
    public const string FaceMismatch = "FACE_MISMATCH";

    /// <summary>活体动作挑战未通过。</summary>
    public const string FaceLivenessFailed = "FACE_LIVENESS_FAILED";

    /// <summary>挑战无效：过期 / 已使用 / 不属于本次尝试。</summary>
    public const string FaceChallengeInvalid = "FACE_CHALLENGE_INVALID";

    /// <summary>画面里没有人脸。</summary>
    public const string FaceNoFace = "FACE_NO_FACE";

    /// <summary>人脸质量不达标（太远 / 太暗 / 侧脸过大）。</summary>
    public const string FaceLowQuality = "FACE_LOW_QUALITY";

    /// <summary>动作做完了但没回正，缺少可比较的一帧。</summary>
    public const string FaceNotReturned = "FACE_NOT_RETURNED";

    /// <summary>录入过程未通过（活体或质量原因），模板没有被写入。</summary>
    public const string FaceEnrollFailed = "FACE_ENROLL_FAILED";

    /// <summary>本机没有人脸模板。</summary>
    public const string FaceNotEnrolled = "FACE_NOT_ENROLLED";

    /// <summary>人脸引擎不可用（模型缺失 / 摄像头打不开）。</summary>
    public const string FaceEngineUnavailable = "FACE_ENGINE_UNAVAILABLE";

    // ── 纯人脸登录（FaceId，独立模块） ───────────────────────────
    // 与上面的 FACE_* 是**两套模块的码**，刻意不复用：
    //   前端要把"2FA 的人脸"和"纯人脸登录"显示成两张不同的卡片，
    //   若共用码，界面就只能靠上下文猜这句提示属于哪张卡。
    //   同理，审计里 FACEID_* 与 FACE_* 必须能分开检索 —— 两条链路的失败
    //   对安全的意义不同（前者是唯一因子，后者是第二因子）。

    /// <summary>纯人脸登录模块整体关闭（等价于从未实现过）。</summary>
    public const string FaceIdDisabled = "FACEID_DISABLED";

    /// <summary>本机 FaceId 引擎不可用（模型缺失 / 摄像头打不开）。</summary>
    public const string FaceIdEngineUnavailable = "FACEID_ENGINE_UNAVAILABLE";

    /// <summary>画面里没有人脸。</summary>
    public const string FaceIdNoFace = "FACEID_NO_FACE";

    /// <summary>画面里有不止一张脸 —— 无法确认要录入的是谁。</summary>
    public const string FaceIdMultipleFaces = "FACEID_MULTIPLE_FACES";

    /// <summary>人脸太小（离摄像头太远）。</summary>
    public const string FaceIdTooSmall = "FACEID_FACE_TOO_SMALL";

    /// <summary>侧脸或歪头幅度过大。</summary>
    public const string FaceIdNotFrontal = "FACEID_NOT_FRONTAL";

    /// <summary>画面模糊（失焦 / 运动模糊）/ 特征提取失败。</summary>
    public const string FaceIdLowQuality = "FACEID_LOW_QUALITY";

    /// <summary>录入过程未通过（质量原因），模板没有写入。</summary>
    public const string FaceIdEnrollFailed = "FACEID_ENROLL_FAILED";

    /// <summary>该账号没有可用于纯人脸登录的模板（未录入，或模板属于旧模型）。</summary>
    public const string FaceIdNotEnrolled = "FACEID_NOT_ENROLLED";

    /// <summary>模板与当前模型不匹配（换过权重）—— 必须重新录入，不是"人脸不像"。</summary>
    public const string FaceIdModelMismatch = "FACEID_MODEL_MISMATCH";

    /// <summary>
    /// 未通过活体判定（画面像是打印照片 / 屏幕回放）。与"脸不像"严格区分：
    /// 前者是**攻击信号**，后者是本人没对上；混成一个码会让审计看不出有人在试照片。
    /// </summary>
    public const string FaceIdLivenessFailed = "FACEID_LIVENESS_FAILED";

    /// <summary>相似度**明确低于**阈值 ⇒ 不是本人。计次（与口令错的地位相同）。</summary>
    public const string FaceIdMismatch = "FACEID_MISMATCH";

    /// <summary>
    /// 相似度落在灰区：既不能判定是本人，也不足以判定不是。**不计次、不签票**，
    /// 引导改用口令登录 —— 计次会让"光线不好"逐步把本人锁在门外。
    /// </summary>
    public const string FaceIdGrayZone = "FACEID_GRAY_ZONE";

    // ── 一次性口令（哈希链） ─────────────────────────────────────
    // 与本类其它分组一样，"业务码"与"审计原因码"是**两套码**（见本类顶部）：
    // 这里决定界面说什么，AuditReason 那边决定审计怎么归类。

    /// <summary>本模块整体关闭。客户端收到它应当回退到口令登录，而不是提示"登录失败"。</summary>
    public const string OtpDisabled = "OTP_DISABLED";

    /// <summary>
    /// 挑战无效：过期 / 已被用过 / 不属于这个用户名。
    /// 与"凭据错"分开是**为了用户**：这条几乎总是"点了登录后放了一会儿"，
    /// 正确补救是重新点一次，而不是怀疑自己记错了口令。因此它**不计入失败次数**。
    /// </summary>
    public const string OtpChallengeInvalid = "OTP_CHALLENGE_INVALID";

    /// <summary>
    /// 配额用尽：链到了尽头。<c>k = 0</c> 时**凭据本身是对的**，错的是没有下一格了。
    ///
    /// 必须与 <see cref="InvalidCredentials"/> 分开，否则用户会以为口令失效，
    /// 反复重输、把自己锁进"口令错"的循环里 —— 而真正要做的是重建链（邮箱验证码重置）。
    /// 代价是它对外透露"该账号有一条用尽的链"，这是可接受的：用尽本身不是秘密，
    /// 且要走到这一步，请求里必须带一个**真实存在**的挑战凭据。
    /// </summary>
    public const string OtpChainExhausted = "OTP_CHAIN_EXHAUSTED";

    /// <summary>
    /// 并发冲突：同一格被两个请求同时提交，另一个抢先核销成功。
    /// 不是失败、**不计次**（否则"手机和电脑同时登录"会平白锁号），客户端重试即可。
    /// </summary>
    public const string OtpChainConflict = "OTP_CHAIN_CONFLICT";

    /// <summary>
    /// 再认证时该账号还没有链（迁移期的新建账号，尚未登录过一次）。
    ///
    /// 与登录路径**刻意不同**：登录那边对它统一回"用户名或密码错误"，因为那是匿名接口，
    /// 承认"这个账号没链"就是承认"这个账号存在"。而这里请求必须带**有效票据**，
    /// 调用者已经知道自己是谁 —— 再含糊其辞只会让人不知道该怎么办。
    /// </summary>
    public const string OtpNotEnrolled = "OTP_NOT_ENROLLED";

    /// <summary>
    /// 敏感操作缺少可用的确认凭据：没带、过期、已用过，或与本次操作的用途/目标不符。
    ///
    /// 与 <see cref="InvalidCredentials"/> 分开是**为了客户端**：这不是"你口令错了"，
    /// 而是"再确认一次就行"。混成一个码，前端只能提示用户重输口令 ——
    /// 而在替代式模型里，那个动作根本不存在了。
    /// </summary>
    public const string OtpConfirmRequired = "OTP_CONFIRM_REQUIRED";

    /// <summary>
    /// 再认证被节流（窗口内失败次数到顶）。**不是账号锁定**：登录不受任何影响。
    /// 单独一个码，是为了让客户端能把"等 5 分钟"和"你被锁号了"区分开。
    /// </summary>
    public const string OtpReconfirmThrottled = "OTP_RECONFIRM_THROTTLED";

    /// <summary>
    /// 重建链失败 ⇒ 本次改密/重置**整体失败**（口令已回滚，什么都没变）。
    ///
    /// 为什么不留成"口令改了、链等下次再说"：那正是 P3 记下的那个隐患形态 ——
    /// 口令登录正常、OTP 登录永远失败，而用户看不出任何异常。
    /// 宁可让他重试一次，也不要留下一个只有到 P8 才会爆的半截状态。
    /// </summary>
    public const string OtpRebuildFailed = "OTP_REBUILD_FAILED";

    // 刻意**没有** OTP_CHAIN_MALFORMED 这个业务码：
    // 链记录畸形是服务端的数据事故，对外统一按"用户名或密码错误"回答。
    // 给它一个对外码等于告诉匿名调用者"这个用户名有链、而且链坏了"——
    // 那是一条比"账号存在"更细的枚举信息。它对内仍可在审计里检索（AuditReason.OtpChainMalformed）。
}
