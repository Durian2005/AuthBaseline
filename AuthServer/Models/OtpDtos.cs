namespace AuthServer.Models;

/**
 * 一次性口令（哈希链）的请求/响应契约。
 *
 * 刻意不引用任何 Service 类型：契约只描述"线上长什么样"，
 * 判定与存储的实现细节（OtpVerifier / OtpChainStore）不该漏到这里来。
 * 算法名与 KDF 名是**字符串常量**，所以这里直接写字面量并保持与
 * `OtpVerifier.ChainAlgorithm` / `KdfName` 一致（单测会核对这一点，
 * 见 OtpOptionsTests.DecisionConstants_LiveOnlyInVerifier 的邻近断言）。
 */

/// <summary>登录第一步的请求：只要一个用户名。</summary>
public class OtpChallengeRequest
{
    public string Username { get; set; } = string.Empty;
}

/**
 * 登录第一步的响应：客户端算 <c>x_k</c> 所需的**全部**公开参数。
 *
 * 两处刻意的设计：
 *   ① **对不存在 / 没有链 / 被冻结的账号，也返回一份格式合法的随机参数**（形状逐字一致）。
 *      否则这个匿名端点就是账号枚举接口 —— 有没有链、账号存不存在，一眼可辨。
 *      随机参数算不出能通过的格，所以"看起来一样"不会带来任何登录能力。
 *   ② 不含任何服务端状态（没有"还剩几次""上次登录时间"）：
 *      那些属于登录之后的接口，放在这里等于给匿名调用者一个观察窗口。
 */
public class OtpChallengeResponse
{
    /// <summary>一次性挑战凭据，登录时必须原样带回。</summary>
    public string ChallengeToken { get; set; } = string.Empty;

    /// <summary>公开链种子（Base32）。不是秘密，作用是让两条链即便口令相同也互不相干。</summary>
    public string R { get; set; } = string.Empty;

    /// <summary>期望下标：本次应当提交 <c>x_k</c>。</summary>
    public int K { get; set; }

    /// <summary>链长 N（客户端用它确认 <c>k</c> 的合法范围）。</summary>
    public int N { get; set; }

    /// <summary>链算法名（当前恒为 <c>SHA256</c>）。写进响应是为了将来能整体升级而不靠猜。</summary>
    public string Algorithm { get; set; } = "SHA256";

    /// <summary>口令派生函数名（当前恒为 <c>PBKDF2-HMACSHA256</c>）。</summary>
    public string Kdf { get; set; } = "PBKDF2-HMACSHA256";

    /// <summary>PBKDF2 迭代次数。**必须用服务端给的这个值**，不能用客户端本地配置。</summary>
    public int Iterations { get; set; }

    /// <summary>挑战有效期（秒）。过期后必须重新申请，不能拿旧参数硬试。</summary>
    public int ExpiresInSeconds { get; set; }
}

/**
 * 静默续期时随登录一起提交的**新链**。
 *
 * 为什么续期由客户端算而不是服务端算：服务端**没有口令**（这正是本方案的全部意义）。
 * 所以它只能收下客户端算好的 `{r, head}`，并相信"算这个的进程手里有正确口令"——
 * 而这个信任是有边界的：换上去的新链即使算错了，也只影响该账号自己（本人令牌都拿不到），
 * 不存在"借此冒充他人"的路径。
 *
 * ⚠️ 服务端只校验**形状**（R 是 32 位 Base32、head 是 32 字节 Base64）。
 *    形状合法但内容错的新链会把账号推进"链不可用"的状态 ——
 *    这时口令路径仍然可用（P3 保留了 `passwordHash`），用户重新登录一次即可再续一条。
 *    这也是 P8 之前**绝不**清 `passwordHash` 的另一个理由。
 */
public class OtpNextChain
{
    /// <summary>新链种子（客户端用 CSPRNG 生成，32 位 Base32）。换种子等于换盐。</summary>
    public string R { get; set; } = string.Empty;

    /// <summary>新链链头 <c>x_N</c>（Base64，32 字节）。由同一口令 + 新种子派生。</summary>
    public string Head { get; set; } = string.Empty;
}

/**
 * 敏感操作前的链值再认证：提交一格链值，换一张一次性确认凭据。
 *
 * 为什么要「换票」而不是让六个敏感接口各验一次链值：
 *   ① 链值会被两处消费（登录 / 再认证）。六处各写一份 CAS，就有六份"抢输了怎么办"；
 *   ② "这张确认只对某个用途、某个目标有效"需要一个落点，凭据本身就是那个落点；
 *   ③ 审计能直接回答"那次确认是为了什么"，而不必从请求报文里反推。
 *
 * ⚠️ 本请求**不含用户名**：身份只由票据回答。若允许从报文里读用户名，
 *    "用我的确认去操作别人的账号"就只是一个改字段的动作。
 */
public class OtpReconfirmRequest
{
    /// <summary>用途，取值见 OtpConfirmPurpose（create-account / set-role / 四个 face*）。</summary>
    public string Purpose { get; set; } = string.Empty;

    /// <summary>
    /// 作用对象（被操作的用户名）。`create-account` / `set-role` **必填** ——
    /// 它们操作的永远是别人；留空会让凭据绑到操作者自己身上，
    /// 然后在下一次请求里以"目标不符"失败（用户看到的现象是"确认了却用不了"）。
    ///
    /// 四个 face* 用途可省略（默认本人）。省略与显式传本人都等价，因为最后都要过 Norm。
    /// </summary>
    public string? Target { get; set; }

    /// <summary>链值 <c>x_k</c>（Base64，32 字节）。**这是凭据，永远不进日志**。</summary>
    public string OtpCode { get; set; } = string.Empty;
}

/// <summary>再认证成功后签发的确认凭据。客户端只做一件事：把它原样带进下一个请求。</summary>
public class OtpReconfirmResponse
{
    /// <summary>一次性确认凭据（Base64Url，43 个字符）。</summary>
    public string ConfirmToken { get; set; } = string.Empty;

    /// <summary>有效期（秒）。过期或已被使用都会得到同一个
    /// <see cref="BusinessCode.OtpConfirmRequired"/>。</summary>
    public int ExpiresInSeconds { get; set; }

    /// <summary>回显用途与目标，便于客户端核对"我确认的到底是不是这件事"。</summary>
    public string Purpose { get; set; } = string.Empty;

    public string Target { get; set; } = string.Empty;
}

/**
 * 链的展示状态：还剩多少格、第几代、离续期线还有多远。
 *
 * 为什么它**不下发** `R` / `k` 这些算链需要的参数：
 *   那些走 `login/challenge`（匿名端点，对任何用户名都返回同形状的一组参数）。
 *   让状态接口也带一份，等于多开一条"取参"路径 —— 而取参路径是防枚举设计里最敏感的一环，
 *   多一条就多一处要验证"它是否与挑战端点逐字同形"。
 *   这里只回答"够不够用、要不要管"，不回答"怎么算"。
 *
 * 字段全部是服务端已经知道、用户也有权知道的：剩余格数、代数、参数档位。
 * 不含种子与链头 —— 那两个是凭据（`v` 泄露即可离线爆破，见设计稿 §2.4）。
 */
public class OtpStatusResponse
{
    /// <summary>模块是否启用（关闭时整个状态块在界面上应当只是一行说明）。</summary>
    public bool Enabled { get; set; }

    /// <summary>这个账号有没有链。false ⇒ 尚未迁移，或链已被清除。</summary>
    public bool Enrolled { get; set; }

    /// <summary>剩余可用格数 <c>k</c>。</summary>
    public int Remaining { get; set; }

    /// <summary>链长 <c>N</c>。</summary>
    public int Length { get; set; }

    /// <summary>剩余百分比（向下取整）。界面上画进度条用，**不做任何判定**。</summary>
    public int Percent { get; set; }

    /// <summary>链的代数（1 = 首次建立；续期与重建都会 +1）。</summary>
    public int Generation { get; set; }

    /// <summary>是否已到续期线（<c>k ≤ N×5%</c>）。</summary>
    public bool NeedsRenewal { get; set; }

    /// <summary>是否已跌破警戒线（<c>k ≤ N×1%</c>）。</summary>
    public bool AtAlertLine { get; set; }

    /// <summary>本条链使用的 PBKDF2 迭代次数（与链绑定：调高全局默认不影响存量链）。</summary>
    public int KdfIterations { get; set; }

    public string Algorithm { get; set; } = string.Empty;

    public string Kdf { get; set; } = string.Empty;

    /// <summary>本条链的建立/重建时刻。</summary>
    public DateTime? EnrolledAt { get; set; }
}

/**
 * P8：`OtpRecoverRequest` 与 `POST /api/auth/otp/recover` 一并删除（见 OtpController 末尾的说明）。
 *
 * 结论一句话：**"凭当前口令重建链"在 P8 之后无法实现** ——
 * 服务端不存口令派生物，就没有任何东西能证明"你知道当前口令"，
 * 除非当场核销一格链值；而这条路径唯一的适用场景恰恰是链已经坏了或用不了。
 * 该需求改由 `reset-password`（邮箱验证码 + 新口令 + 整条重建）承担。
 */
