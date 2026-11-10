using System.Security.Cryptography;
using AuthServer.Models;
using AuthServer.Services;
using AuthServer.Services.Otp;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;

namespace AuthServer.Controllers;

/**
 * 一次性口令（哈希链）的**两个非登录入口**：签发登录挑战、敏感操作的链值再认证。
 *
 * 两者放在同一个控制器里，是因为它们共用同一套依赖（<see cref="OtpChainStore"/> 与
 * <see cref="OtpOptions"/>）与同一份"链怎么被核销"的语义。差异只在鉴权：
 * 挑战必须匿名（登录之前没有票据），再认证必须带票据（它替换的是"再输一次口令"）。
 *
 * 这个端点为什么必须是匿名的：它在登录之前被调用，调用者手里不可能有票据。
 * 也正因为匿名，它天然是"账号枚举"的第一嫌疑对象 —— 所以它的回答必须
 * 对**存在 / 不存在 / 有链 / 没链 / 被冻结 / 待审核**这些情况**逐字一致**。
 *
 * ── "一致"靠什么保证 ──────────────────────────────────────────
 * 不是靠"小心地写 if"，而是靠**结构**：本方法只有一条出口、一个响应类型，
 * 且分成"真参数"与"假参数"两组后立刻合流；两组来自同一组常量（N / 算法 / KDF / TTL），
 * 只有 R 与 k 的取值不同，而它们**都长得像随机**。
 * 于是"有没有链"这个事实并不体现在响应的形状里，只体现在"这组参数能不能算出链条"，
 * 而后者需要知道口令。
 *
 * ── 为什么挑战不写审计 ────────────────────────────────────────
 * 它不透露任何账号事实（我们自己也只在内存里区分真假），而它又是完全匿名、
 * 可被无限调用的。若每条都落审计，"扫一遍用户名"就能把审计表刷成一屏噪声 ——
 * 那正是审计最不该被浪费的地方。真正值得记的是"有人拿这些参数去登录"，
 * 那发生在 login，且那里已经有完整的 LOGIN_FAILED / OTP_* 记录。
 */
[ApiController]
[Route("api/auth")]
public class OtpController : AuthControllerBase
{
    private readonly OtpOptions _otp;
    private readonly OtpChainStore _chains;
    private readonly OtpChallengeStore _challenges;
    private readonly OtpReconfirmThrottle _throttle;

    // ⚠️ `_confirms` **不在这里声明**：它由 AuthControllerBase 提供（确认闸门也在那儿）。
    //    本类若再声明一份，编译器只会给一条 CS0108 警告，而两者的类型相同、注入的又是同一个单例，
    //    于是行为上看不出任何差异 —— 直到有人给基类换了一个实例，才发现两处读的不是同一个东西。
    //    这种"能跑但有两个真相"的字段必须只有一个。

    public OtpController(MongoDbService db, AuditWriter auditWriter, SessionService sessions,
        IConfiguration configuration,
        OtpOptions otp, OtpChainStore chains, OtpChallengeStore challenges,
        OtpConfirmStore confirms, OtpReconfirmThrottle throttle)
        : base(db, auditWriter, sessions, configuration, confirms)
    {
        _otp = otp;
        _chains = chains;
        _challenges = challenges;
        _throttle = throttle;
    }

    /**
     * 签发登录挑战：返回算 <c>x_k</c> 所需的公开参数 + 一次性凭据。
     *
     * 客户端拿到后：<c>x₀ = PBKDF2(口令, R, iterations)</c> → 迭代 k 次 → 把 <c>x_k</c>
     * 与 challengeToken 一起交给 <c>POST /api/auth/login</c>。
     */
    [HttpPost("login/challenge")]
    public async Task<IActionResult> Challenge([FromBody] OtpChallengeRequest req)
    {
        var username = Norm(req.Username);
        if (string.IsNullOrWhiteSpace(username))
            return BadRequest(new ApiResponse
            {
                Success = false,
                Code = BusinessCode.EmptyFields,
                Message = "用户名不能为空"
            });

        // 有链 ⇒ 真参数；没链 ⇒ 假参数（形状逐字一致）。这就是防枚举的全部实现。
        var chain = await _chains.FindByUsernameAsync(username);

        // 先把三个被签名的参数定下来：proof 覆盖的就是它们，签发之后再算就白算了。
        // 真链用库里的 R；没有链就现造一段等长 Base32。
        // ⚠️ 假 R 必须是 CSPRNG，不能是常量：常量会让"没链的账号"在多次请求间保持同一个 R，
        //    而真链的 R 只有续期才变 —— 反复采样就能把两类账号分开。
        var r = chain?.R ?? OtpChainStore.NewSeed();

        // k 在 [0, N-1] 之间取：真链的 k 也在这个区间里（含用尽时的 0），
        // 所以取值域完全重合，单次采样分不出真假。
        var k = chain?.K ?? RandomNumberGenerator.GetInt32(0, Math.Max(2, _otp.Length));

        var n = chain?.Length ?? _otp.Length;

        var (token, proof, ttl) = _challenges.Issue(username, r, k, n);

        var response = new OtpChallengeResponse
        {
            ChallengeToken = token,

            // 客户端必须先验它，再决定算不算这一格。验不过就说明挑战在链路上被改过
            // （典型就是把 k 改小 ⇒ 小数攻击），此时**绝不能**计算，否则等于把
            // 更靠前的一格主动交给攻击者，让它正向补齐后冒充登录。
            Proof = proof,

            R = r,
            K = k,
            N = n,

            // 算法名与 KDF 名是**全局常量**，不是每条链的属性（每条链可变的只有迭代次数）。
            Algorithm = OtpVerifier.ChainAlgorithm,
            Kdf = OtpVerifier.KdfName,

            // 迭代次数必须来自链本身：将来把全局默认调高，存量链仍按它自己的次数派生，
            // 否则同一个口令会算出不同的链根，表现是"所有人都登不上"。
            Iterations = chain?.KdfIterations ?? _otp.KdfIterations,

            ExpiresInSeconds = ttl
        };

        return Ok(new ApiResponse<OtpChallengeResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = "已签发登录挑战",
            Data = response
        });
    }

    /* ==================== 敏感操作：链值再认证 ==================== */

    /**
     * 用一格链值换一张**一次性确认凭据**，供六处敏感操作消费。
     *
     * ── 为什么这个端点必须带票据 ──────────────────────────────────
     * 它替换的是"再输一次口令"。而"再输一次口令"之所以有意义，前提是**已经登录**：
     * 票据回答"你是哪个会话"，链值回答"此刻操作的是不是本人"。缺了前者，
     * 这就成了一个"给我任意用户名、我替你确认"的端点 —— 比不做还糟。
     *
     * ── 顺序：为什么先查节流、再核销 ──────────────────────────────
     * 被节流时**一个字节都不该读链**：否则封禁期间每次请求都仍能拿到
     * "这一格对不对"的答案（核销失败仍然是失败，而失败本身携带信息）。
     * 更实际的理由是成本：核销一次要读库 + 一次条件写，节流本就该在最前面。
     *
     * ── 失败一律不计入登录失败计数 ────────────────────────────────
     * 见 <see cref="OtpReconfirmThrottle"/> 的类注释。这里只说结论：
     * 用登录计数器会让"拿着一张票据连点三次"变成一次锁号攻击。
     */
    [HttpPost("reconfirm")]
    public async Task<IActionResult> Reconfirm([FromBody] OtpReconfirmRequest req)
    {
        const string action = AuditAction.OtpReconfirm;
        const string failAction = AuditAction.OtpReconfirmFailed;

        var purpose = (req.Purpose ?? string.Empty).Trim();
        if (!OtpConfirmPurpose.IsKnown(purpose))
            return BadRequest(new ApiResponse
            {
                Success = false,
                Code = BusinessCode.InvalidPurpose,
                Message = "未知的确认用途"
            });

        var (user, deny) = await RequireAuthenticatedAsync(action, purpose);
        if (deny != null) return deny;

        // 链值是凭据，**绝不进日志**：请求袋里只留用途与目标。
        var requestLog = new { Purpose = purpose, Target = req.Target };
        var statusBefore = user!.Status.ToString();

        // ── 目标归一 ──
        // `create-account` / `set-role` 操作的是**别人**，必须显式给出目标：
        // 允许省略会让凭据绑到操作者自己身上，然后在下一次请求里以"目标不符"失败 ——
        // 那是一种"确认了却用不了"的哑谜，不如当场说清楚。
        // 四个 face* 是自助操作，目标恒为本人；客户端即使传了别的名字也**忽略**，
        // 因为"给谁录人脸"不是可以商量的东西（见各控制器的 self-* 守卫）。
        //
        // 放在最前面（早于"缺链值"这类校验）是为了让后面每一条审计都能写同一个 target：
        // 审计的 target 列是"这件事作用在谁身上"，若同一动作码时而写用户名、时而写用途，
        // 按 target 检索就会漏。
        string target;
        if (OtpConfirmPurpose.RequiresTarget(purpose))
        {
            target = Norm(req.Target);
            if (string.IsNullOrWhiteSpace(target))
            {
                var resp = new ApiResponse
                {
                    Success = false,
                    Code = BusinessCode.EmptyFields,
                    Message = "该操作的确认必须指定目标账号"
                };
                await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                    statusBefore, purpose, AuditResult.Failed, AuditReason.EmptyFields);
                return BadRequest(resp);
            }
        }
        else
        {
            target = user.Username;
        }

        if (string.IsNullOrWhiteSpace(req.OtpCode))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "缺少确认凭据" };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                statusBefore, target, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        // ── 节流 ──
        var (blocked, retryAfter) = _throttle.Check(user.Id);
        if (blocked)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.OtpReconfirmThrottled,
                Message = $"确认失败次数过多，请 {Math.Ceiling(retryAfter / 60.0)} 分钟后再试（登录不受影响）"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore,
                new { Purpose = purpose, Target = target, RetryAfterSeconds = retryAfter }, resp,
                statusBefore, target, AuditResult.Failed, AuditReason.OtpReconfirmThrottled);
            Response.Headers["Retry-After"] = retryAfter.ToString();
            return StatusCode(StatusCodes.Status429TooManyRequests, resp);
        }

        // ── 核销一格 ──
        var consumed = await _chains.ConsumeAsync(user.Id, req.OtpCode);

        switch (consumed.Outcome)
        {
            case OtpConsumeOutcome.NotEnrolled:
                // 迁移期的"刚建出来、还没登录过"的账号。对已认证的调用者没必要隐瞒。
                {
                    var resp = new ApiResponse
                    {
                        Success = false,
                        Code = BusinessCode.OtpNotEnrolled,
                        Message = "本账号尚未建立一次性口令链，请先重新登录一次再试"
                    };
                    await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                        statusBefore, target, AuditResult.Failed, AuditReason.OtpNotEnrolled);
                    return Conflict(resp);
                }

            case OtpConsumeOutcome.Malformed:
                // 服务端数据事故：不计次、不外露细节，但必须留下可检索的线索。
                {
                    Console.WriteLine($"[Otp] ⚠️ 链记录畸形，账号「{user.Username}」无法完成再认证（需重建链）");
                    var resp = new ApiResponse
                    {
                        Success = false,
                        Code = BusinessCode.InvalidCredentials,
                        Message = "确认失败，请重新登录"
                    };
                    await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                        statusBefore, target, AuditResult.Failed, AuditReason.OtpChainMalformed);
                    return Unauthorized(resp);
                }

            case OtpConsumeOutcome.Mismatch:
                {
                    // 这是唯一的"猜测信号" ⇒ 记一次节流。**不碰 FailedLoginAttempts**。
                    _throttle.OnFailure(user.Id);
                    var resp = new ApiResponse
                    {
                        Success = false,
                        Code = BusinessCode.OtpConfirmRequired,
                        Message = "确认凭据不正确，请重新确认身份"
                    };
                    await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                        statusBefore, target, AuditResult.Failed, AuditReason.OtpChainMismatch);
                    return Unauthorized(resp);
                }

            case OtpConsumeOutcome.Conflict:
                {
                    // 同一格被两个请求同时提交（比如连点两次）。不计次：这是并发，不是猜测。
                    var resp = new ApiResponse
                    {
                        Success = false,
                        Code = BusinessCode.OtpChainConflict,
                        Message = "确认请求发生并发冲突，请重试"
                    };
                    await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                        statusBefore, target, AuditResult.Failed, AuditReason.OtpChainConflict);
                    return Conflict(resp);
                }

            case OtpConsumeOutcome.Exhausted:
                {
                    // 凭据是真的，链没了。回"需重建"而不是"凭据错"。
                    var resp = new ApiResponse
                    {
                        Success = false,
                        Code = BusinessCode.OtpChainExhausted,
                        Message = "本账号的一次性口令已用尽，请重新登录以建立新的链"
                    };
                    await _auditWriter.WriteAsync(user.Id, user.Username, failAction, statusBefore, requestLog, resp,
                        statusBefore, target, AuditResult.Failed, AuditReason.OtpChainExhausted);
                    return Unauthorized(resp);
                }
        }

        // ── 成功 ──
        // 核销这一格必须可追溯（§8.3 第 3 条）：审计里要能回答"这一格被谁、为什么吃掉"。
        // 它与登录的 OTP_CONSUME 共用动作码，靠 Purpose 区分 —— 这样"某格去哪了"
        // 只需要查一个动作码，而不必在两处拼结果。
        var next = consumed.NewState!.Value;
        await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.OtpConsume, statusBefore,
            requestLog,
            new
            {
                user.Username,
                KBefore = next.K + 1,
                KAfter = next.K,
                ChainLength = next.Length,
                NeedsRenewal = consumed.NeedsRenewal,
                AtAlertLine = consumed.AtAlertLine,
                Purpose = "RECONFIRM",
                ConfirmPurpose = purpose
            },
            statusBefore, user.Username, AuditResult.Success, AuditReason.OtpChainVerified);

        _throttle.OnSuccess(user.Id);

        var (token, ttl) = _confirms.Issue(user.Id, purpose, target);

        var response = new ApiResponse<OtpReconfirmResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = $"已确认身份，凭据 {ttl} 秒内有效且只能用一次",
            Data = new OtpReconfirmResponse
            {
                ConfirmToken = token,
                ExpiresInSeconds = ttl,
                Purpose = purpose,
                Target = target
            }
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, action, statusBefore,
            requestLog, new { Purpose = purpose, Target = target, ExpiresInSeconds = ttl },
            statusBefore, target, AuditResult.Success, AuditReason.OtpReconfirmOk);
        return Ok(response);
    }


    /* ==================== 链状态 ==================== */

    /**
     * 本人链的展示状态：还剩多少格、第几代、是否该续期。
     *
     * 它**不参与任何判定**，只是把服务端已经知道的事实摊开：
     * 否则用户在"某天突然登不上"之前，没有任何地方能看到自己的链正在变短。
     *
     * 只读接口成功时**不写审计**（与 `GET /api/auth/face` 同一口径）：
     * 刷一次页面就留一条审计，会把审计表冲成噪声。失败仍由基类的守卫留痕。
     */
    [HttpGet("otp/status")]
    public async Task<IActionResult> Status()
    {
        var (user, deny) = await RequireAuthenticatedAsync(AuditAction.AuditAccessDenied, "self-otp");
        if (deny != null) return deny;

        var chain = await _chains.FindAsync(user!.Id);

        var data = new OtpStatusResponse
        {
            Enabled = true,
            Enrolled = chain is not null,
            Remaining = chain?.K ?? 0,
            Length = chain?.Length ?? _otp.Length,
            // 没链时百分比给 0 而不是 100：0 表示"没有可用配额"，语义与"刚建满"不同。
            Percent = chain is null || chain.Length <= 0
                ? 0
                : (int)Math.Floor(chain.K * 100.0 / chain.Length),
            Generation = chain?.Generation ?? 0,
            NeedsRenewal = chain is not null && OtpVerifier.NeedsRenewal(chain.K, chain.Length),
            AtAlertLine = chain is not null && OtpVerifier.AtAlertLine(chain.K, chain.Length),
            KdfIterations = chain?.KdfIterations ?? _otp.KdfIterations,
            Algorithm = OtpVerifier.ChainAlgorithm,
            Kdf = OtpVerifier.KdfName,
            EnrolledAt = chain?.CreatedAt
        };

        return Ok(new ApiResponse<OtpStatusResponse>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = chain is null ? "本账号尚未建立一次性口令链" : "已返回链状态",
            Data = data
        });
    }

    /* ==================== 人工恢复：已并入「忘记口令」 ==================== */

    /**
     * 这里原本是 `POST /api/auth/otp/recover`：凭「邮箱验证码 + 当前口令」把链重建成满配额。
     *
     * P8 删掉它，不是简化，是**前提没了**：
     *   · 它要证明"你知道当前口令"。P8 之前这件事靠 `PasswordHasher.Verify` —— 库里有哈希，
     *     比一次就行；P8 之后服务端不存任何口令派生物，唯一的验证方式就是
     *     "拿口令算出一格、核销它"，而那正是登录本身。
     *   · 于是它只剩「邮箱验证码 + 当前链值」这一种写法。但它的**唯一适用场景**
     *     恰恰是链已经坏掉或用尽 —— 那时根本算不出可核销的一格（`Exhausted` 在比对之前就返回）。
     *     一个只在"不需要它的时候能用"的接口，比没有更糟：它会让人以为有一层兜底。
     *
     * 现在这条需求由 `POST /api/auth/reset-password` 承担：邮箱验证码 + **新口令** ⇒ 整条重建。
     * 代价是用户必须换一个口令；换来的是"不需要服务端记住任何口令痕迹"这条性质。
     * 未绑邮箱的账号（例如种子 admin）只能由运维用 `--rechain` 处理，见 `OtpRechainCli`。
     */

}
