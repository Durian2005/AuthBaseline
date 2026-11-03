using AuthServer.Models;
using AuthServer.Services;
using AuthServer.Services.Face;
using AuthServer.Services.Otp;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AuthServer.Controllers;

/**
 * 认证与会话接口：传输层状态、登录（含可选的人脸第二因子）、登出。
 *
 * 这三件事共同构成"一次会话从建立到结束"的完整闭环，
 * 与账号自助（AccountController）、用户管理（UserAdminController）分开。
 * 路由前缀仍是 api/auth —— 与拆分前逐一对应，前端契约不变。
 */
[ApiController]
[Route("api/auth")]
public class AuthController : AuthControllerBase
{
    private readonly TransportInfo _transport;
    private readonly FaceLoginService _face;
    private readonly FacePreviewService _preview;

    /// <summary>哈希链存储：仅"登录的第一因子"这一处用得上（核销一格）。</summary>
    private readonly OtpChainStore _chains;

    /// <summary>一次性挑战：消费即作废，绑定用户名与 TTL。</summary>
    private readonly OtpChallengeStore _challenges;

    public AuthController(MongoDbService db, AuditWriter auditWriter, SessionService sessions,
        TransportInfo transport, IConfiguration configuration, FaceLoginService face,
        FacePreviewService preview, OtpChainStore chains, OtpChallengeStore challenges,
        OtpConfirmStore confirms)
        : base(db, auditWriter, sessions, configuration, confirms)
    {
        _transport = transport;
        _face = face;
        _preview = preview;
        _chains = chains;
        _challenges = challenges;
    }

    /// <summary>
    /// 传输层状态：供界面状态栏显示「加密 / 明文」。
    ///
    /// **刻意不做鉴权**：状态栏在登录页就要显示，而"这条链路到底有没有加密"
    /// 恰恰是用户最该在**输入口令之前**就知道的事。
    /// 该接口不含任何敏感信息 —— 证书主题与指纹属于公钥信息，本就是公开的。
    /// </summary>
    [HttpGet("transport")]
    public IActionResult Transport()
    {
        // 以**实际请求**的 scheme 为准，而不是配置项：
        // 配置说的是"打算怎么跑"，Request.IsHttps 说的是"这一跳到底有没有加密"，
        // 而验收要证明的是后者。两者不一致本身就是最该被暴露的信号。
        var https = Request.IsHttps;

        return Ok(new ApiResponse
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = https ? "链路已加密（TLS）" : "链路为明文 HTTP",
            Data = new
            {
                scheme = https ? "https" : "http",
                tls = https,
                requireHttps = _transport.RequireHttps,
                subject = _transport.Subject,
                notAfter = _transport.NotAfter?.ToUniversalTime().ToString("o"),
                thumbprint = _transport.Thumbprint,
                trustStore = _transport.TrustStore,
                // 配置要求加密、实际却是明文 ⇒ 界面必须显眼地报出来，而不是静静显示"明文"
                downgraded = _transport.RequireHttps && !https
            }
        });
    }

    /* ==================== P8：口令凭据路径已移除 ==================== */

    /**
     * 这里原先有三个东西：`TryUpgradePasswordHashAsync`（旧格式哈希升级）、
     * `TryMigrateToChainAsync`（存量账号懒迁移）、以及登录里的口令比对分支。
     *
     * P8 一并删除，因为**前提消失了**：本版本不再保存任何口令派生物
     * （`PasswordHash` 只在迁移期作为历史数据存在，登录路径读都不读）。
     * 于是「升级哈希」没有对象，「迁移」改为运维工具 `--rechain` 完成，
     * 「口令比对」没有可比的东西 —— 唯一的凭据就是链上那一格。
     *
     * 存量账号怎么迁过来见 `OtpRechainCli`：那里仍然会用旧哈希**校验一次**明文口令，
     * 但它的产物是一条链，而不是一个新哈希。
     */

    /* ==================== 登出 ==================== */

    /**
     * 主动登出：吊销当前票据。
     *
     * 有了服务端会话，登出才真正"登出"——
     * 改造前前端清掉本地状态即可，令牌本身仍有效；现在服务端一吊销，票据立刻作废。
     */
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var ticket = ReadTicket();
        var auth = await _sessions.ValidateAsync(ticket, AccessLevel.Authenticated);

        if (!auth.Success)
        {
            // 登出失败不值得打断用户，但仍留痕
            var quiet = new ApiResponse { Success = false, Code = auth.ReasonCode, Message = auth.Message };
            await _auditWriter.WriteAsync("anonymous", "anonymous", AuditAction.Logout, "N/A",
                new { Reason = auth.ReasonCode }, quiet, "N/A", "", AuditResult.Failed, auth.ReasonCode);
            return StatusCode(auth.HttpStatus, quiet);
        }

        await _sessions.RevokeAsync(ticket!, "用户主动登出");
        var resp = new ApiResponse { Success = true, Code = BusinessCode.Ok, Message = "已安全退出" };
        await _auditWriter.WriteAsync(auth.User!.Id, auth.User.Username, AuditAction.Logout,
            auth.User.Status.ToString(), new { }, resp, auth.User.Status.ToString(),
            auth.User.Username, AuditResult.Success);
        return Ok(resp);
    }

    /* ==================== 登录 ==================== */

    /**
     * 登录：**唯一**的第一因子是哈希链上的一格。
     *
     * ── P8 删掉了什么 ────────────────────────────────────────────
     * 改造前这里是分流的：带 `otpCode` 走链值，不带就走口令比对。现在没有第二条路 ——
     * 服务端不存口令派生物，也就没有东西可以拿来比。请求体里的 `password` 字段随之删除，
     * 于是「客户端把口令传上网」这件事在本版本里第一次真正不存在（口令只在本机参与派生）。
     *
     * ── 为什么把空值校验留在入口 ──────────────────────────────────
     * 链值/挑战缺失属于**请求不完整**，不是一次凭据尝试：在这里回 400，
     * 就不会往下走到计次逻辑里 —— 否则一个写错的客户端会把自己主子的账号锁掉。
     */
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        var sanitizedUsername = Norm(req.Username);
        // 口令与链值都绝不进入日志，请求里只保留用户名
        var requestLog = new { req.Username };

        if (string.IsNullOrWhiteSpace(sanitizedUsername)
            || string.IsNullOrWhiteSpace(req.OtpCode)
            || string.IsNullOrWhiteSpace(req.ChallengeToken))
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.EmptyFields, Message = "用户名或口令不能为空" };
            await _auditWriter.WriteAsync("anonymous", sanitizedUsername, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
                sanitizedUsername, AuditResult.Failed, AuditReason.EmptyFields);
            return BadRequest(resp);
        }

        return await LoginWithChainAsync(req, sanitizedUsername, requestLog);
    }

    /* ==================== 登录：一次性口令（哈希链）分支 ==================== */

    /**
     * 第一因子 = 哈希链上的一格：`H(提交值) == v`。
     *
     * 顺序里的每一步都对应一种已知攻击，一步都不能省：
     *   ① 先消费挑战：一次性、有 TTL、绑定用户名。放在最前面，
     *      是为了"无论后面成败，这张票都不能再用"（否则重试就有了稳定通道）；
     *   ② 再找账号：不存在 ⇒ 与"口令错"同一话术（否则这就是个账号枚举接口）；
     *   ③ 锁定 / 待审核 / 冻结**在验链值之前**判：顺序反了，冻结账号就成了链值探针；
     *   ④ 核销：判定与条件写在同一处（`userId + v + k` 三条件 CAS）；
     *   ⑤ 通过后才进第二因子与 CompleteLoginAsync（清零计数 / 更新 lastLoginAt / 签票）。
     *
     * 链值的特殊性在于**它会消耗配额**，所以每次失败都必须计入失败次数 ——
     * 除非它根本不是一次凭据尝试（挑战无效、并发冲突、链畸形、链用尽）。
     */
    private async Task<IActionResult> LoginWithChainAsync(LoginRequest req, string username, object requestLog)
    {
        // 空值已在入口挡住（见 Login）：这里不再重复判一次 ——
        // 两处各写一份，迟早出现"提示话术不一样"这种没法解释的差异。

        // ① 挑战：先取出（pop）再判，过期 / 已用 / 不存在一律同一个码。
        var (challengeUsername, challengeError) = _challenges.Consume(req.ChallengeToken);
        if (challengeError is not null || !string.Equals(challengeUsername, username, StringComparison.Ordinal))
        {
            // 不计次：这不是一次凭据尝试，而是"客户端手里的参数过期了"。
            // 计入失败次数会让"打开登录页放了五分钟"变成一次失败 —— 三次就锁号。
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.OtpChallengeInvalid,
                Message = "登录请求已失效，请重新登录"
            };
            await _auditWriter.WriteAsync("anonymous", username, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.OtpChallengeInvalid);
            return Unauthorized(resp);
        }

        // ②③ 账号与状态闸门（与口令路径同一出口）
        var candidate = await ResolveLoginCandidateAsync(username, requestLog);
        if (candidate.Denial is not null) return candidate.Denial;

        var user = candidate.User!;
        var statusBefore = candidate.StatusBefore;

        // ④ 核销：判定 + 条件写。这里的返回值已经是"存储层的事实"，不需要再判一次。
        var consumed = await _chains.ConsumeAsync(user.Id, req.OtpCode);

        switch (consumed.Outcome)
        {
            case OtpConsumeOutcome.NotEnrolled:
                // 迁移期的存量账号：还没有链。对外与"口令错"**逐字一致**，
                // 否则"这个账号有没有链"就成了可探测的信息。对内单独归类，便于统计迁移进度。
                await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore,
                    requestLog,
                    new { Code = BusinessCode.InvalidCredentials, Step = "OTP" },
                    statusBefore, username, AuditResult.Failed, AuditReason.OtpNotEnrolled);
                return Unauthorized(new ApiResponse
                {
                    Success = false,
                    Code = BusinessCode.InvalidCredentials,
                    Message = "用户名或密码错误"
                });

            case OtpConsumeOutcome.Malformed:
                // 服务端数据事故：不计次、不外露，但必须留下线索。
                // 对外仍按统一话术，理由见 BusinessCode 里"刻意没有 OTP_CHAIN_MALFORMED"的说明。
                Console.WriteLine($"[Otp] ⚠️ 链记录畸形，账号「{user.Username}」当前无法登录（需重建链）");
                await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore,
                    requestLog,
                    new { Code = BusinessCode.InvalidCredentials, Step = "OTP", ChainMalformed = true },
                    statusBefore, username, AuditResult.Failed, AuditReason.OtpChainMalformed);
                return Unauthorized(new ApiResponse
                {
                    Success = false,
                    Code = BusinessCode.InvalidCredentials,
                    Message = "用户名或密码错误"
                });

            case OtpConsumeOutcome.Mismatch:
                // 与口令错同等对待：计次、可能锁定、统一话术。差异只在审计原因码。
                return await RejectFirstFactorAsync(user, statusBefore, requestLog, username,
                    AuditReason.OtpChainMismatch);

            case OtpConsumeOutcome.Conflict:
                // 同一格被两个请求同时提交，另一个抢先核销成功。
                // **不计次**：这是并发，不是猜测 —— 计入的话"手机和电脑同时登录"就会锁号。
                var conflictResp = new ApiResponse
                {
                    Success = false,
                    Code = BusinessCode.OtpChainConflict,
                    Message = "登录请求发生并发冲突，请重试"
                };
                await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore,
                    requestLog, conflictResp, statusBefore, username, AuditResult.Failed,
                    AuditReason.OtpChainConflict);
                return Conflict(conflictResp);

            case OtpConsumeOutcome.Exhausted:
                // 凭据是真的，链没了。必须回"需重建"，不能压成"口令错"。
                var exhaustedResp = new ApiResponse
                {
                    Success = false,
                    Code = BusinessCode.OtpChainExhausted,
                    Message = "本账号的一次性口令已用尽，请用邮箱验证码重置口令后再登录"
                };
                await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore,
                    requestLog, exhaustedResp, statusBefore, username, AuditResult.Failed,
                    AuditReason.OtpChainExhausted);
                return Unauthorized(exhaustedResp);
        }

        // ⑤ 消耗配额是必须可追溯的事件（§8.3 第 3 条）：审计里要能回答"这一格被什么吃掉了"。
        // 链值本身是凭据，**绝不进日志** —— 只记下标、链长与代数。
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
                Purpose = "LOGIN"
            },
            user.Status.ToString(), username, AuditResult.Success, AuditReason.OtpChainVerified);

        // ── ⑥ 静默续期（§7）：**第二步写**，与上面的核销彻底解耦 ──
        //
        // 为什么必须分开写：若把"核销 + 换链"塞进一次原子写，换链失败会连带本次登录失败 ——
        // 而换链是**锦上添花**：旧链还有余量，照样能登。用户不该为一次锦上添花失败而进不来。
        // 所以这里的任何失败都只写日志与审计，登录结果早已确定。
        if (consumed.NeedsRenewal)
            await TryRenewChainAsync(user, consumed, req.NextChain);
        else if (req.NextChain is not null)
            // 没到续期点却提交了新链：忽略。这不是攻击（有口令就能自己造链），
            // 而是**不该被允许的配额重置**——否则客户端每登一次就能把 k 刷回 N-1，
            // 链的"有配额"这件事就名存实亡了。
            Console.WriteLine($"[Otp] 账号「{user.Username}」在非续期窗口提交了新链，已忽略（k={next.K}/{next.Length}）");

        // 警戒线：只喊，不改行为。§7.4 要求"对用户静默，但对系统不能静默"。
        if (consumed.AtAlertLine)
            Console.WriteLine($"[Otp] ⚠️ 账号「{user.Username}」的链已跌破警戒线（k={next.K}/{next.Length}，" +
                              $"第 {consumed.Snapshot!.Value.Generation} 代）—— 若下次续期仍未成功，账号将无法用链值登录");

        return await ContinueAfterFirstFactorAsync(user, statusBefore, requestLog, username);
    }

    /* ==================== 登录：静默续期（P4，两步写的第二步） ==================== */

    /**
     * 把链换成客户端随登录提交的新一代。
     *
     * ── 这一步为什么"失败也无所谓" ──────────────────────────────
     * 它只在 `k ≤ N×5%` 时触发，此时旧链**还有余量**：换失败了大不了下次再换。
     * 所以本方法不返回值、不影响登录结果 —— 它的全部产出是"日志 + 一条审计"。
     *
     * ── 为什么服务端只能收下客户端算的链 ────────────────────────
     * 服务端没有口令，算不出新链根。它只校验形状，然后条件替换。
     * 这带来一个必须承认的边界：形状合法但内容错的新链会把账号推进「链不可用」的状态，
     * 而服务端无从分辨。**P8 之后这条边界的代价变大了** —— 原来的兜底是「口令路径还在，
     * 重登一次就能再续一条」，现在没有第二条路，坏掉的链只能靠 `reset-password`
     * （邮箱验证码 + 新口令，它会整条重建）或运维工具 `--rechain` 修复。
     * 之所以仍然接受这个风险：新链由本机 Rust 侧用同一个确定性算法算出，
     * `otp_p7_probe.py` 与 `otp_p7_ui_e2e.mjs` 会在装机产物上各验一遍；
     * 而拒绝续期的代价是链变短直至用尽 —— 那是**确定会发生**的故障，比"可能坏"更差。
     *
     * ── 条件写为什么用"核销时读到的那一代 R" ───────────────────
     * 两台设备可能同时续期。若这里重新去库里读 R，就可能把"对方刚换好的新链"
     * 当成起点再覆盖一次 —— 结果是两边各自的新链互相作废，代数越滚越多。
     * 用快照里的 R 做条件后，抢输的一方写入被拒（返回 false），旧链继续有效。
     */
    private async Task TryRenewChainAsync(User user, OtpConsumeResult consumed, OtpNextChain? next)
    {
        // 核销成功才能走到这里 ⇒ 快照必然存在。
        var snapshot = consumed.Snapshot!.Value;
        var length = snapshot.Length;

        if (next is null || string.IsNullOrWhiteSpace(next.R) || string.IsNullOrWhiteSpace(next.Head))
        {
            // 客户端**没有**提交新链。不阻断登录，但必须留痕：
            // 这是"链正在静默变短"的唯一线索，缺了它，某天登录失败时无从归因。
            Console.WriteLine($"[Otp] 账号「{user.Username}」已到续期线（k={consumed.NewState!.Value.K}/{length}）" +
                              "但未提交新链，本次跳过续期");
            await WriteRenewAuditAsync(user, AuditAction.OtpRenewFailed, consumed, snapshot,
                renewed: false, outcome: "NO_NEXT_CHAIN", errorType: null, reason: AuditReason.OtpRenewFailed);
            return;
        }

        try
        {
            // 新链从满配额开始：k = N-1。链长与迭代次数**继承旧链**而不是读当前配置 ——
            // 配置改了不该让这一次续期悄悄换掉参数（那会让同一账号的两代链不可比）。
            var newState = new OtpChainState(next.Head, length - 1, length);
            var replaced = await _chains.RenewAsync(
                user.Id, snapshot.R, next.R, newState, snapshot.KdfIterations, length);

            if (replaced)
            {
                Console.WriteLine($"[Otp] 账号「{user.Username}」链已续期：第 {snapshot.Generation} → {snapshot.Generation + 1} 代，" +
                                  $"k 回到 {length - 1}/{length}");
                await WriteRenewAuditAsync(user, AuditAction.OtpRenewed, consumed, snapshot,
                    renewed: true, outcome: "RENEWED", errorType: null, reason: AuditReason.OtpRenewed);
            }
            else
            {
                // 条件未命中：别的请求刚刚换过链。**这不是错误**，旧链（或对方的新链）仍然有效。
                Console.WriteLine($"[Otp] 账号「{user.Username}」续期未生效：种子已被并发请求换过（旧链继续有效）");
                await WriteRenewAuditAsync(user, AuditAction.OtpRenewFailed, consumed, snapshot,
                    renewed: false, outcome: "STALE_SEED", errorType: null, reason: AuditReason.OtpRenewFailed);
            }
        }
        catch (Exception ex)
        {
            // 写库失败 / 形状非法（RenewAsync 会在写库前拒掉坏形状）。
            // 一律不外抛：本次登录已经成功，续期失败最多让链少一格。
            Console.WriteLine($"[Otp] 账号「{user.Username}」续期失败（不影响本次登录，下次登录会再试）: {ex.Message}");
            try
            {
                await WriteRenewAuditAsync(user, AuditAction.OtpRenewFailed, consumed, snapshot,
                    renewed: false, outcome: "ERROR", errorType: ex.GetType().Name,
                    reason: AuditReason.OtpRenewFailed);
            }
            catch (Exception auditEx)
            {
                // 审计也写不进去时更不能抛：这条路径已经处在"出问题"的状态上。
                Console.WriteLine($"[Otp] 续期失败记录也未能写入审计: {auditEx.Message}");
            }
        }
    }

    /**
     * 续期结果的审计。**响应袋里只放公开参数**：种子只记前 8 位（用于"是不是同一代"的对账），
     * 链头一个字节都不记 —— 链头是下一格的直接来源，落进审计等于把配额白送。
     */
    private Task WriteRenewAuditAsync(User user, string action, OtpConsumeResult consumed,
        OtpChainSnapshot snapshot, bool renewed, string outcome, string? errorType, string reason)
    {
        var next = consumed.NewState!.Value;
        return _auditWriter.WriteAsync(user.Id, user.Username, action, user.Status.ToString(),
            new { user.Username, Purpose = "RENEW" },
            new
            {
                Renewed = renewed,
                Outcome = outcome,
                ErrorType = errorType,
                // 当前（旧）链的状态：k 是"还剩多少"，generation 是"第几代"
                K = next.K,
                ChainLength = snapshot.Length,
                Generation = snapshot.Generation,
                // 只留前 8 位用于对账，够区分"是不是同一代"，不足以重建任何东西
                OldSeedPrefix = snapshot.R.Length >= 8 ? snapshot.R[..8] : snapshot.R
            },
            user.Status.ToString(), user.Username,
            renewed ? AuditResult.Success : AuditResult.Failed, reason);
    }

    /* ==================== 登录：账号定位与状态闸门 ==================== */

    /** 账号定位的结果。User 与 Denial 互斥：Denial 非空时 User 必为 null。 */
    private readonly record struct LoginCandidate(User? User, string StatusBefore, IActionResult? Denial);

    /**
     * 从用户名走到"可以开始验凭据"的状态，或直接给出拒绝响应。
     *
     * 为什么单独抽出来：口令分支与链值分支必须**逐步一致** ——
     * 锁定判定要用同一条时间线、冻结要先于凭据校验、待审核不能被漏掉。
     * 各写一份的后果不是"多几行代码"，而是某些账号在其中一条路径上变成凭据探针。
     */
    private async Task<LoginCandidate> ResolveLoginCandidateAsync(string username, object requestLog)
    {
        var user = await _db.Users.Find(u => u.Username == username).FirstOrDefaultAsync();
        if (user == null)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.InvalidCredentials, Message = "用户名或密码错误" };
            await _auditWriter.WriteAsync("anonymous", username, AuditAction.LoginFailed, "N/A", requestLog, resp, "N/A",
                username, AuditResult.Failed, AuditReason.InvalidCredentials);
            return new LoginCandidate(null, "N/A", Unauthorized(resp));
        }

        var statusBefore = user.Status.ToString();

        // 锁定期间，即使正确凭据也拒绝登录。
        // 注意判定不再直接拿墙钟比：TimeGuard 会核对"墙钟"与"锁定时的墙钟 + 真实流逝的
        // 运行时长"这两条线，背离时以单调线为准 ——
        // 于是把电脑时间往前拨 3 分钟并不会让这里放行。
        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue)
        {
            var verdict = TimeGuard.Assess(user, TimeGuard.WallNow(), TimeGuard.UptimeMs());
            await LogClockDriftIfAnyAsync(user, verdict, "LOGIN", username);

            if (verdict.Locked)
                return new LoginCandidate(null, statusBefore,
                    await LockoutRejectionAsync(user, verdict, AuditAction.LoginFailed, statusBefore,
                        requestLog, username, "账号已锁定，请 ", 401));

            // 锁定时间已过（按可靠时刻判断），自动恢复为启用状态
            // 失败计数与窗口锚点一并清掉：解锁后应当从 0 重新数满 3 次。
            user.Status = UserStatus.Enabled;
            ResetFailedAttempts(user);
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            statusBefore = UserStatus.Enabled.ToString();
        }

        if (user.Status == UserStatus.Pending)
        {
            var resp = new ApiResponse { Success = false, Code = BusinessCode.PendingApproval, Message = "账号待审核，请联系管理员" };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, user.Status.ToString(),
                username, AuditResult.Failed, AuditReason.PendingApproval);
            return new LoginCandidate(null, statusBefore, Unauthorized(resp));
        }

        // 冻结账号（沉睡治理的产物）：直接拒绝，且**放在凭据校验之前**。
        //
        // 顺序很重要：若先验凭据，冻结就只是"拦住知道口令的人"——
        // 攻击者仍可对冻结账号验证凭据猜测是否命中（正确凭据会走到下一步，
        // 于是错误码从"口令错"变成别的），等于给已停用的账号留了个探针。
        // 先判状态 ⇒ 不论凭据对错一律 ACCOUNT_DISABLED，不透出任何凭据信息。
        if (user.Status == UserStatus.Disabled)
        {
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.AccountDisabled,
                Message = "账号已被冻结，如需恢复请联系用户管理员"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp,
                user.Status.ToString(), username, AuditResult.Failed, AuditReason.AccountDisabled);
            return new LoginCandidate(null, statusBefore, Unauthorized(resp));
        }

        return new LoginCandidate(user, statusBefore, null);
    }

    /* ==================== 登录：第一因子失败的唯一出口 ==================== */

    /**
     * 第一因子不匹配（口令错 / 链值不符）：计次 →（可能）锁定 → 落库 → 审计。
     *
     * 两条路径共用同一段代码的理由与 ApplyCountedFailureAsync 相同：
     * 各写一份，锁定锚点迟早会走偏，而"锁定什么时候到期"只能有一个答案。
     * 唯一的差异是审计原因码 —— 它是"被猜的是哪一类凭据"的证据。
     */
    private async Task<IActionResult> RejectFirstFactorAsync(User user, string statusBefore, object requestLog,
        string target, string mismatchReason)
    {
        // 两个时间读数只取一次，供"失败计数窗口的锚点"与"锁定锚点"共用：
        // 分两次读会拿到两个不同步的"现在"，让本应同起点的锚点对不上。
        var failWallNow = TimeGuard.WallNow();
        var failUptimeMs = TimeGuard.UptimeMs();

        // 计一次失败：只有落在同一个窗口（FailureWindow）内的才累加。
        // 窗口过期时由它把计数归零、本次成为新窗口的第 1 次 ——
        // 这里刻意不自己判"过期没有"，窗口语义只有基类那一份实现。
        // 它同时是"还没锁定就拨钟"的唯一留痕点：拨钟不改变本次尝试的结果
        // （不加罚、也不放过），只让"有人动过时钟"在审计里留下一条。
        var thresholdReached = await RegisterFailedAttemptAsync(user, failWallNow, failUptimeMs, target);

        string? message;
        string code;
        string reason;
        UserStatus newStatus = user.Status;
        DateTime? lockoutEnd = user.LockoutEnd;

        if (thresholdReached)
        {
            newStatus = UserStatus.Locked;
            // 锁定时同时记下**两个**时间锚点：墙钟 + 系统运行时长。
            // 只记墙钟的话，"现在到了没有"就还得再读一次墙钟，
            // 而墙钟恰恰是能被拨动的那一个（拨快 3 分钟即可解锁）；
            // 运行时长不受拨钟影响，两者一对比就知道这段时间真实过去了多久。
            lockoutEnd = failWallNow.Add(LockoutDuration);
            user.Status = newStatus;
            user.LockoutEnd = lockoutEnd;
            user.LockoutWallAt = failWallNow;
            user.LockoutUptimeAt = failUptimeMs;
            // 新的一轮锁定：把"已就时钟背离告警过"的标记归零，
            // 否则上一轮留下的 true 会让这一轮的拨钟不再留痕。
            user.LockoutDriftLogged = false;
            message = $"连续输错 {MaxFailedAttempts} 次密码，账号已锁定 {LockoutDuration.TotalMinutes} 分钟";
            code = BusinessCode.AccountLocked;
            // 本次尝试既"凭据错"也"触发锁定"，审计语义上按更严重的锁定归类：
            // 审计员要能一条查询捞出"所有因凭据错误而锁定的事件"。
            reason = AuditReason.AccountLocked;
        }
        else
        {
            message = $"密码错误，还剩 {MaxFailedAttempts - user.FailedLoginAttempts} 次机会";
            code = BusinessCode.InvalidCredentials;
            reason = mismatchReason;
        }

        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
        var resp = new ApiResponse
        {
            Success = false,
            Code = code,
            Message = message,
            Data = new { FailedAttempts = user.FailedLoginAttempts, LockoutEnd = lockoutEnd }
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginFailed, statusBefore, requestLog, resp, user.Status.ToString(),
            target, AuditResult.Failed, reason);
        return Unauthorized(resp);
    }

    /* ==================== 登录：第一因子之后的统一收口 ==================== */

    /**
     * 第一因子已通过：过第二因子闸门，然后交给 CompleteLoginAsync。
     *
     * ⚠️ 从这里往下，**还没有**清零失败计数、**还没有**更新 lastLoginAt、
     *    更没有签发任何票据。这三件事统一由 CompleteLoginAsync 在"整段认证全部通过"时
     *    一次做完 —— 理由见该方法注释（否则人脸这一因子会变成一条不会触发锁定的凭据探针）。
     *
     * 两个第一因子路径共用它，是为了让"链值登录 + 人脸"与"口令登录 + 人脸"
     * 走的是**同一条**第二因子链路：否则会出现"某一路绕过人脸"这种最难发现的缺口。
     */
    private async Task<IActionResult> ContinueAfterFirstFactorAsync(User user, string statusBefore,
        object requestLog, string target)
    {
        if (_face.Enabled)
        {
            var decision = await _face.AssessAsync(user);

            if (decision.Requirement == FaceLoginService.Requirement.EngineUnavailable)
            {
                // 该账号已录人脸（= 自愿启用了第二因子），但本机引擎不可用。
                // 这里**拒绝**而不是"跳过第二因子放行"：跳过等于给出一条
                // "把摄像头占用/弄坏就降回单因子"的静默通道（见 FaceLoginService.AssessAsync）。
                var resp = new ApiResponse
                {
                    Success = false,
                    Code = BusinessCode.FaceEngineUnavailable,
                    Message = $"该账号已启用刷脸验证，但本机人脸引擎不可用：{decision.Message}。"
                              + "请联系用户管理员重置你的人脸后重试。"
                };
                await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginFailed, statusBefore,
                    requestLog, resp, user.Status.ToString(), target, AuditResult.Failed,
                    AuditReason.FaceEngineUnavailable);
                return StatusCode(503, resp);
            }

            if (decision.Requirement == FaceLoginService.Requirement.Challenge)
            {
                var (token, action) = _face.Issue(user.Username);

                // 放行"识别画面"：把这张挑战登记成一段**会自己结束**的预览窗口。
                // 门禁就绑在挑战上 —— 拿不到挑战（= 没过口令）就拿不到画面，
                // 而过期/被消费/被取消之后，窗口自动关闭。
                _preview.Open(token, _face.ChallengeTtlSeconds);

                var challengeResp = new ApiResponse<FaceChallengeResponse>
                {
                    // Success=true 表示"这一步本身成功":口令这一因子已经通过，
                    // 流程正确地进入第二阶段。它与"已登录"完全不同——
                    // 响应里没有票据，客户端拿不到任何可用于访问接口的凭据。
                    Success = true,
                    Code = BusinessCode.FaceRequired,
                    Message = "口令已通过，请完成人脸验证",
                    Data = new FaceChallengeResponse
                    {
                        ChallengeToken = token,
                        Action = action,
                        ActionText = FacePose.ActionText(action),
                        ActionHint = FacePose.ActionHint,
                        ExpiresInSeconds = _face.ChallengeTtlSeconds,
                        Threshold = _face.Threshold
                    }
                };
                await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginRequired, statusBefore,
                    requestLog,
                    new { user.Username, Step = "PASSWORD_OK", ChallengeIssued = true, Action = action },
                    user.Status.ToString(), target, AuditResult.Success);
                return Ok(challengeResp);
            }
        }

        // 未录人脸（或模块关闭）⇒ 与改造前逐字一致的单因子登录。
        return await CompleteLoginAsync(user, statusBefore, requestLog, target, secondFactor: false);
    }

    /* ==================== 登录第二阶段：人脸验证 ==================== */

    /**
     * 人脸验证通过后，提交一次性挑战，由服务端自己开摄像头完成动作挑战并比对模板。
     *
     * 这是**未鉴权**接口 —— 此时还没有任何票据可携带，唯一的凭据就是那张一次性挑战 token。
     * 它之所以安全，是因为 token 只可能来自"口令刚刚验证通过"那一步，且随机、新鲜、一次性：
     *   拿不到 token 的人，必须先有一个正确的口令。
     *
     * 接口上**只有 token 一个输入**，没有"画面"也没有"特征" ——
     * 采集与特征提取全在服务端进程内完成。这不是省事，是这条功能的立身之本：
     * 一旦允许前端上送特征，攻击者就能不碰摄像头、直接 POST 一个向量。详见设计文档 §四。
     */
    [HttpPost("login/face")]
    public async Task<IActionResult> LoginFace([FromBody] FaceVerifyRequest req)
    {
        var (user, action, error) = await _face.BeginVerifyAsync(req.ChallengeToken);

        if (error is not null || user is null || action is null)
        {
            // 认不出这张票属于谁 ⇒ 无法归属到某个账号，因此**不累加任何计数**
            // （计数是账号级的量，无主的失败没有累加对象）。
            // 这不构成绕过：要拿到 token 必须先过口令，重放一张已消费/过期的票并不推进攻击。
            var resp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.FaceChallengeInvalid,
                Message = FaceCodes.MessageFor("FACE_CHALLENGE_INVALID")
            };
            await _auditWriter.WriteAsync("anonymous", "anonymous", AuditAction.FaceLoginFailed, "N/A",
                new { Step = "FACE", ChallengePresent = !string.IsNullOrWhiteSpace(req.ChallengeToken) },
                resp, "N/A", "anonymous", AuditResult.Failed, AuditReason.FaceChallengeInvalid);
            return Unauthorized(resp);
        }

        var statusBefore = user.Status.ToString();
        var requestLog = new { user.Username };

        // 口令通过之后、人脸完成之前，账号状态仍可能被管理员改掉（冻结 / 锁定）。
        // 这里**重新判一次**：否则"口令通过那一刻还正常、之后被冻结"的账号
        // 仍会被人脸这一步放进来 —— 等于给处置动作留了一个时间窗。
        if (user.Status == UserStatus.Locked && user.LockoutEnd.HasValue)
        {
            var verdict = TimeGuard.Assess(user, TimeGuard.WallNow(), TimeGuard.UptimeMs());
            await LogClockDriftIfAnyAsync(user, verdict, "LOGIN_FACE", user.Username);

            if (verdict.Locked)
                return await LockoutRejectionAsync(user, verdict, AuditAction.FaceLoginFailed, statusBefore,
                    requestLog, user.Username, "账号已锁定，请 ", 401);

            user.Status = UserStatus.Enabled;
            ResetFailedAttempts(user);
            await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);
            statusBefore = UserStatus.Enabled.ToString();
        }

        if (user.Status == UserStatus.Disabled)
        {
            var disabledResp = new ApiResponse
            {
                Success = false,
                Code = BusinessCode.AccountDisabled,
                Message = "账号已被冻结，如需恢复请联系用户管理员"
            };
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginFailed, statusBefore,
                requestLog, disabledResp, user.Status.ToString(), user.Username, AuditResult.Failed,
                AuditReason.AccountDisabled);
            return Unauthorized(disabledResp);
        }

        // 正式采集开始：这几秒里摄像头归采集循环独占，预览循环主动停手，
        // 画面改由采集循环自己推（见 FacePreviewService.BeginCapture）。
        // 用 using + finally 收回预览权，是为了不让任何一条 return 分支
        // 把"这张挑战还能换到画面"这件事留在身后。
        FaceLoginService.VerifyResult result;
        using (var _ = _preview.BeginCapture())
        {
            try
            {
                result = await _face.EvaluateAsync(user, action);
            }
            finally
            {
                _preview.Close(req.ChallengeToken);
            }
        }

        if (result.Passed)
        {
            // 人脸这一因子单独记一条：事后能一条查询捞出"哪些登录真的刷过脸"。
            await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginSuccess, statusBefore,
                requestLog,
                new
                {
                    user.Username,
                    Similarity = result.Similarity,
                    Threshold = _face.Threshold,
                    Diagnostic = result.Diagnostic
                },
                user.Status.ToString(), user.Username, AuditResult.Success);

            // 两个因子都过了 ⇒ 到这里才真正完成登录（清零计数 / 更新 lastLoginAt / 签票）。
            return await CompleteLoginAsync(user, statusBefore, requestLog, user.Username, secondFactor: true);
        }

        // ── 未通过：按 A/B 组决定要不要计入 3 分钟失败窗口 ──
        // A 组（欺骗信号 / 主动绕过）计次，B 组（质量问题 / 配合问题）不计 ——
        // 否则用户会被自己的摄像头误伤到锁号，而症状（"我明明是对的脸却登不上"）极难归因。
        string? lockMessage = null;
        if (result.Counted)
            lockMessage = await ApplyCountedFailureAsync(user);
        // 不计次的分支刻意**不写库**：质量问题不改变账号上的任何字段。
        // 多写一次除了浪费一次往返，还会让"这次到底动没动计数"变得难以从代码上一眼看清。

        var reason = result.AuditReason;
        var responseCode = result.BusinessCode;
        if (lockMessage is not null)
        {
            // 本次既"人脸没过"也"触发锁定"，审计按更严重的锁定归类 ——
            // 与口令失败那条路径的口径一致，好让"所有因验证失败而锁定"能被一条查询捞出。
            responseCode = BusinessCode.AccountLocked;
            reason = AuditReason.AccountLocked;
        }

        var failResp = new ApiResponse
        {
            Success = false,
            Code = responseCode,
            Message = lockMessage ?? result.Message,
            Data = new
            {
                FailedAttempts = user.FailedLoginAttempts,
                LockoutEnd = user.LockoutEnd,
                Similarity = result.Similarity,
                Threshold = _face.Threshold
            }
            // 刻意**不下发** Counted：那等于告诉攻击者"哪一类失败不会被计数"。
        };
        await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.FaceLoginFailed, statusBefore, requestLog,
            new
            {
                user.Username,
                BusinessCode = responseCode,
                Similarity = result.Similarity,
                Threshold = _face.Threshold,
                Counted = result.Counted,
                Diagnostic = result.Diagnostic
            },
            user.Status.ToString(), user.Username, AuditResult.Failed, reason);
        return Unauthorized(failResp);
    }

    /* ==================== 人脸识别画面（预览） ==================== */

    /**
     * 取一帧"识别画面"。这是一条**未鉴权**接口 —— 与 login/face 同类，
     * 此时还没有任何票据可携带。
     *
     * 它凭什么安全（这三条必须一起成立，少一条都不能开这个口子）：
     *   ① **凭据是一张一次性挑战 token**，而挑战只可能来自"口令刚刚验证通过"
     *      （登录）或"本人重新输了一遍当前口令"（录入）。拿不到 token 的人，
     *      必须先知对口令 —— 不是"本机任何页面都能来拉摄像头流"。
     *   ② **窗口会自己结束**：token 过期、被消费、或采集结束，预览立刻失效
     *      （`FaceChallengeStore` 的 TTL 与这里的 `Close` 各管一头）。
     *   ③ **双向只出图像**：接口上没有"接收画面或特征"的形状，出去的也只是
     *      服务端画好框的图，关键点坐标从不下发。
     *
     * ⚠️ 与设计期登记的那条威胁一致：它仍然落在未鉴权面上，
     *    缓解手段依旧只有"仅绑环回" + 挑战门禁。**不要对外宣称这条已被解决。**
     *
     * 刻意**不写审计**：预览是界面行为，一次登录可能拉几百帧；若每帧记一条，
     * 审计链会被无意义地灌满。真正需要留痕的是"谁在什么时候被要求刷脸"
     * （FACE_LOGIN_REQUIRED，已在签发挑战那一步记过）。
     */
    [HttpGet("face/preview")]
    public IActionResult FacePreview([FromQuery] string? token)
    {
        if (!_preview.IsOpen(token))
        {
            // 用 404 而不是 401：这里没有"认证失败"的语义，
            // 只是"这张票不在预览窗口里"，且不该给探测者任何额外信息。
            return NotFound(new ApiResponse
            {
                Success = false,
                Code = BusinessCode.FaceChallengeInvalid,
                Message = FaceCodes.MessageFor("FACE_CHALLENGE_INVALID")
            });
        }

        var frame = _preview.Latest;
        if (frame is null)
        {
            // 窗口是开的、但还没攒出第一帧（刚放行时必然如此，约一个取帧周期）。
            // 报 503 而不是 200+空图：让客户端把"暂无画面"和"画面是黑的"区分开。
            return StatusCode(503, new ApiResponse
            {
                Success = false,
                Code = BusinessCode.FaceEngineUnavailable,
                Message = "暂时还取不到画面，请稍候"
            });
        }

        // 状态只走响应头（响应体是 JPEG）。跨源时这两个头必须由 CORS 显式放行，
        // 否则浏览器会把它们挡在 JS 之外（见 Program.cs 的 WithExposedHeaders）。
        Response.Headers["X-Face-State"] = frame.State;
        Response.Headers["X-Face-Score"] = frame.Score?.ToString("F4",
            System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        Response.Headers["Cache-Control"] = "no-store";

        return File(frame.Jpeg, "image/jpeg");
    }

    /* ==================== 登录完成的唯一出口 ==================== */

    /**
     * 一次登录**真正完成**的唯一出口。
     *
     * 为什么"清零失败计数 + 更新 lastLoginAt + 签发票据 + 写 LOGIN_SUCCESS"必须收在一处：
     *   引入第二因子后，登录从"一步"变成"口令 + 人脸"两步。
     *   如果在口令那一步就把失败计数清零，那么一个**已经知道口令**的攻击者
     *   只要反复"口令正确 → 人脸随便过两下 → 失败 → 重新登录"，
     *   就能让计数在每次口令通过时归零，**永远刷不满 3 次** ——
     *   人脸这一因子反而被自己变成了一个不会被锁定的口令探针。
     *   所以清零只发生在"两个因子都过"的那一刻，与 lastLoginAt、票据同生共死。
     *
     * secondFactor 只进审计的 JSON 袋（**不加列**，见 AuditLog 的字段约束）：
     *   事后必须能回答"这次 LOGIN_SUCCESS 到底有没有过第二因子"，
     *   因为它直接决定这条成功记录代表多强的认证。
     */
    private async Task<IActionResult> CompleteLoginAsync(User user, string statusBefore, object requestLog,
        string target, bool secondFactor)
    {
        // 失败计数与窗口一起归零（下次要从 0 重新数满 3 次）。
        // 走统一出口 —— 清零牵动 5 个字段，散着写迟早漏掉一个。
        if (user.FailedLoginAttempts > 0)
            ResetFailedAttempts(user);

        // ── 沉睡账号治理：记录最后一次成功登录 ──
        // 为什么记在"登录成功"这一处：它是全系统唯一入口（任何操作都要先拿票据），
        // 于是"在这写一次"就等于"覆盖全部真实使用"。沉睡判定以本字段为基准，
        // 漏写会让活跃账号被误判成沉睡 —— 这是本功能最不能出错的地方。
        // 注意：人脸没过的那次**不算**成功登录，因此不会走到这里，
        // lastLoginAt 也就不会被一次失败的尝试刷新。
        user.LastLoginAt = DateTime.UtcNow;

        // 上面两条改动合并在一次写入里（而不是各写一次）：
        // 同一请求内对同一文档的两次 Replace 会白跑一次往返，也更容易在
        // 未来某次改动中漏掉其中一条。
        await _db.Users.ReplaceOneAsync(u => u.Id == user.Id, user);

        // 登录成功 → 签发服务端会话票据。
        // 票据是后续所有管理员接口的凭证，也是"普通用户无权查看审计日志"能成立的前提。
        // 注意明文只存在于 issued.Ticket（随响应发回客户端），**库里落的是它的哈希**。
        var issued = await _sessions.IssueAsync(user);

        var successResp = new ApiResponse<LoginResult>
        {
            Success = true,
            Code = BusinessCode.Ok,
            Message = "登录成功",
            Data = new LoginResult
            {
                Username = user.Username,
                Status = user.Status.ToString(),
                Role = user.Role.ToString(),
                RoleLabel = UserRoles.Label(user.Role),
                IsAdmin = UserRoles.CanManageUsers(user.Role),
                Ticket = issued.Ticket,
                ExpiresAt = issued.Session.ExpiresAt
            }
        };
        // 审计里绝不记录票据本体，只记"已签发"这一事实
        await _auditWriter.WriteAsync(user.Id, user.Username, AuditAction.LoginSuccess, statusBefore, requestLog,
            new
            {
                user.Username,
                user.Status,
                Role = user.Role.ToString(),
                TicketIssued = true,
                SecondFactor = secondFactor ? "FACE" : "NONE"
            },
            user.Status.ToString(), target, AuditResult.Success);
        return Ok(successResp);
    }
}
