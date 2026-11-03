namespace AuthServer.Services.Otp;

/**
 * 一次性口令（哈希链）的配置。
 *
 * 全部有默认值：缺配置时按"可用"启动，而不是像 pepper / 证书那样拒绝启动 ——
 * 拒绝启动的合理性只属于"缺了就一定不安全"的东西（pepper 缺失 ⇒ 存量口令全部失效）；
 * 而链长、迭代次数都是有合理默认值的**参数**，把整个认证系统拖下线才是更糟的失败。
 *
 * ── 与 <see cref="OtpVerifier"/> 的分工（重要） ───────────────
 * 本类只管"部署时可调的数"：链长、迭代次数、挑战有效期。
 *
 * ⚠️ P8 删掉了原来的 `Enabled` 总开关。它存在的唯一理由是"回滚到口令路径"，
 *    而口令路径已经不存在 —— 关掉它只会让**所有人**都登不进来。
 *    "能不能关掉某个功能"是一种安全能力，但前提是关掉之后还有别的路可走。
 * **判定契约性质的常量不进这里**（格宽 32 字节、SHA256、续期线 5%、警戒线 1%），
 * 它们定义在 <see cref="OtpVerifier"/> 且只有那一份 —— 若配置能改 5%，服务端判定与
 * 客户端预期就会各说各话，而"什么时候续链"恰好是客户端也要算的事。
 * 换句话说：这里改的是"链有多长"，不是"链怎么算"。
 *
 * ⚠️ 环境变量覆盖的理由同 FaceIdOptions：安装目录里的 appsettings.json 会被覆盖安装冲掉，
 *    而探针需要在**同一个二进制**上把 N 调小（N=100 ⇒ 20 次登录内就能走到续期路径）。
 */
public class OtpOptions
{
    public const string SectionName = "Otp";

    /// <summary>
    /// 链长 N，默认 1000。
    ///
    /// 选 1000 而不是更大的数，理由与直觉相反：N 决定的是**续期失败时的缓冲深度**（N × 5%），
    /// 不是链的寿命 —— 有静默续链，寿命由"每次登录都是一次续期机会"保证。
    /// N 越大，客户端每次登录要算的 <c>H^k</c> 越慢（k 最大 N-1），
    /// 且探针要跑 0.95N 次登录才能摸到续期路径（N=10000 时几乎无法在测试里覆盖）。
    /// 50 次缓冲足以吸收"写库失败"级别的故障。
    /// </summary>
    public int Length { get; set; } = 1000;

    /// <summary>
    /// PBKDF2 迭代次数，默认 100 000。
    ///
    /// **这不是性能参数**：`v` 是明文存的，拿到库的人可以离线猜口令。
    /// 若省掉这一步（改用裸哈希），每次猜测只需 N 次 SHA-256（约 1ms），
    /// 比现有的 BCrypt+pepper 弱两个数量级 —— 本方案在最重要的拖库场景下反而比现状更差。
    /// 迭代次数与链一起存（见 <c>OtpChain.KdfIterations</c>），所以调高它不影响存量链。
    /// </summary>
    public int KdfIterations { get; set; } = 100_000;

    /// <summary>
    /// 挑战（下发 <c>R</c>/<c>k</c>/<c>N</c> 的那一步）的有效期，默认 120 秒。
    ///
    /// 定这么短是因为挑战**不携带任何秘密**（R 可公开、k 服务端也会校验），
    /// 它的唯一作用是让"客户端算 <c>H^k</c> 时用到的那组参数"与"服务端此刻的状态"对得上。
    /// 太长会让"客户端拿着一小时前的 k 去提交"变成常态（那必然失败，且用户看不懂为什么）；
    /// 太短则会让慢机器上的 PBKDF2（约 50–100ms）来不及。120 秒足够一次点击。
    /// </summary>
    public int ChallengeTtlSeconds { get; set; } = 120;

    /// <summary>
    /// 确认凭据（`/api/auth/reconfirm` 换来的那张票）的有效期，默认 120 秒。
    ///
    /// **刻意不与挑战共用**：两者虽然都是 120 秒的一次性凭据，但改动其中一个的理由
    /// 完全不适用于另一个 —— 挑战的 TTL 受"慢机器算 PBKDF2 要多久"约束，
    /// 确认凭据的 TTL 受"用户隔多久才点下一步表单"约束。共用一个字段，
    /// 未来为了迁就其中一边而调整，就会在另一边悄悄改变安全窗口。
    /// </summary>
    public int ConfirmTtlSeconds { get; set; } = 120;

    /// <summary>
    /// 环境变量覆盖（理由见类注释）。
    /// 与本项目其它模块同一手法：只看非空的变量，非法值**保持默认**而不是把服务改坏 ——
    /// 一个拼错的探针变量不该让认证参数变成 0。
    /// </summary>
    public void ApplyEnvironmentOverrides()
    {
        var length = Environment.GetEnvironmentVariable("AUTHBASELINE_OTP_LENGTH");
        if (!string.IsNullOrWhiteSpace(length) && int.TryParse(length.Trim(), out var n))
            Length = n;

        var iterations = Environment.GetEnvironmentVariable("AUTHBASELINE_OTP_KDF_ITERATIONS");
        if (!string.IsNullOrWhiteSpace(iterations) && int.TryParse(iterations.Trim(), out var it))
            KdfIterations = it;

        var ttl = Environment.GetEnvironmentVariable("AUTHBASELINE_OTP_CHALLENGE_TTL_SECONDS");
        if (!string.IsNullOrWhiteSpace(ttl) && int.TryParse(ttl.Trim(), out var sec))
            ChallengeTtlSeconds = sec;

        var confirmTtl = Environment.GetEnvironmentVariable("AUTHBASELINE_OTP_CONFIRM_TTL_SECONDS");
        if (!string.IsNullOrWhiteSpace(confirmTtl) && int.TryParse(confirmTtl.Trim(), out var csec))
            ConfirmTtlSeconds = csec;
    }

    /// <summary>
    /// 参数自检。**在启动时调用一次**，让错误配置当场炸在明处，而不是等到第一个用户登录失败。
    ///
    /// 为什么这里选择抛异常而不是"悄悄纠正成默认值"：
    ///   链长 1 的链建出来就是死的（初始 k=0，一次都登不了），迭代次数 0 的链根
    ///   等于裸哈希 —— 两者都是"看起来启动了、实际把安全或可用性打掉"的形态。
    ///   静默纠正会把这些错误藏到用户投诉为止。
    /// </summary>
    public void Validate()
    {
        if (Length < 2)
            throw new ArgumentOutOfRangeException(nameof(Length),
                $"链长至少为 2（当前 {Length}）—— 链长 1 的链建出来就没有可用格");

        if (KdfIterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(KdfIterations),
                $"PBKDF2 迭代次数必须为正（当前 {KdfIterations}）—— 为 0 等价于裸哈希");

        if (ChallengeTtlSeconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(ChallengeTtlSeconds),
                $"挑战有效期必须为正（当前 {ChallengeTtlSeconds}）");

        if (ConfirmTtlSeconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(ConfirmTtlSeconds),
                $"确认凭据有效期必须为正（当前 {ConfirmTtlSeconds}）—— 为 0 等于签出来就不能用");
    }

    /// <summary>启动日志用的一行摘要。宁可啰嗦，也不要让人靠猜"现在到底跑在什么档位"。</summary>
    public string Describe() =>
        $"链长 N={Length} · PBKDF2 {KdfIterations} 次 · 挑战 {ChallengeTtlSeconds}s · 确认 {ConfirmTtlSeconds}s · 续期线 {OtpVerifier.RenewThresholdPercent}% · 警戒线 {OtpVerifier.AlertThresholdPercent}%";
}
