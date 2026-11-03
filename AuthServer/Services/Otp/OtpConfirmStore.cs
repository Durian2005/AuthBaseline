using System.Collections.Concurrent;
using System.Security.Cryptography;
using AuthServer.Services;

namespace AuthServer.Services.Otp;

/**
 * 「一次性确认凭据」的用途白名单。
 *
 * 为什么用字符串常量而不是枚举：这个值要出现在 **HTTP 请求体**里（客户端算好、服务端核对），
 * 枚举会被序列化成数字，于是"6 个魔法数字"就成了接口契约 —— 日后调换枚举顺序
 * 会静默地把 `face-enroll` 变成 `face-delete`（一个是录入、一个是删除，方向正好相反）。
 * 字符串则永远可读、可对账、可在审计里直接检索。
 */
public static class OtpConfirmPurpose
{
    public const string CreateAccount = "create-account";
    public const string SetRole = "set-role";
    public const string FaceEnroll = "face-enroll";
    public const string FaceDelete = "face-delete";
    public const string FaceIdEnroll = "faceid-enroll";
    public const string FaceIdDelete = "faceid-delete";

    /// <summary>全部合法用途。签发与消费两侧都只认这一份清单。</summary>
    public static readonly string[] All =
    {
        CreateAccount, SetRole, FaceEnroll, FaceDelete, FaceIdEnroll, FaceIdDelete
    };

    public static bool IsKnown(string? purpose) =>
        !string.IsNullOrEmpty(purpose) && Array.IndexOf(All, purpose) >= 0;

    /// <summary>
    /// 该用途是否**必须**显式指定目标账号。
    ///
    /// 只有两个管理类用途需要：它们操作的永远是别人，而"别人"是谁无法从票据推断。
    /// 四个 face* 是自助操作，目标恒为票据本人 —— 让客户端去填自己的用户名，
    /// 只是多一个可能填错、且填错也没有任何安全收益的字段。
    /// </summary>
    public static bool RequiresTarget(string? purpose) =>
        purpose is CreateAccount or SetRole;
}

/// <summary>确认凭据的核验结果。</summary>
public enum OtpConfirmStatus
{
    /// <summary>有效，且已消费（此凭据不能再用）。</summary>
    Ok,

    /// <summary>不存在 / 已用过 / 已过期 —— 三者对外**不做区分**。</summary>
    NotFound,

    /// <summary>凭据属于另一个账号。**依然视为已消费**，见 <see cref="OtpConfirmStore.Consume"/>。</summary>
    OwnerMismatch,

    /// <summary>用途不符（拿"录入人脸"的凭据去删人脸）。同样视为已消费。</summary>
    PurposeMismatch,

    /// <summary>目标不符（拿"给 alice 提权"的凭据去给 root 提权）。同样视为已消费。</summary>
    TargetMismatch
}

/**
 * 一次性的「敏感操作确认凭据」。
 *
 * ── 它解决的是什么问题 ────────────────────────────────────────
 * 票据是 Bearer 凭据：它证明"这个会话登录过"，但不证明"此刻坐在电脑前的是本人"。
 * 会话活几小时，人可能已经走开。原来六处敏感操作靠"再打一遍口令"补这个洞；
 * 换成一次性口令模型后，"知道口令"不再是一个可提交的动作 —— 能提交的只有链值。
 * 于是问题变成：**链值应该在每个敏感接口里各验一次，还是先换一张票？**
 *
 * 选后者（`/api/auth/reconfirm` 换票），理由有三条，都不是风格问题：
 *  1. **链值会被两处消费**（登录与再认证）。若六个接口各自去 CAS，就有六份
 *     "抢输了怎么办"的实现；集中到一处，只有一份。
 *  2. **绑定关系有了落点**。"这张确认只对 create-account 有效、只对 alice 有效"
 *     必须有地方记 —— 记在凭据里比记在六个接口的 if 里可靠。
 *  3. **审计能回答"那次确认是为了什么"**。凭据本身带用途，审计不必靠猜。
 *
 * ── 三个刻意的设计决定 ───────────────────────────────────────
 *  ① **验之前先删**：任何一次消费尝试都会让凭据消失，即使用途或目标不符。
 *     若"不符就不删"，一张凭据可以被反复试六种用途 —— 而用途恰恰是它唯一的
 *     保护维度。宁可让一个写错用途的客户端多确认一次（可恢复），
 *     也不要让凭据变成一张可以逐项试错的通票（不可恢复）。
 *  ② **不落库**：它只活 120 秒、一次即弃。落库要额外面对"过期清理"和
 *     "重启后仍在"两个问题，而重启后留在库里的确认票只会是残留风险。
 *     代价是多实例部署时凭据不共享 —— 本项目 sidecar 与客户端同机，
 *     进程只有一个，这个代价为零（与 <see cref="OtpChallengeStore"/> 同一取舍）。
 *  ③ **TTL 用单调时钟**（<see cref="TimeGuard.UptimeMs"/>）：凭据的有效期
 *     不该被系统时间调整影响。墙钟往前拨一小时就"永不过期"，
 *     往后拨一小时就"刚签发就失效"，两种都不是我们想要的语义。
 */
public sealed class OtpConfirmStore
{
    /// <summary>同时存活的凭据上限。超过就淘汰最早签发的那张。</summary>
    private const int MaxPending = 512;

    /// <summary>token 的字节长度。256 位随机，猜不出来，也不需要猜。</summary>
    private const int TokenBytes = 32;

    private sealed record Entry(string UserId, string Purpose, string Target, long CreatedAtMs, long ExpiresAtMs);

    private readonly ConcurrentDictionary<string, Entry> _pending = new(StringComparer.Ordinal);
    private readonly OtpOptions _opt;
    private readonly Func<long> _uptimeMs;

    public OtpConfirmStore(OtpOptions opt, Func<long>? uptimeMs = null)
    {
        _opt = opt;
        // 可注入单调时钟：单测要能"把时间往后拨 121 秒"，而不必真的 sleep。
        _uptimeMs = uptimeMs ?? TimeGuard.UptimeMs;
    }

    /// <summary>
    /// 签发一张确认凭据。
    /// </summary>
    /// <param name="userId">持票人。消费时必须同一人 —— 否则"用我的确认去操作你的账号"。</param>
    /// <param name="purpose">用途，取自 <see cref="OtpConfirmPurpose"/>。</param>
    /// <param name="target">作用对象（用户名）。自助类操作就是本人用户名。</param>
    public (string Token, int TtlSeconds) Issue(string userId, string purpose, string target)
    {
        // 未知用途直接拒绝签发：放进去只会变成一张"谁也用不上"的凭据，
        // 而调用方会以为它有效 —— 到消费时才失败，归因成本高得多。
        if (!OtpConfirmPurpose.IsKnown(purpose))
            throw new ArgumentException($"未知的确认用途：{purpose}", nameof(purpose));

        var token = Base64Url(RandomNumberGenerator.GetBytes(TokenBytes));
        var now = _uptimeMs();
        var ttl = _opt.ConfirmTtlSeconds;

        _pending[token] = new Entry(userId, purpose, target, now, now + ttl * 1000L);
        Trim(now);

        return (token, ttl);
    }

    /// <summary>
    /// 消费一张确认凭据。<b>无论结果如何，这张凭据都不再存在</b>（见类注释 ①）。
    /// </summary>
    public OtpConfirmStatus Consume(string? token, string userId, string purpose, string target)
    {
        if (string.IsNullOrWhiteSpace(token)) return OtpConfirmStatus.NotFound;

        // 先摘出来再判断：摘不到就是"不存在/用过"，摘到了就一定要作废。
        if (!_pending.TryRemove(token, out var entry)) return OtpConfirmStatus.NotFound;

        if (_uptimeMs() >= entry.ExpiresAtMs) return OtpConfirmStatus.NotFound;

        // 三个绑定维度分开返回，是为了让审计能写下"到底哪一维不符"。
        // 对外的话术仍然统一（都是"请重新确认身份"）—— 逐维解释等于告诉攻击者
        // 他手里这张票是哪里来的。
        if (!string.Equals(entry.UserId, userId, StringComparison.Ordinal)) return OtpConfirmStatus.OwnerMismatch;
        if (!string.Equals(entry.Purpose, purpose, StringComparison.Ordinal)) return OtpConfirmStatus.PurposeMismatch;
        if (!string.Equals(entry.Target, target, StringComparison.Ordinal)) return OtpConfirmStatus.TargetMismatch;

        return OtpConfirmStatus.Ok;
    }

    /// <summary>当前存活数量。仅用于单测与诊断，不参与任何判定。</summary>
    public int Count => _pending.Count;

    /// <summary>
    /// 超过上限时淘汰最早签发的那些。
    ///
    /// 为什么可以随便淘汰：每张凭据都对应一次刚刚做过的链值再认证。淘汰只会让
    /// 用户"再确认一次"，不会让人进不来 —— 而任由它增长则是内存泄漏，
    /// 且这张表在攻击者手里是**可以主动填充**的（只要他有票据与链值）。
    /// </summary>
    private void Trim(long now)
    {
        if (_pending.Count <= MaxPending) return;

        foreach (var (token, _) in _pending.OrderBy(kv => kv.Value.CreatedAtMs).Take(_pending.Count - MaxPending))
            _pending.TryRemove(token, out _);
    }

    /// <summary>Base64Url（无填充）：能直接放进 JSON 与查询串，不需要再做一次转义。</summary>
    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
