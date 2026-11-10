using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace AuthServer.Services.Otp;

/**
 * 登录第一步（challenge）签发的**一次性挑战**。
 *
 * ── 它解决什么问题 ────────────────────────────────────────────
 * 链值验证本身不需要"票"：`H(提交值) == v` 就够了。挑战存在的意义是把三件事钉在一起：
 *   ① **参数新鲜**：客户端算 `x_k` 用的是服务端此刻的 `k`，而不是一小时前缓存的本地下标；
 *   ② **一次性**：同一张挑战不能被反复拿去试（否则"格值错了再试一个"就有了稳定的免费重试通道）；
 *   ③ **归属**：这张挑战只对签发时那个用户名有效，不能被搬去给别人用。
 *
 * ── 它不解决什么（必须说清楚）────────────────────────────────
 * 挑战**不携带任何秘密**，R 本来就是公开下发的。因此：
 *   · 拿到一张挑战 ≠ 能登录（还得算出 `x_k`）；
 *   · 挑战不是票据，拿它调任何需要鉴权的接口都必须失败（它只存在这个类里，
 *     `SessionService` 与它零交集 —— 与 FaceChallengeStore 同一原则）。
 * 所以 token 本身**不需要加密**，只需要不可预测 + 有 TTL + 用过即焚。
 *
 * ── 但参数需要签名（小数攻击）────────────────────────────────
 * token 不透明并不等于挑战可信：中间人可以篡改 `k` 再转发给客户端，客户端算出的
 * 是更靠前的一格，攻击者正向哈希补齐后照样能登录，且顺手拿到后续若干格。
 * 服务端对此**无从分辨**（它收到的就是真正的 `x_k`），所以必须由客户端验签。
 * 签名在 <see cref="OtpChallengeKey"/>，本类只负责把 proof 拼进签发结果。
 *
 * ── 一个刻意的取舍：挑战过期回"挑战无效"，而不是"口令错" ──
 * 两者对攻击者都是"没通过"，但对用户是两件事：前者几乎总是"点了登录之后放了一会儿"，
 * 正确的补救是重新点一次（会自动重取 challenge），而不是去怀疑自己记错口令。
 * 代价是这条路径**不计入失败次数** —— 它本来也不是一次凭据尝试（见 §8.3 的同款判断）。
 */
public sealed class OtpChallengeStore
{
    /// <summary>一张未被消费的挑战。用户名在签发时绑定，之后不再由调用方传入。</summary>
    private sealed record Pending(string Username, DateTime CreatedAt);

    private readonly ConcurrentDictionary<string, Pending> _pending = new();
    private readonly OtpOptions _opt;
    private readonly OtpChallengeKey _signer;

    /// <summary>
    /// 未消费挑战的上限。挑战端点是**匿名**的，任何人不带凭据就能刷；
    /// 没有上限时它就是一条可以被拿来打爆内存的路径（每张 100 字节左右，但请求是无限的）。
    /// </summary>
    private const int MaxPending = 512;

    public OtpChallengeStore(OtpOptions opt, OtpChallengeKey signer)
    {
        _opt = opt;
        _signer = signer;
    }

    /// <summary>当前挂着的挑战数（探针用来确认"消费真的把记录删掉了"）。</summary>
    public int PendingCount => _pending.Count;

    /// <summary>
    /// 签发一张挑战，返回 (token, proof, TTL 秒)。
    ///
    /// ⚠️ **无论账号是否存在、是否有链、是否被冻结，都会签出一张**。
    ///    这是防枚举的一部分：如果"不存在的账号"拿不到 token，那个端点就成了账号名录。
    ///    判断账号状态是控制器的事，本类不做任何存在性判断 —— 它也不该知道。
    ///
    /// ⚠️ **假参数也必须签**。若只在真链上返回 proof，"proof 是否为空"就成了
    ///    比 token 更好用的存在性判据 —— 那样防枚举等于白做。真/假两条路的
    ///    字段集合与取值形状必须完全一致（单测 B3 那条断言现在也覆盖 proof）。
    /// </summary>
    public (string Token, string Proof, int TtlSeconds) Issue(string username, string r, int k, int n)
    {
        Prune();

        // 24 字节 CSPRNG ⇒ Base64Url 32 字符。长度足够大到猜不中，又不至于让日志难读。
        var token = OtpChallengeKey.Base64Url(RandomNumberGenerator.GetBytes(24));
        _pending[token] = new Pending(username, DateTime.UtcNow);

        // proof 覆盖 (username, r, k, n)：客户端验过它才敢按这个 k 算格。
        var proof = _signer.Sign(username, r, k, n);
        return (token, proof, _opt.ChallengeTtlSeconds);
    }

    /// <summary>
    /// 取出并作废一张挑战，返回 (username, error)。error 为 null 表示可用。
    ///
    /// **先取出再判过期**：这一行之后这张票就不存在了，无论下面返回成功还是失败。
    /// 反过来（先校验再删除）会让"过期边界上反复提交"变成可重试的路径 ——
    /// 而链只有那么多格，任何免费重试都等于把配额放大。
    /// </summary>
    public (string? Username, string? Error) Consume(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return (null, OtpChallengeError.Invalid);

        if (!_pending.TryRemove(token.Trim(), out var item))
            return (null, OtpChallengeError.Invalid);   // 不存在 / 已被用过

        // 用 >= 而不是 >：TTL 是一个**上界**，"正好满 TTL"这一刻就该失效。
        // 顺带让"TTL=0 立即过期"成为确定可测的语义（单测靠它钉住这条分支）。
        if ((DateTime.UtcNow - item.CreatedAt).TotalSeconds >= _opt.ChallengeTtlSeconds)
            return (null, OtpChallengeError.Invalid);   // 过期

        return (item.Username, null);
    }

    /// <summary>
    /// 清理过期项；仍超上限时按签发时间淘汰最旧的。
    ///
    /// 为什么用"淘汰最旧"而不是"直接拒绝签发"：拒绝签发等于让一次洪泛把**正常用户**挡在门外
    /// （他们的挑战也签不出来）。淘汰最旧只会让被淘汰的那个人重新点一次登录，
    /// 而洪泛者本来就在反复申请 —— 代价落在发起者身上，这才是对的失败方向。
    /// </summary>
    private void Prune()
    {
        var now = DateTime.UtcNow;
        var ttl = TimeSpan.FromSeconds(_opt.ChallengeTtlSeconds);

        foreach (var (token, item) in _pending)
        {
            if (now - item.CreatedAt > ttl)
                _pending.TryRemove(token, out _);
        }

        if (_pending.Count <= MaxPending) return;

        // 多淘汰一个：本次调用紧接着还要 Issue 一条，只淘汰到"正好等于上限"会让
        // 稳态停在 MaxPending + 1（每次都是"删一个、加一个"，永远多那一条）。
        foreach (var (token, _) in _pending.OrderBy(kv => kv.Value.CreatedAt)
                     .Take(_pending.Count - MaxPending + 1))
            _pending.TryRemove(token, out _);
    }

    // Base64Url 只保留一份实现（`OtpChallengeKey.Base64Url`）：token 与 proof 都要出现在
    // JSON 里，'/' 与 '+' 都是麻烦。两处各写一遍迟早会在填充或替换顺序上分叉，
    // 而那种分叉的表现是"客户端偶尔验签失败"，极难定位。
}

/// <summary>
/// 挑战失败的原因码。只有一个取值，但**刻意不是布尔**：
/// 将来若要区分"过期"与"已使用"（例如给用户更准确的话术），不需要改签名。
/// 现在合并成一个值，是因为对外必须一致 —— 区分它们会告诉攻击者"这张票曾经有效"。
/// </summary>
public static class OtpChallengeError
{
    public const string Invalid = "OTP_CHALLENGE_INVALID";
}
