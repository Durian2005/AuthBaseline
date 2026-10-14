using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace AuthServer.Services.Face;

/**
 * 登录第二因子的**一次性挑战**。
 *
 * 为什么它和会话票据是两套东西、且绝不能互换：
 *   - 会话票据（SessionService）代表"已经通过认证"，签出去就能访问接口；
 *   - 挑战票据只代表"口令那一因子刚过，还差一步"，**拿它做任何事都应该失败**。
 *   如果两者共用一个存储或一个校验函数，那么"用挑战当票据"或"用票据当挑战"
 *   这条路会在某次重构后悄悄打开。所以它们在类型上就是两个类，各自持有各自的存储。
 *
 * 安全性来自"随机 + 新鲜 + 一次有效"，而不是来自保密 ——
 * 动作内容必须告诉用户（不然他没法做），所以 action 明文返回，不加密。
 *
 * 三个刻意的实现细节：
 *   ① **先取出再校验**：无论后续校验成功与否，票据都不会被第二次使用。
 *      反过来（先校验后取出）会让"同一张挑战反复提交"成为可能 ——
 *      而人脸的特征提取是确定性的，重放同一张挑战等于绕开"必须当场做动作"。
 *   ② **绑定用户名**：挑战只能用于它所属的那个账号。
 *   ③ **绑定用途**：登录挑战与录入挑战形状相同，但绝不允许互换 ——
 *      否则"为录入申请的挑战"可以被丢到登录接口上当通行证使用。
 *      用途在签发时写死，调用方拿到后必须自己核对（本类只如实转述，不做策略判断）。
 */
public sealed class FaceChallengeStore
{
    /// <summary>登录第二因子。</summary>
    public const string PurposeLogin = "login";

    /// <summary>已登录状态下录入 / 更换人脸。</summary>
    public const string PurposeEnroll = "enroll";

    private sealed record Pending(string Username, string Action, string Purpose, DateTime CreatedAt);

    private readonly ConcurrentDictionary<string, Pending> _pending = new();
    private readonly FaceOptions _opt;

    /// <summary>未被消费的挑战上限，防无界增长（无登录动作时可以被反复申请）。</summary>
    private const int MaxPending = 256;

    public FaceChallengeStore(FaceOptions opt) => _opt = opt;

    /// <summary>发一张新挑战，返回 (token, action)。</summary>
    public (string Token, string Action) Issue(string username, string purpose)
    {
        Prune();

        // 动作取自密码学安全随机数：可预测的动作序列等于把活体挑战变成"等着看下一步"。
        var action = FacePose.Actions[RandomNumberGenerator.GetInt32(FacePose.Actions.Length)];
        var token = Base64Url(RandomNumberGenerator.GetBytes(24));
        _pending[token] = new Pending(username, action, purpose, DateTime.UtcNow);
        return (token, action);
    }

    /// <summary>
    /// 取出并作废一张挑战，返回 (username, action, purpose, error)；error 为 null 表示可用。
    /// error 取值与 BusinessCodes 对齐：FACE_CHALLENGE_INVALID。
    ///
    /// 用户名与用途都取自**存储内部**，而不是由调用方传进来核对 ——
    /// 调用方手里只有 token，把 username / purpose 也算成"要核对的一项"
    /// 只会凭空多出可被伪造的输入。绑定关系改由"token → 内部记录"保证：
    /// 拿不到别人的 token，就换不成别人的身份，绑定反而更硬。
    /// </summary>
    public (string? Username, string? Action, string? Purpose, string? Error) Consume(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return (null, null, null, "FACE_CHALLENGE_INVALID");

        // 先取出（pop）：这一行之后这张票就不存在了，无论下面哪一步返回失败。
        if (!_pending.TryRemove(token, out var item)) return (null, null, null, "FACE_CHALLENGE_INVALID");

        if ((DateTime.UtcNow - item.CreatedAt).TotalSeconds > _opt.ChallengeTtlSeconds)
            return (null, null, null, "FACE_CHALLENGE_INVALID");     // 过期

        return (item.Username, item.Action, item.Purpose, null);
    }

    public int PendingCount => _pending.Count;

    private void Prune()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _pending)
        {
            if ((now - kv.Value.CreatedAt).TotalSeconds > _opt.ChallengeTtlSeconds)
                _pending.TryRemove(kv.Key, out _);
        }
        if (_pending.Count < MaxPending) return;

        // 仍然超限：淘汰最旧的一张（正常使用绝不会走到这里，走到说明有人在刷挑战）。
        foreach (var kv in _pending.OrderBy(k => k.Value.CreatedAt).Take(_pending.Count - MaxPending + 1))
            _pending.TryRemove(kv.Key, out _);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
