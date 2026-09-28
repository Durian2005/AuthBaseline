using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services;

/// <summary>
/// 会话票据的存储形态转换：**明文 → 无盐 SHA-256（Base64Url）**。
///
/// 为什么要做这一步
///   票据是服务端签发的凭证。改造前库里存的是**票据本体**，
///   于是"能读到数据库"与"能冒用任意登录态"变成同一件事 —— 一次读库即可直接带走会话，
///   连破解这一步都不需要。而库里存哈希之后，读库者拿到的东西无法反过来当凭证使用。
///
/// 为什么**刻意不加盐**（与口令的处理相反）
///   口令是低熵、可猜、可能跨用户重复的，所以必须「慢哈希 + 每记录随机盐」；
///   票据是 32 字节密码学随机数（256 位熵），盐要防的两件事在这里都不成立：
///     · 预计算/彩虹表 —— 对 2^256 的取值空间无意义；
///     · 相同输入跨记录比对 —— 随机票据本就不会重复。
///   而一旦加盐，验证时就必须"逐条取盐再算"，O(1) 索引查询会退化成全表慢哈希。
///   这是**刻意的取舍不对称**，也是本仓库里"哈希什么时候该加盐"的一个对照样本。
///
/// 为什么不加 pepper / 不用 HMAC
///   票据本来就必须随请求明文传回服务端（客户端持有它），它不是一个"只存不传"的秘密；
///   引入服务端密钥只会带来密钥丢失即全员掉线的风险，换不来实质收益。
/// </summary>
public static class TicketHasher
{
    /// <summary>把明文票据折算成入库形态。同一输入恒定得到同一输出，因此仍可走索引等值查询。</summary>
    public static string Hash(string ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(ticket));

        // 与票据本身同样的 URL 安全字符集，便于放进头部、URL 与日志而不产生转义问题
        return Convert.ToBase64String(digest)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
