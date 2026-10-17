using System.Text.Json;
using AuthServer.Models;

namespace AuthServer.Services;

/// <summary>
/// 一条「职责分离绕过」的归因链。
///
/// 语义：审计管理员 <see cref="Auditor"/> 的登录口令是管理员 <see cref="Granter"/>
/// 在造号/任命时设定的；在它自己改密（<see cref="SealedAt"/>）之前，
/// 它读审计的动作可以归因到 <see cref="Granter"/>。
/// </summary>
public sealed class SodChain
{
    /// <summary>被授予审计管理员角色的账号（用户名）。</summary>
    public string Auditor { get; set; } = string.Empty;

    /// <summary>授予者（只可能是管理员 —— create-account / set-role 的门槛就是 Admin）。</summary>
    public string Granter { get; set; } = string.Empty;

    /// <summary>授予方式：create（造号时直接给角色）/ set-role（事后任命）。</summary>
    public string GrantKind { get; set; } = string.Empty;

    /// <summary>首次被授予审计角色的时刻（UTC）。</summary>
    public DateTime GrantedAt { get; set; }

    /// <summary>该账号自助改密 / 邮箱重置成功的时刻；null = 口令至今仍是授予者设定的那个。</summary>
    public DateTime? SealedAt { get; set; }

    /// <summary>该账号首次登录成功时刻（授予之后）。未登录为 null。</summary>
    public DateTime? FirstLoginAt { get; set; }

    /// <summary>封口之前（或未封口时全部）的审计读取次数 —— 这部分可归因于授予者。</summary>
    public int AttributedReads { get; set; }

    /// <summary>封口之后的审计读取次数 —— 只能归因于该账号本人。</summary>
    public int PostSealReads { get; set; }

    public DateTime? FirstAttributedReadAt { get; set; }
    public DateTime? LastAttributedReadAt { get; set; }

    /// <summary>ATTRIBUTED（可归因且未封口）/ SEALED（已封口，历史读取仍归因）/ DORMANT（造了但没读过）。</summary>
    public string Risk { get; set; } = SodAnalyzer.RiskDormant;

    /// <summary>支撑本结论的审计序号 —— 结论可以被逐条翻回原始记录核对。</summary>
    public List<long> EvidenceSeqs { get; set; } = new();
}

/// <summary>一次检测的结果。</summary>
public sealed class SodScanResult
{
    /// <summary>参与分析的审计事件总数。</summary>
    public int Scanned { get; set; }

    /// <summary>可归因且未封口（风险最高）的链数。</summary>
    public int Attributed { get; set; }

    /// <summary>已封口的链数（历史读取仍归因）。</summary>
    public int Sealed { get; set; }

    /// <summary>造出了审计管理员但从未读过审计的链数（准备行为，持续观察）。</summary>
    public int Dormant { get; set; }

    /// <summary>造出 2 条及以上此类链的管理员 —— 批量制造审计身份。</summary>
    public List<string> BatchGranters { get; set; } = new();

    public List<SodChain> Chains { get; set; } = new();
}

/// <summary>
/// 职责分离（SoD）绕过的检测层。
///
/// 为什么需要它
/// ============
/// 本系统的权限模型**允许**管理员创建「审计管理员」账号 —— 这是分工需要，
/// 不是漏洞。但同一个规则也留下了一条已知的绕过路径：
/// 管理员用自己设定的初始口令造出一个审计管理员，再以它的身份登录读审计日志。
/// 这条路径**无法在前端或接口层阻止**（阻止它就等于禁止管理员建审计账号），
/// 因此只能做到"事后可追溯"。
///
/// 但"可追溯"若不落到规则上就只是口号：原始审计里躺着 CREATE_ACCOUNT /
/// LOGIN_SUCCESS / AUDIT_QUERY 三类记录，谁也不会天天手工把它们串起来。
/// 本类把那串关联**固化成判定规则**，输出可枚举、可解释、可复算的归因链。
///
/// 判定规则（只用审计事件，不引入任何新列）
/// ======================================
///   R1 授予：成功的 CREATE_ACCOUNT 或 SET_ROLE，且角色是 AuditAdmin。
///   R2 归属：该账号此后每一次成功的 AUDIT_QUERY / AUDIT_VERIFY，
///            在它自助改密（CHANGE_PASSWORD）或用邮箱重置（RESET_PASSWORD）
///            成功之前，都计为"授予者的读取"。
///   R3 封口：一旦账号自助改密/重置成功，链从那一刻起封口；封口前的读取仍归因。
///   R4 观察：造了审计管理员却从未读过 —— 未遂的准备行为，单独列出而非忽略。
///   R5 批量：同一个管理员名下出现 2 条及以上链 ⇒ 记入 BatchGranters。
///
/// 为什么做成纯函数
/// ================
/// 不碰数据库、不读时钟、不看配置：入参就是一份审计事件列表。于是后端接口、
/// 离线复算脚本（tools/sod_trace.py）、将来 P1 的 xUnit 单测可以共用**同一套规则**，
/// 而不是各写一份然后互相印证"都对"。检测结论必须能被外部独立重算，
/// 这是"可追溯"这三个字唯一的落地方式。
///
/// 能力边界（口径别说满）
/// ====================
///   1. 只做事后归因，**不阻止**任何操作 —— 造审计账号本身是合法行为。
///   2. sidecar 与客户端同机 ⇒ 全部记录都来自 127.0.0.1 和同一个 WebView2 UA，
///      来源指纹在本项目里几乎没有区分力，判定只能靠事件序列。
///   3. 归因依赖"会话 + 口令"这一层：管理员若把口令告诉第三方、由第三方登录，
///      本层**看不出来**（那已是人的问题，不是系统能判的）。
///   4. 账号若在封口后被注销，链仍保留 —— 历史读取不会因为删号而消失。
/// </summary>
public static class SodAnalyzer
{
    /// <summary>可归因且未封口 —— 该审计管理员的读取可视为授予者的读取。</summary>
    public const string RiskAttributed = "ATTRIBUTED";

    /// <summary>已封口 —— 封口前的读取仍归因，之后的读取归该账号本人。</summary>
    public const string RiskSealed = "SEALED";

    /// <summary>造了审计管理员但从未读过审计（准备行为）。</summary>
    public const string RiskDormant = "DORMANT";

    /// <summary>一次授予事件（内部中间结构）。</summary>
    private sealed class Grant
    {
        public string Auditor = string.Empty;
        public string Granter = string.Empty;
        public string Kind = string.Empty;
        public DateTime At;
        public long Seq;
    }

    /// <summary>
    /// 分析审计事件，输出归因链。
    /// 纯函数：同一份入参永远得到同一份结论（顺序按 Seq 归一，不依赖时间戳唯一性）。
    /// </summary>
    public static SodScanResult Analyze(IReadOnlyList<AuditLog> logs)
    {
        var result = new SodScanResult { Scanned = logs.Count };
        if (logs.Count == 0) return result;

        // 序号是系统内唯一且严格递增的，时间戳可能重复（同一毫秒多条），
        // 所以先按 Seq 排序，时间只作次级键。
        var ordered = logs.OrderBy(l => l.Seq).ThenBy(l => l.Timestamp).ToList();

        /* ---------- R1 授予：谁把审计管理员这个角色给出去过 ---------- */
        var grants = new List<Grant>();
        foreach (var e in ordered)
        {
            if (e.Result != AuditResult.Success) continue;

            string? kind = e.Action switch
            {
                AuditAction.CreateAccount => "create",
                AuditAction.SetRole => "set-role",
                _ => null
            };
            if (kind == null) continue;

            // 角色优先取 request 里的 Role；老记录 / 缺字段时退到 statusAfter 的
            // "用户名·审计管理员" 形态 —— 两条路都指向"这次操作把审计角色给出去了"。
            var role = ReadStringProp(e.Request, "Role");
            var byRole = string.Equals(role, nameof(UserRole.AuditAdmin), StringComparison.OrdinalIgnoreCase);
            var byStatus = e.StatusAfter != null &&
                           e.StatusAfter.EndsWith("·" + UserRoles.Label(UserRole.AuditAdmin), StringComparison.Ordinal);
            if (!byRole && !byStatus) continue;
            if (string.IsNullOrWhiteSpace(e.Target)) continue;

            grants.Add(new Grant
            {
                Auditor = e.Target.Trim(),
                Granter = e.OperatorName,
                Kind = kind,
                At = e.Timestamp,
                Seq = e.Seq
            });
        }

        /* ---------- 每个审计管理员只保留**最早**一次授予作为观察起点 ---------- */
        var first = new Dictionary<string, Grant>(StringComparer.OrdinalIgnoreCase);
        foreach (var g in grants)
        {
            if (!first.TryGetValue(g.Auditor, out var cur) || g.Seq < cur.Seq) first[g.Auditor] = g;
        }

        /* ---------- R2/R3/R4：逐账号还原读取归属 ---------- */
        foreach (var pair in first)
        {
            var g = pair.Value;
            var chain = new SodChain
            {
                Auditor = g.Auditor,
                Granter = g.Granter,
                GrantKind = g.Kind,
                GrantedAt = g.At,
                Risk = RiskDormant
            };
            chain.EvidenceSeqs.Add(g.Seq);

            // 只看授予之后的事件：账号在被授予前不可能是审计管理员，
            // 之前的记录即使同名（改名前重名）也与本条链无关。
            var own = ordered.Where(l => l.Timestamp >= g.At && SameOperator(l, g.Auditor)).ToList();

            var login = own.FirstOrDefault(l => l.Action == AuditAction.LoginSuccess);
            chain.FirstLoginAt = login?.Timestamp;
            if (login != null) chain.EvidenceSeqs.Add(login.Seq);

            // 封口事件：本人自助改密或走邮箱重置成功。两者都意味着"口令不再由他人掌握"。
            var seal = own
                .Where(l => l.Result == AuditResult.Success &&
                            (l.Action == AuditAction.ChangePassword || l.Action == AuditAction.ResetPassword))
                .OrderBy(l => l.Seq)
                .FirstOrDefault();
            chain.SealedAt = seal?.Timestamp;
            if (seal != null) chain.EvidenceSeqs.Add(seal.Seq);

            var reads = own
                .Where(l => l.Result == AuditResult.Success &&
                            (l.Action == AuditAction.AuditQuery || l.Action == AuditAction.AuditVerify))
                .OrderBy(l => l.Seq)
                .ToList();

            var attributed = reads.Where(l => seal == null || l.Seq < seal.Seq).ToList();
            chain.AttributedReads = attributed.Count;
            chain.PostSealReads = reads.Count - attributed.Count;

            if (attributed.Count > 0)
            {
                chain.FirstAttributedReadAt = attributed.First().Timestamp;
                chain.LastAttributedReadAt = attributed.Last().Timestamp;
                chain.EvidenceSeqs.Add(attributed.First().Seq);
                if (attributed.Count > 1) chain.EvidenceSeqs.Add(attributed.Last().Seq);
            }

            chain.Risk = attributed.Count == 0
                ? RiskDormant
                : (seal == null ? RiskAttributed : RiskSealed);

            result.Chains.Add(chain);
        }

        /* ---------- R5 批量：同一管理员名下多条链 ---------- */
        result.BatchGranters = result.Chains
            .GroupBy(c => c.Granter, StringComparer.OrdinalIgnoreCase)
            .Where(grp => grp.Count() >= 2)
            .Select(grp => grp.Key)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();

        result.Attributed = result.Chains.Count(c => c.Risk == RiskAttributed);
        result.Sealed = result.Chains.Count(c => c.Risk == RiskSealed);
        result.Dormant = result.Chains.Count(c => c.Risk == RiskDormant);

        // 排序：可归因且未封口的排最前；同风险内读取次数多的在前；再按授予时间。
        result.Chains = result.Chains
            .OrderBy(c => c.Risk switch
            {
                RiskAttributed => 0,
                RiskSealed => 1,
                _ => 2
            })
            .ThenByDescending(c => c.AttributedReads)
            .ThenBy(c => c.GrantedAt)
            .ToList();

        return result;
    }

    /// <summary>操作者是否指向同一个账号。用户名是系统内唯一键，Id 仅作补充。</summary>
    private static bool SameOperator(AuditLog log, string username) =>
        string.Equals(log.OperatorName, username, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// 从 request 的 JSON 袋里取字符串字段。
    ///
    /// 注意：审计的扩展信息只能塞进 request / response 这两个**字符串**列
    /// （哈希链的输入字段是固定的，不能加列），所以这里必须防解析失败：
    /// 老记录可能是空串，也可能是别种结构 —— 解析不出来就当"没有"，绝不让
    /// 一条脏数据把整次检测打断。
    /// </summary>
    private static string? ReadStringProp(string? json, string name)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (!string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) continue;
                return p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.ToString();
            }
        }
        catch (JsonException)
        {
            // 忽略：见上面的说明。
        }
        return null;
    }
}
