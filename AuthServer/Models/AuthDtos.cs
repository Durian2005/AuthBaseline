namespace AuthServer.Models;

public class RegisterRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;

    /// <summary>注册时绑定的邮箱（邮件功能启用时必填）。</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>发送到上述邮箱的 6 位验证码，用于证明邮箱归属。</summary>
    public string Code { get; set; } = string.Empty;
}

/// <summary>
/// 发送邮箱验证码请求。
/// Purpose 必须显式声明用途（REGISTER / RESET），
/// 使注册码无法用于重置密码、重置码也无法用于注册。
/// </summary>
public class SendEmailCodeRequest
{
    public string Purpose { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

/// <summary>
/// 忘记密码：用户名 + 邮箱 → 验证码 → 直接设置新密码。
/// 刻意不做"验证码直接登录"：系统内不存在不凭口令即可建立会话的路径。
/// </summary>
public class ResetPasswordRequest
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;

    // P8：这里原本是 `Password`（口令明文，旧路径唯一的第一因子），已删除。
    // 删除它才让「口令明文不上网」在**协议层面**成立 —— 之前是客户端自觉不传，
    // 现在是服务端根本没有地方收。

    /// <summary>
    /// 哈希链的一格（<c>x_k</c>，Base64）—— **P8 起它是唯一的第一因子**。
    ///
    /// 口令只在本机参与 PBKDF2 → H^k 派生，出门的只有这一格。
    ///
    /// ⚠️ 反序列化保持宽松：旧客户端若还带着 `password` 字段，会被静默忽略，
    ///    登录失败于"没带 otpCode"这条 400 上 —— 报错指向真正的原因，而不是"未知字段"。
    /// </summary>
    public string? OtpCode { get; set; }

    /// <summary>
    /// 挑战端点签发的一次性凭据。链值路径**必须**带上：
    /// 它绑定用户名与 TTL，使"十分钟前算好的格"和"替别人提交"都失效。
    /// </summary>
    public string? ChallengeToken { get; set; }

    /// <summary>
    /// 续期用的新链（只在服务端判定"该续期"时才需要）。见 <see cref="OtpNextChain"/>。
    ///
    /// 服务端**无法验证**这条新链算不算得出格（那需要口令），只校验形状；
    /// 真正保证"换上去的新链可用"的，是客户端算它的那一刻手里有正确的口令。
    /// </summary>
    public OtpNextChain? NextChain { get; set; }
}

public class ChangePasswordRequest
{
    public string Username { get; set; } = string.Empty;

    // P8：这里原本是 `OldPassword`（旧口令明文），已删除。
    // 旧凭据改为链值 `OldOtpCode`，见下。

    /// <summary>
    /// 旧凭据的链值（<c>x_k</c>，Base64）。**P8 起是唯一的身份证明**：
    /// 本端点匿名，只能靠"算得出一格仍然有效的链值"证明你是本人。
    /// </summary>
    public string? OldOtpCode { get; set; }

    /// <summary>
    /// 改密用的挑战凭据（`POST /api/auth/login/challenge` 签发）。
    ///
    /// 与登录一样必须带：它绑定用户名与 TTL，使"十分钟前算好的格"和"替别人改密"都失效。
    /// 本端点**匿名**（没有票据可依），所以这张挑战是"这组参数是此刻为你签发的"唯一凭据。
    /// </summary>
    public string? OldChallengeToken { get; set; }

    public string NewPassword { get; set; } = string.Empty;
}

public class ApproveRequest
{
    public string Username { get; set; } = string.Empty;
    public string AdminUsername { get; set; } = string.Empty;
}

public class UnlockRequest
{
    public string Username { get; set; } = string.Empty;
    public string AdminUsername { get; set; } = string.Empty;
}

public class DeleteUserRequest
{
    public string Username { get; set; } = string.Empty;
    public string AdminUsername { get; set; } = string.Empty;
}

/// <summary>
/// 沉睡（僵尸）账号治理：冻结未被使用的账号。
///
/// 语义与 <see cref="DeleteUserRequest"/> 有本质区别 ——
/// 注销是**不可逆**的，冻结只是"暂时不让登录"，随时可解冻。
/// 两者分成两个接口，是为了让"点了注销"这个动作在代码层面
/// 就不可能被误当成"治理沉睡账号"来执行。
/// </summary>
public class FreezeUserRequest
{
    public string Username { get; set; } = string.Empty;
    public string AdminUsername { get; set; } = string.Empty;

    /// <summary>
    /// 冻结原因（可空）。治理动作应当能回答"为什么把他关了"，
    /// 留一个自由填写的位置比只记一个布尔值更有用。
    /// </summary>
    public string Reason { get; set; } = string.Empty;
}

/// <summary>
/// 管理员创建账号（普通用户 / 用户管理员 / 审计管理员）。
///
/// 与自助注册的区别：**不发验证码、建号即启用**。
/// 邮箱是**可选**的：留空即只凭口令登录（代价是无法自助找回密码）；
/// 填写则登记为已验证 —— 管理员是可信主体，不额外发码（理由见 User.EmailVerified）。
/// 因此这个接口本身就是一条高权限通道，必须由管理员发起，
/// 且要求二次校验操作者口令 —— 仅凭会话不足以证明是本人操作。
/// </summary>
public class CreateAccountRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// 目标角色：User（普通用户）/ UserAdmin（用户管理员）/ AuditAdmin（审计管理员）。
    /// 刻意不接受 Admin —— 不允许管理员自我复制。
    /// </summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>
    /// 可选绑定邮箱。留空 ⇒ 账号只凭口令登录，且无法自助找回密码。
    /// 填写 ⇒ 与自助注册用同一套格式校验与唯一性校验，但**不发验证码**，
    /// 直接置 EmailVerified=true（管理员代填视为已验证）；随后即可用「忘记密码」。
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// 一次性确认凭据（`POST /api/auth/reconfirm` 的产物）。
    ///
    /// **P8 起是唯一的确认方式**：没有它这个请求一律 401（`OTP_CONFIRM_REQUIRED`），
    /// 客户端据此去 `POST /api/auth/reconfirm` 换一张再来 —— 这正是原来"再输一次口令"
    /// 那一步的等价物，只是这一回口令没有离开过本机。
    ///
    /// 它只能用于**签发时绑定的那个用途与那个目标**，用一次即作废，
    /// 有效期见 <see cref="AuthServer.Services.Otp.OtpOptions.ConfirmTtlSeconds"/>。
    /// </summary>
    public string? ConfirmToken { get; set; }
}

/// <summary>
/// 变更他人角色 —— 这是"指定某位管理员为审计管理员"的落地接口。
/// 同样需要操作者二次口令：角色任免是系统内权限最高的操作。
/// </summary>
public class SetRoleRequest
{
    public string Username { get; set; } = string.Empty;

    /// <summary>目标角色：User / UserAdmin / AuditAdmin（不接受 Admin）。</summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>
    /// 一次性确认凭据（`POST /api/auth/reconfirm` 的产物）。
    ///
    /// **P8 起是唯一的确认方式**：没有它这个请求一律 401（`OTP_CONFIRM_REQUIRED`），
    /// 客户端据此去 `POST /api/auth/reconfirm` 换一张再来 —— 这正是原来"再输一次口令"
    /// 那一步的等价物，只是这一回口令没有离开过本机。
    ///
    /// 它只能用于**签发时绑定的那个用途与那个目标**，用一次即作废，
    /// 有效期见 <see cref="AuthServer.Services.Otp.OtpOptions.ConfirmTtlSeconds"/>。
    /// </summary>
    public string? ConfirmToken { get; set; }
}

/// <summary>
/// 批量处置：对多个账号执行**同一个**动作。
///
/// 为什么是"一个动作 × 多个目标"而不是"多个字段一起改"：
///   六种动作的前置校验、审计码、副作用（吊销票据 / 清两套人脸模板 / 改状态）
///   全不相同。把它们揉进一个通用的"批量编辑"入口，等于把六套授权规则
///   塞进一个函数，判错一次就是越权。所以这里只做**分派**，业务仍然走单条入口。
///
/// 执行语义（已定，不要改）：
///   · **逐条执行、逐条留痕**。无权处置的目标（含操作者自己）被拒、其余照做，
///     不做整批回滚 —— 批量最常见的失败原因是"选多了"，回滚只会让人反复试，
///     而且事后答不出"到底哪些没做"。
///   · 每个目标写一条与单条接口**逐字一致**的审计，
///     因此「谁被处置了」在哈希链里仍可独立还原。
/// </summary>
public class BatchRequest
{
    /// <summary>
    /// 动作名，取值见 <c>UserAdminController.BatchAction</c>：
    /// approve / unlock / freeze / delete / reset-face / set-role。
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>目标账号用户名清单。去空白、去重、转小写后执行。</summary>
    public List<string> Usernames { get; set; } = new();

    /// <summary>冻结原因（仅 freeze 使用，可空）。</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>目标角色（仅 set-role 使用）。</summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>
    /// 逐目标的确认凭据（仅 set-role 使用）：`用户名 → reconfirm 换来的 token`。
    ///
    /// 为什么不是"一张票放行整批"：确认凭据在签发时就绑定了**用途 + 目标**，
    /// 那是它存在的全部意义。拿一张绑定 alice 的票去改 bob 的角色，
    /// 等于把"确认"退化成"点过一次按钮就可以授权任意多次"。
    /// 所以批量里每个目标各带一张 —— 服务端这边仍然是"循环调用单条 SetRole"，
    /// 不新增第二条业务路径；缺票的那个目标回 401，其余照做（部分成功是批量的常态）。
    /// </summary>
    public Dictionary<string, string>? ConfirmTokens { get; set; }
}

/// <summary>批量里**单个目标**的结果。码与话术取自该目标实际走的那条单条接口。</summary>
public class BatchItemResult
{
    public string Username { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string Code { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

/// <summary>批量处置的汇总。前端据此显示"成功 N / 未处理 M"并可展开看每条原因。</summary>
public class BatchResult
{
    public int Total { get; set; }
    public int Ok { get; set; }
    public int Failed { get; set; }
    public List<BatchItemResult> Items { get; set; } = new();
}

public class LoginResult
{
    public string Username { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;

    /// <summary>角色标识：User / Admin / UserAdmin / AuditAdmin。</summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>角色中文显示名。</summary>
    public string RoleLabel { get; set; } = string.Empty;

    /// <summary>
    /// 是否具备用户管理能力（Admin / UserAdmin）。审计管理员为 false。
    /// 由 Role 派生，保留是为了兼容既有前端字段。
    /// </summary>
    public bool IsAdmin { get; set; }

    /// <summary>
    /// 服务端签发的会话票据。后续管理员接口需通过
    /// `Authorization: Bearer &lt;ticket&gt;` 携带该值。
    ///
    /// 注意：这是凭证，前端只应保存在本地会话存储中，
    /// 绝不能写进审计日志或任何可被他人读取的位置。
    /// </summary>
    public string Ticket { get; set; } = string.Empty;

    /// <summary>票据过期时刻（滑动续期的当前值）。</summary>
    public DateTime ExpiresAt { get; set; }
}
