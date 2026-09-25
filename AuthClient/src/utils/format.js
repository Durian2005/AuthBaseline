const pad = (n) => String(n).padStart(2, '0')

/** 2026-09-01 12:04:33 */
export function formatDateTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/** 12:04:33 */
export function formatClock(date) {
  const d = date instanceof Date ? date : new Date(date)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/** 2026-09-01 */
export function formatDate(date) {
  const d = date instanceof Date ? date : new Date(date)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

/** 秒 -> 3 分 05 秒 / 45 秒 */
export function formatDuration(totalSeconds) {
  const s = Math.max(0, Math.floor(totalSeconds))
  if (s < 60) return `${s} 秒`
  const m = Math.floor(s / 60)
  return `${m} 分 ${pad(s % 60)} 秒`
}

/** 距现在多久：刚刚 / 5 分钟前 / 2 小时前 / 3 天前 */
export function formatRelative(iso, nowMs = Date.now()) {
  if (!iso) return '—'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return '—'
  const diff = Math.floor((nowMs - t) / 1000)
  if (diff < 0) return '刚刚'
  if (diff < 60) return '刚刚'
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`
  return `${Math.floor(diff / 86400)} 天前`
}

export function truncate(str, len = 80) {
  const s = String(str ?? '')
  return s.length > len ? s.slice(0, len) + '…' : s
}

/** 后端 UserStatus 枚举 -> 展示元数据 */
export const STATUS_META = {
  Pending: { label: '待审核', tone: 'pending', icon: 'clock' },
  Enabled: { label: '启用', tone: 'enabled', icon: 'check-circle' },
  Locked: { label: '锁定', tone: 'locked', icon: 'lock' },
  Disabled: { label: '禁用', tone: 'disabled', icon: 'minus-circle' }
}

export function statusMeta(status) {
  return STATUS_META[status] || { label: status || '未知', tone: 'disabled', icon: 'question' }
}

export function statusLabel(status) {
  return statusMeta(status).label
}

/**
 * 后端审计日志 Action -> 中文名 + 语义色
 *
 * 登录被拆成 LOGIN_SUCCESS / LOGIN_FAILED 两个动作，审计时不必翻响应报文
 * 就能区分"登录成功"与"登录失败"；历史数据里仍存在旧的 LOGIN，一并保留映射。
 */
export const ACTION_META = {
  REGISTER: { label: '用户注册', tone: 'info' },
  LOGIN_SUCCESS: { label: '登录成功', tone: 'enabled' },
  LOGIN_FAILED: { label: '登录失败', tone: 'locked' },
  LOGIN: { label: '用户登录', tone: 'primary' },
  LOGOUT: { label: '退出登录', tone: 'disabled' },
  APPROVE: { label: '审核通过', tone: 'enabled' },
  UNLOCK: { label: '解锁账号', tone: 'warn' },
  DELETE_USER: { label: '注销账号', tone: 'locked' },
  CHANGE_PASSWORD: { label: '修改密码', tone: 'info' },
  // 口令类失败独立成动作：与"成功"在动作层面就分开，
  // 审计员一条查询即可拉出全部改密失败事件，不必再叠加 result 条件。
  CHANGE_PASSWORD_FAILED: { label: '改密失败', tone: 'locked' },
  TRANSFER_ADMIN: { label: '权限转让', tone: 'primary' },
  SEND_EMAIL_CODE: { label: '发送验证码', tone: 'info' },
  SEND_EMAIL_CODE_FAILED: { label: '发码被拒', tone: 'locked' },
  RESET_PASSWORD: { label: '重置密码', tone: 'warn' },
  RESET_PASSWORD_FAILED: { label: '重置密码失败', tone: 'locked' },
  // 实验二新增：审计访问相关事件
  AUDIT_QUERY: { label: '查询审计日志', tone: 'info' },
  AUDIT_VERIFY: { label: '完整性校验', tone: 'primary' },
  AUDIT_ACCESS_DENIED: { label: '越权访问被拒', tone: 'locked' },
  AUDIT_TAMPERED: { label: '检出篡改', tone: 'locked' },
  // 时钟异常：墙钟与本机运行时长两条时间线背离。
  // 用与"检出篡改"同一档色：它同样是"系统保障被动过"的信号，
  // 而不是某个人操作失败 —— 不宜混进普通业务失败里。
  CLOCK_ANOMALY: { label: '时钟异常', tone: 'locked' }
}

export function actionMeta(action) {
  return ACTION_META[action] || { label: action || '未知操作', tone: 'disabled' }
}

/**
 * 后端审计 reasonCode -> 中文说明。
 *
 * 为什么要在界面上翻译一遍：原因码是审计语义的键（WEAK_PASSWORD），
 * 验收演示时逐条查表解释太慢，且容易把 WRONG_OLD_PASSWORD 与
 * INVALID_CREDENTIALS 讲混 —— 而这两者的区别（"账号在、口令错" vs
 * "账号不存在"）正是口令攻击研判的关键。表格里给出中文名，
 * 悬停可看到原始码，两边都不丢。
 */
export const REASON_META = {
  // 口令 / 凭据
  WEAK_PASSWORD: '口令复杂度不达标',
  WRONG_OLD_PASSWORD: '旧口令错误（账号存在）',
  INVALID_CREDENTIALS: '用户名或口令错误',
  PASSWORD_REUSED: '新旧口令相同',
  ACCOUNT_LOCKED: '账号处于锁定中',
  PENDING_APPROVAL: '账号待审核',
  ACCOUNT_DISABLED: '账号已被禁用',
  ACCOUNT_NOT_ENABLED: '账号状态不可用',
  // 参数 / 冲突
  EMPTY_FIELDS: '必填字段为空',
  DUPLICATE_USERNAME: '用户名已存在',
  INVALID_EMAIL: '邮箱格式不合法',
  EMAIL_ALREADY_BOUND: '邮箱已被其它账号绑定',
  INVALID_PURPOSE: '验证码用途不合法',
  NOT_FOUND: '目标不存在',
  NOT_PENDING: '目标不在待审核状态',
  NOT_LOCKED: '目标未被锁定',
  ROLE_UNCHANGED: '角色未发生变化',
  // 验证码
  CODE_INVALID: '验证码无效或错误',
  CODE_EXPIRED: '验证码已过期',
  CODE_USED: '验证码已被使用',
  CODE_REQUIRED: '未填写验证码',
  CODE_TOO_MANY_ATTEMPTS: '验证码错误次数用尽',
  EMAIL_MISMATCH: '验证码与所填邮箱不一致',
  RESEND_TOO_SOON: '发码过于频繁',
  EMAIL_DISABLED: '邮件服务未启用',
  EMAIL_SEND_FAILED: '验证码发送失败',
  // 越权
  NO_TICKET: '未携带访问凭证',
  SESSION_INVALID: '凭证无效',
  SESSION_EXPIRED: '凭证已过期',
  SESSION_REVOKED: '凭证已被吊销',
  NOT_ADMIN: '权限不足',
  NOT_AUDIT_ADMIN: '越界访问审计数据（非审计管理员）',
  FORBIDDEN_ROLE: '越界提权被拒',
  FORBIDDEN_TARGET: '越界处置目标被拒',
  // 完整性
  CHAIN_BROKEN: '审计哈希链断裂',
  // 时钟背离（配合动作 CLOCK_ANOMALY）。
  // 两个方向必须分开说：前拨通常是**攻击**（想提前解开锁定），
  // 回拨通常是**事故**（主板电池耗尽、虚拟机快照回滚）。
  // 界面上若都写"时钟异常"，审计员就分不出该找人还是该修机器。
  CLOCK_ROLLED_FORWARD: '系统时钟被前拨（可能试图提前解锁）',
  CLOCK_ROLLED_BACKWARD: '系统时钟被回拨（可能是时钟故障）'
}

export function reasonLabel(code) {
  if (!code) return ''
  return REASON_META[code] || code
}

/** 审计结果 -> 中文名 + 语义色（后端 AuditResult 常量：成功 / 失败） */
export const RESULT_META = {
  成功: { label: '成功', tone: 'enabled' },
  失败: { label: '失败', tone: 'locked' }
}

export function resultMeta(result) {
  return (
    RESULT_META[result] || {
      label: result || '未知',
      tone: 'disabled'
    }
  )
}

/** 尝试把后端存的 JSON 字符串格式化展示，失败则原样返回 */
export function prettyJson(raw) {
  if (!raw) return ''
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return String(raw)
  }
}
