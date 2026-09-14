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
  TRANSFER_ADMIN: { label: '权限转让', tone: 'primary' },
  SEND_EMAIL_CODE: { label: '发送验证码', tone: 'info' },
  RESET_PASSWORD: { label: '重置密码', tone: 'warn' },
  // 实验二新增：审计访问相关事件
  AUDIT_QUERY: { label: '查询审计日志', tone: 'info' },
  AUDIT_VERIFY: { label: '完整性校验', tone: 'primary' },
  AUDIT_ACCESS_DENIED: { label: '越权访问被拒', tone: 'locked' },
  AUDIT_TAMPERED: { label: '检出篡改', tone: 'locked' }
}

export function actionMeta(action) {
  return ACTION_META[action] || { label: action || '未知操作', tone: 'disabled' }
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
