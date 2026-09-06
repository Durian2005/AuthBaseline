/**
 * 口令复杂度规则 —— 与后端 AuthController.IsPasswordComplex 严格一致：
 * 至少 8 位，且同时包含大写字母、小写字母、数字。
 */
export const PASSWORD_RULES = [
  { id: 'length', label: '至少 8 位字符', test: (v) => v.length >= 8 },
  { id: 'upper', label: '包含大写字母 A-Z', test: (v) => /[A-Z]/.test(v) },
  { id: 'lower', label: '包含小写字母 a-z', test: (v) => /[a-z]/.test(v) },
  { id: 'digit', label: '包含数字 0-9', test: (v) => /[0-9]/.test(v) }
]

export function evaluatePassword(value) {
  const v = value || ''
  return PASSWORD_RULES.map((rule) => ({ ...rule, passed: rule.test(v) }))
}

export function isPasswordStrong(value) {
  return PASSWORD_RULES.every((rule) => rule.test(value || ''))
}

/** 0-4 分，用于强度条 */
export function passwordScore(value) {
  const v = value || ''
  if (!v) return 0
  return PASSWORD_RULES.filter((r) => r.test(v)).length
}

export const STRENGTH_META = [
  { label: '太弱', tone: 'locked' },
  { label: '弱', tone: 'locked' },
  { label: '一般', tone: 'pending' },
  { label: '较强', tone: 'info' },
  { label: '强', tone: 'enabled' }
]
