import { ROLE_LABELS } from '../stores/roles'

/**
 * 用户列表相关的展示文案。
 *
 * 为什么单独成文件：`UsersView.vue` 的三张表格与「冻结账号」弹窗都要显示
 * "沉睡多久 / 是什么角色"。原先这些函数长在视图里，拆出弹窗后若各自复制一份，
 * 就会出现两份措辞可能走样的实现（这类文案一旦不一致，验收时最容易被追问）。
 */

/** 角色标识 → 中文标签。与 store 的 ROLE_LABELS 同源，避免两处各写一张表。 */
export function roleLabelOf(user) {
  return ROLE_LABELS[user?.role] ?? '普通用户'
}

/** 未登录天数的可读描述 */
export function dormantText(user) {
  if (!user) return ''
  if (!user.lastLoginAt) return `注册后从未登录 · ${user.dormantDays} 天`
  return `${user.dormantDays} 天未登录`
}
