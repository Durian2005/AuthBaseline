/**
 * 角色常量。与后端 UserRole 枚举一一对应。
 *
 * User       普通用户
 * Admin      管理员：管用户 + 任命角色，**看不到审计日志**
 * UserAdmin  用户管理员：管用户，不能任命角色
 * AuditAdmin 审计管理员：**只看审计日志**，不能进行任何用户管理
 *
 * 为什么单独成一个文件：
 *   角色判定被两处同时依赖 —— session（会话状态、菜单开关）与 adminDomain
 *   （用户列表分组）。放在任何一侧都会让另一侧产生反向依赖，
 *   而"谁依赖谁"一旦成环，正是这类 900 行 store 难以维护的起点。
 */
export const ROLES = {
  USER: 'User',
  ADMIN: 'Admin',
  USER_ADMIN: 'UserAdmin',
  AUDIT_ADMIN: 'AuditAdmin'
}

/** 角色 → 徽章文案 */
export const ROLE_LABELS = {
  [ROLES.USER]: '普通用户',
  [ROLES.ADMIN]: '管理员',
  [ROLES.USER_ADMIN]: '用户管理员',
  [ROLES.AUDIT_ADMIN]: '审计管理员'
}
