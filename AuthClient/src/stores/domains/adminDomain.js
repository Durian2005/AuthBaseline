import { computed, ref } from 'vue'
import { api } from '../../api/client'
import { createPoller } from '../../composables/poller'
import { ROLES } from '../roles'

/**
 * 用户管理数据的轮询间隔。
 *
 * 注意它现在**只拉用户列表**，不再连带拉审计数据 ——
 * 角色分离后管理员无权查看审计，"顺手刷新一下日志"会直接撞 403 并
 * 在审计链里留下大量无意义的拒绝记录。审计数据由独立的轮询负责，
 * 且只在审计管理员登录时才启动。
 */
const ADMIN_REFRESH_MS = 20000

/**
 * 用户管理域：用户清单、沉睡账号治理、审核/解锁/冻结/注销/建号/改角色。
 *
 * 从 session store 里拆出来的判据 —— 这一域的守卫**统一是
 * `CanManageUsers`（Admin / UserAdmin）**，唯一例外是"建号 / 改角色"
 * 两级收窄到 Admin（后端为 RequireAdminAsync，前端由 isRoleAdmin 控制入口）。
 *
 * ⚠️ 与 auditDomain 一样，本模块只返回一组 ref / computed / 函数，
 * 由 `stores/session.js` 组装成 store 的公开面，对外契约不变。
 *
 * @param {object} core 共享上下文：{ currentUser, persist, isAdmin, markOnline, fail }
 */
export function useAdminDomain(core) {
  const { currentUser, persist, isAdmin, markOnline, fail } = core

  /* ---- state ---- */
  const users = ref([])
  const loadingUsers = ref(false)

  /**
   * 沉睡账号治理数据：`{ thresholdDays, items, protectedItems, frozenItems }`。
   * 保持 null 表示"尚未加载过"——界面据此区分"没拉过"与"拉过但结果为空"。
   */
  const dormant = ref(null)

  /* ---- getters ---- */
  const pendingUsers = computed(() => users.value.filter((u) => u.status === 'Pending'))
  const lockedUsers = computed(() => users.value.filter((u) => u.status === 'Locked'))
  const enabledUsers = computed(() => users.value.filter((u) => u.status === 'Enabled'))
  /** 具备用户管理能力的账号（Admin / UserAdmin） */
  const adminUsers = computed(() => users.value.filter((u) => u.isAdmin))
  /** 审计管理员账号 */
  const auditUsers = computed(() => users.value.filter((u) => u.role === ROLES.AUDIT_ADMIN))

  /** 当前生效的沉睡阈值（天）。未加载时为 undefined，由后端下发 */
  const dormantThresholdDays = computed(() => dormant.value?.thresholdDays ?? null)
  /** 可被冻结的沉睡候选 */
  const dormantCandidates = computed(() => dormant.value?.items ?? [])
  /** 达到阈值但受角色保护的账号（管理类，只提示） */
  const dormantProtected = computed(() => dormant.value?.protectedItems ?? [])
  /** 当前处于冻结态的账号（可解除） */
  const frozenAccounts = computed(() => dormant.value?.frozenItems ?? [])

  /* ---- actions ---- */

  async function refreshUsers() {
    if (!isAdmin.value) return
    loadingUsers.value = true
    try {
      const res = await api.getUsers()
      users.value = res.data ?? []
      markOnline()
      syncSelfFromUsers()
    } catch (err) {
      throw fail(err, '加载用户列表失败')
    } finally {
      loadingUsers.value = false
    }
  }

  /**
   * 刷新沉睡账号清单（只读）。
   *
   * 后端该接口**不写审计**，因此可以放心地随用户列表轮询一起跑 ——
   * 若它会留痕，每隔 20 秒一次的自动刷新就会把审计链刷满正常管理记录。
   */
  async function refreshDormant({ silent = false } = {}) {
    if (!isAdmin.value) return
    try {
      const res = await api.getDormantUsers()
      dormant.value = res.data ?? {
        thresholdDays: null,
        items: [],
        protectedItems: [],
        frozenItems: []
      }
    } catch (err) {
      if (silent) return
      throw fail(err, '加载沉睡账号失败')
    }
  }

  /**
   * 刷新用户管理数据（**用户列表 + 沉睡清单**）。
   *
   * 角色分离后这里刻意不再连带拉取审计数据：
   * 管理员没有审计权限，顺手刷一下日志只会撞 403 并污染审计链。
   * 审计数据由 auditDomain.refreshAuditData 单独负责，只在审计管理员登录时调用。
   */
  async function refreshAdminData() {
    if (!isAdmin.value) return
    // 沉睡清单失败不该让整个用户数据刷新失败（它只是增值信息），
    // 所以用 silent 吞掉错误、由用户列表的成功决定整体成败。
    await Promise.allSettled([refreshUsers(), refreshDormant({ silent: true })])
  }

  async function approve(username) {
    const res = await api.approve(username)
    markOnline()
    await refreshUsers()
    return res
  }

  async function unlock(username) {
    const res = await api.unlock(username)
    markOnline()
    await refreshUsers()
    // 解冻可能把某个账号从"冻结"移回正常，沉睡清单要同步刷新
    await refreshDormant({ silent: true })
    return res
  }

  /**
   * 冻结账号（沉睡账号治理）。
   *
   * 后端会同时：置 Disabled + 吊销该账号全部票据 + 写审计 DORMANT_FREEZE。
   * 冻结是可逆的，但仍需二次确认 —— 被冻结的人会立刻登不进来。
   */
  async function freezeUser(username, reason = '') {
    const res = await api.freezeUser(username, reason)
    markOnline()
    await refreshUsers()
    await refreshDormant({ silent: true })
    return res
  }

  async function deleteUser(username) {
    const res = await api.deleteUser(username)
    markOnline()
    await refreshUsers()
    return res
  }

  /**
   * 管理员创建账号（普通用户 / 用户管理员 / 审计管理员）。
   *
   * 与注册不同：**不发验证码**，邮箱是可选参数（留空即只凭口令登录，
   * 该账号用不了「忘记密码」）。但需要操作者（管理员）本人的登录口令
   * 做二次确认 —— 后端在建号之前会再验一次，三种角色一视同仁。
   */
  async function createAccount(username, password, roleValue, operatorPassword, email) {
    const res = await api.createAccount(username, password, roleValue, operatorPassword, email)
    markOnline()
    await refreshUsers()
    return res
  }

  /**
   * 变更他人角色 —— "指定某位管理员为审计管理员"走这里。
   *
   * 后端会吊销目标账号的全部票据，因此对方需要重新登录；
   * 操作者自己的会话不受影响，刷新列表即可。
   */
  async function setRole(username, roleValue, operatorPassword) {
    const res = await api.setRole(username, roleValue, operatorPassword)
    markOnline()
    // 如果被改的是自己（后端已禁止，这里只是兜底），同步一下本地角色
    if (username === currentUser.value?.username) {
      currentUser.value = { ...currentUser.value, role: roleValue }
      persist()
    }
    await refreshUsers()
    return res
  }

  /** 用户列表里包含自己时，同步回本地会话状态（例如角色被别处调整） */
  function syncSelfFromUsers() {
    if (!currentUser.value) return
    const me = users.value.find((u) => u.username === currentUser.value.username)
    if (!me) return
    currentUser.value = {
      username: me.username,
      status: me.status,
      role: me.role ?? currentUser.value.role,
      lockoutEnd: me.lockoutEnd ?? null
    }
    persist()
  }

  /** 登出时清空本域状态。 */
  function reset() {
    users.value = []
    dormant.value = null
  }

  /* ---- 后台轮询 ---- */

  /**
   * 用户数据轮询（Admin / UserAdmin）。
   * 只拉用户列表 —— 管理员没有审计权限，连带刷新日志会撞 403。
   */
  const adminPoller = createPoller({
    name: 'admin',
    guard: () => isAdmin.value,
    task: refreshAdminData,
    intervalMs: ADMIN_REFRESH_MS,
  })

  return {
    // state
    users,
    loadingUsers,
    dormant,
    // getters
    pendingUsers,
    lockedUsers,
    enabledUsers,
    adminUsers,
    auditUsers,
    dormantThresholdDays,
    dormantCandidates,
    dormantProtected,
    frozenAccounts,
    // actions
    refreshUsers,
    refreshDormant,
    refreshAdminData,
    approve,
    unlock,
    freezeUser,
    deleteUser,
    createAccount,
    setRole,
    reset,
    // 轮询开关
    startAdminPolling: () => adminPoller.start(),
    stopAdminPolling: () => adminPoller.stop()
  }
}
