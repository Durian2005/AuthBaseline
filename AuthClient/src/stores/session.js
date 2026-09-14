import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { ApiError, api } from '../api/client'
import { now } from '../composables/clock'
import { useToastStore } from './toast'

const STORAGE_KEY = 'auth.currentUser'
const ADMIN_REFRESH_MS = 20000

function loadPersisted() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    if (!parsed?.username) return null
    return {
      username: parsed.username,
      status: parsed.status ?? 'Enabled',
      isAdmin: !!parsed.isAdmin,
      lockoutEnd: parsed.lockoutEnd ?? null
    }
  } catch {
    return null
  }
}

export const useSessionStore = defineStore('session', () => {
  const toast = useToastStore()

  // ---------------- state ----------------
  const currentUser = ref(loadPersisted())
  const users = ref([])
  const logs = ref([])

  const submitting = ref(false)
  /** 验证码发送中的独立状态：不能与 submitting 混用，否则点"获取验证码"会连带锁住提交按钮 */
  const sendingCode = ref(false)
  const loadingUsers = ref(false)
  const loadingLogs = ref(false)

  /** 'unknown' | 'online' | 'offline' */
  const connection = ref('unknown')
  const lastSyncAt = ref(null)

  let adminTimer = null

  // ---------------- getters ----------------
  const isLoggedIn = computed(() => !!currentUser.value)
  const isAdmin = computed(() => !!currentUser.value?.isAdmin)
  const status = computed(() => currentUser.value?.status ?? null)
  const isLocked = computed(() => currentUser.value?.status === 'Locked')

  /** 锁定剩余秒数，随全局心跳每秒重算 */
  const lockRemaining = computed(() => {
    const u = currentUser.value
    if (!u?.lockoutEnd) return 0
    const end = new Date(u.lockoutEnd).getTime()
    if (Number.isNaN(end)) return 0
    return Math.max(0, Math.ceil((end - now.value) / 1000))
  })

  const pendingUsers = computed(() => users.value.filter((u) => u.status === 'Pending'))
  const lockedUsers = computed(() => users.value.filter((u) => u.status === 'Locked'))
  const enabledUsers = computed(() => users.value.filter((u) => u.status === 'Enabled'))
  const adminUsers = computed(() => users.value.filter((u) => u.isAdmin))

  const stats = computed(() => ({
    total: users.value.length,
    pending: pendingUsers.value.length,
    locked: lockedUsers.value.length,
    enabled: enabledUsers.value.length,
    logs: logs.value.length
  }))

  // ---------------- persistence ----------------
  function persist() {
    try {
      if (currentUser.value) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(currentUser.value))
      } else {
        localStorage.removeItem(STORAGE_KEY)
      }
    } catch {
      /* 隐私模式下 localStorage 可能不可写，忽略即可 */
    }
  }

  function markOnline() {
    connection.value = 'online'
    lastSyncAt.value = new Date().toISOString()
  }

  function markOffline() {
    connection.value = 'offline'
  }

  /** 统一错误出口：识别网络故障并给出可操作提示 */
  function fail(err, fallback = '操作失败') {
    if (err instanceof ApiError) {
      if (err.kind === 'network') markOffline()
      return err
    }
    return new ApiError(err?.message || fallback, { kind: 'unknown' })
  }

  // ---------------- actions ----------------
  async function register(username, password, email, code) {
    submitting.value = true
    try {
      const res = await api.register(username, password, email, code)
      markOnline()
      return res
    } catch (err) {
      throw fail(err, '注册失败')
    } finally {
      submitting.value = false
    }
  }

  /**
   * 发送邮箱验证码。
   * purpose: 'REGISTER'（注册绑定邮箱）| 'RESET'（忘记密码）
   * 成功时返回后端给的 maskedEmail / expiresIn / resendAfter，界面据此显示倒计时。
   */
  async function sendEmailCode(purpose, username, email) {
    sendingCode.value = true
    try {
      const res = await api.sendEmailCode(purpose, username, email)
      markOnline()
      return res
    } catch (err) {
      throw fail(err, '验证码发送失败')
    } finally {
      sendingCode.value = false
    }
  }

  /**
   * 忘记密码：用户名 + 邮箱 + 验证码 → 直接设置新密码。
   * 刻意不建立任何本地会话 —— 重置成功后必须用新口令重新登录。
   */
  async function resetPassword(username, email, code, newPassword) {
    submitting.value = true
    try {
      const res = await api.resetPassword(username, email, code, newPassword)
      markOnline()
      return res
    } catch (err) {
      throw fail(err, '重置密码失败')
    } finally {
      submitting.value = false
    }
  }

  async function login(username, password) {
    submitting.value = true
    try {
      const res = await api.login(username, password)
      currentUser.value = {
        username: res.data.username,
        status: res.data.status,
        isAdmin: res.data.isAdmin,
        lockoutEnd: null
      }
      persist()
      markOnline()
      startAdminPolling()
      return res
    } catch (err) {
      // 注意：登录失败绝不写入 currentUser。
      // 认证失败却建立本地会话会让未通过校验的用户进入主界面。
      // 锁定信息通过 ApiError.data（lockoutEnd / remainingSeconds）交给界面展示倒计时。
      throw fail(err, '登录失败')
    } finally {
      submitting.value = false
    }
  }

  function logout({ silent = false } = {}) {
    stopAdminPolling()
    currentUser.value = null
    users.value = []
    logs.value = []
    persist()
    if (!silent) toast.info('已安全退出')
  }

  async function changePassword(oldPassword, newPassword) {
    submitting.value = true
    try {
      const res = await api.changePassword(currentUser.value.username, oldPassword, newPassword)
      markOnline()
      return res
    } catch (err) {
      throw fail(err, '修改密码失败')
    } finally {
      submitting.value = false
    }
  }

  async function refreshUsers() {
    if (!currentUser.value?.isAdmin) return
    loadingUsers.value = true
    try {
      const res = await api.getUsers(currentUser.value.username)
      users.value = res.data ?? []
      markOnline()
      syncSelfFromUsers()
    } catch (err) {
      throw fail(err, '加载用户列表失败')
    } finally {
      loadingUsers.value = false
    }
  }

  async function refreshLogs() {
    if (!currentUser.value?.isAdmin) return
    loadingLogs.value = true
    try {
      const res = await api.getLogs(currentUser.value.username)
      logs.value = res.data ?? []
      markOnline()
    } catch (err) {
      throw fail(err, '加载审计日志失败')
    } finally {
      loadingLogs.value = false
    }
  }

  async function refreshAdminData() {
    if (!currentUser.value?.isAdmin) return
    await Promise.allSettled([refreshUsers(), refreshLogs()])
  }

  async function approve(username) {
    const res = await api.approve(username, currentUser.value.username)
    markOnline()
    await refreshUsers()
    await refreshLogs()
    return res
  }

  async function unlock(username) {
    const res = await api.unlock(username, currentUser.value.username)
    markOnline()
    await refreshUsers()
    await refreshLogs()
    return res
  }

  async function deleteUser(username) {
    const res = await api.deleteUser(username, currentUser.value.username)
    markOnline()
    await refreshUsers()
    await refreshLogs()
    return res
  }

  /**
   * 管理员权限转让。
   *
   * 转让成功后当前账号不再是管理员：先刷新用户列表，再由 syncSelfFromUsers
   * 把本地会话同步为普通用户（App.vue 会自动离开管理员页面）。
   */
  async function transferAdmin(targetUsername, password) {
    const res = await api.transferAdmin(targetUsername, currentUser.value.username, password)
    markOnline()
    await refreshUsers()
    await refreshLogs()
    syncSelfFromUsers()
    // 已失去管理员身份，停止后台轮询，避免继续请求管理员接口
    if (!currentUser.value?.isAdmin) stopAdminPolling()
    return res
  }

  /** 管理员列表里包含自己时，同步回本地会话状态（例如自己被别处锁定） */
  function syncSelfFromUsers() {
    if (!currentUser.value) return
    const me = users.value.find((u) => u.username === currentUser.value.username)
    if (!me) return
    currentUser.value = {
      username: me.username,
      status: me.status,
      isAdmin: me.isAdmin,
      lockoutEnd: me.lockoutEnd ?? null
    }
    persist()
  }

  // ---------------- 后台轮询 ----------------
  function startAdminPolling() {
    stopAdminPolling()
    if (!currentUser.value?.isAdmin) return
    adminTimer = setInterval(() => {
      if (document.visibilityState === 'visible') refreshAdminData()
    }, ADMIN_REFRESH_MS)
  }

  function stopAdminPolling() {
    if (adminTimer) {
      clearInterval(adminTimer)
      adminTimer = null
    }
  }

  // 锁定到期：提示用户重新登录（与后端自动解锁逻辑保持一致）
  watch(lockRemaining, (v) => {
    if (v === 0 && currentUser.value?.status === 'Locked' && currentUser.value?.lockoutEnd) {
      currentUser.value.status = 'Enabled'
      currentUser.value.lockoutEnd = null
      persist()
      toast.warning('锁定时间已到，请重新登录')
      setTimeout(() => logout({ silent: true }), 2200)
    }
  })

  // 恢复会话时，管理员自动拉一次数据
  if (currentUser.value?.isAdmin) {
    startAdminPolling()
    refreshAdminData()
  }

  return {
    // state
    currentUser,
    users,
    logs,
    submitting,
    sendingCode,
    loadingUsers,
    loadingLogs,
    connection,
    lastSyncAt,
    // getters
    isLoggedIn,
    isAdmin,
    status,
    isLocked,
    lockRemaining,
    pendingUsers,
    lockedUsers,
    enabledUsers,
    adminUsers,
    stats,
    // actions
    register,
    sendEmailCode,
    resetPassword,
    login,
    logout,
    changePassword,
    refreshUsers,
    refreshLogs,
    refreshAdminData,
    approve,
    unlock,
    deleteUser,
    transferAdmin,
    startAdminPolling,
    stopAdminPolling
  }
})
