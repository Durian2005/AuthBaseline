import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { ApiError, api, getTicket, setTicket, transportInfo } from '../api/client'
import { now } from '../composables/clock'
import { useToastStore } from './toast'
import { ROLES, ROLE_LABELS } from './roles'
import { useAdminDomain } from './domains/adminDomain'
import { useAuditDomain } from './domains/auditDomain'

// 角色常量对外仍从本模块导出（历史引用点不变），定义在 ./roles.js。
export { ROLES, ROLE_LABELS }

const STORAGE_KEY = 'auth.currentUser'

function loadPersisted() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    if (!parsed?.username) return null
    return {
      username: parsed.username,
      status: parsed.status ?? 'Enabled',
      // 老版本缓存里没有 role，只有 isAdmin —— 用它兜底推断，
      // 避免升级后用户刷新页面时角色短暂变成"普通用户"。
      role: parsed.role ?? (parsed.isAdmin ? ROLES.ADMIN : ROLES.USER),
      lockoutEnd: parsed.lockoutEnd ?? null
    }
  } catch {
    return null
  }
}

/**
 * 会话 store —— **组装根**，不再承载全部业务。
 *
 * 拆分前的形态是单个 900+ 行的 setup：会话、用户管理、审计三套互不相干的
 * 数据与轮询全挤在同一个作用域里，改一处审计逻辑得先读完用户管理代码。
 *
 * 现在按**权限边界**拆成三块（这也是本项目最自然的接缝）：
 *   · 本文件           会话核心：身份、票据、传输状态、登录/登出/改密
 *   · domains/adminDomain  用户管理域（Admin / UserAdmin）
 *   · domains/auditDomain  审计域（仅 AuditAdmin）
 *
 * ⚠️ **对外契约刻意保持不变**：返回对象的键仍与拆分前逐一对应，
 * 因此 4 个视图、2 个告警对话框、App.vue 全都无需改动。
 * 这一点是这次重构敢做的前提 —— 界面级验证（10/10）才能当作回归证据。
 */
export const useSessionStore = defineStore('session', () => {
  const toast = useToastStore()

  // ---------------- 会话状态 ----------------
  const currentUser = ref(loadPersisted())
  const submitting = ref(false)
  /** 验证码发送中的独立状态：不能与 submitting 混用，否则点"获取验证码"会连带锁住提交按钮 */
  const sendingCode = ref(false)

  /** 'unknown' | 'online' | 'offline' */
  const connection = ref('unknown')
  const lastSyncAt = ref(null)

  /**
   * 传输层状态：`{ tls, scheme, subject, notAfter, downgraded, ... }`，取自后端
   * `GET /api/auth/transport`。仅供状态栏显示"加密 / 明文"。
   *
   * 保持 null 表示"还不知道"（老后端没有这个接口 / 尚未连上）——
   * 此时状态栏不显示指示灯。宁可什么都不显示，也不要显示一个可能是错的结论：
   * 验收时要讲的是"现在这条链路到底加没加密"，讲错比不讲更糟。
   */
  const transport = ref(null)

  async function refreshTransport() {
    transport.value = await transportInfo()
  }

  // ---------------- getters ----------------
  const isLoggedIn = computed(() => !!currentUser.value)

  /** 当前角色标识（User / Admin / UserAdmin / AuditAdmin） */
  const role = computed(() => currentUser.value?.role ?? ROLES.USER)

  /**
   * 是否具备用户管理能力（Admin / UserAdmin）。
   * 决定「用户管理」菜单，以及用户列表轮询是否启动。
   */
  const isAdmin = computed(() => role.value === ROLES.ADMIN || role.value === ROLES.USER_ADMIN)

  /**
   * 是否为管理员（含初始 admin）—— 也就是"能任命角色的人"。
   * 只有他能看到「新建账号」与「变更角色」入口。
   */
  const isRoleAdmin = computed(() => role.value === ROLES.ADMIN)

  /**
   * 是否为审计管理员。
   *
   * 这是「审计日志」菜单的唯一开关。管理员（含初始 admin）在这里恒为 false ——
   * 不是界面藏了入口，而是他们的角色压根不满足条件，
   * 即使手敲 URL 调接口，后端也会以 NOT_AUDIT_ADMIN 拒绝并留痕。
   */
  const isAuditAdmin = computed(() => role.value === ROLES.AUDIT_ADMIN)

  const roleLabel = computed(() => ROLE_LABELS[role.value] ?? '普通用户')

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

  // ---------------- persistence / 连接状态 ----------------
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
    // 传输状态只在首次连上时取一次：同一个后端进程内 scheme 不会变，
    // 每次业务请求都去问一遍纯属浪费（markOnline 的调用频率不低）。
    if (transport.value === null) refreshTransport()
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

  // ---------------- 两个业务域 ----------------
  // 域只拿到它真正需要的共享能力，而不是整个 store：
  // 这样"谁能改会话状态"从参数列表就看得出来，不必通读全文。
  const admin = useAdminDomain({ currentUser, persist, isAdmin, markOnline, fail })
  const audit = useAuditDomain({ isAuditAdmin, markOnline, fail })

  /**
   * 统计卡数据。**刻意留在根 store**：它跨用户域（users）与审计域（logs），
   * 放进任一侧都会造成域之间的横向依赖。
   */
  const stats = computed(() => ({
    total: admin.users.value.length,
    pending: admin.pendingUsers.value.length,
    locked: admin.lockedUsers.value.length,
    enabled: admin.enabledUsers.value.length,
    logs: audit.logs.value.length
  }))

  // ---------------- 会话动作 ----------------
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
      // 先落票据再改状态：后续刷新用户/日志都依赖它，
      // 顺序反了会在管理员登录后立刻打出 401 请求。
      if (res.data?.ticket) setTicket(res.data.ticket)
      currentUser.value = {
        username: res.data.username,
        status: res.data.status,
        role: res.data.role ?? ROLES.USER,
        lockoutEnd: null
      }
      persist()
      markOnline()
      // 按角色分别预热一次数据，避免"登录后最长一个轮询周期内界面全空"。
      //
      // 关键：**两条数据链路彻底分开**。改造前管理员一登录就把
      // users / logs / shards / stats 全拉一遍；角色分离后管理员无权看审计，
      // 那样做会立刻撞 403，还会在审计链里灌进自己制造的拒绝记录。
      if (role.value === ROLES.AUDIT_ADMIN) {
        audit.refreshAuditData().catch(() => {
          /* 首次加载失败由轮询兜底，不弹错 */
        })
      } else if (isAdmin.value) {
        admin.refreshAdminData().catch(() => {
          /* 同上 */
        })
      }
      admin.startAdminPolling()
      audit.startAuditPolling()
      // 完整性巡检与越权巡检都只在审计管理员身份下启动 ——
      // 它们读的是审计接口，其他角色跑起来只会产生 403 噪声。
      audit.startIntegrityPolling()
      audit.startIntrusionPolling()
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

  /**
   * 登出。
   *
   * 除了清本地状态，还**必须通知服务端吊销票据** ——
   * 否则票据在有效期内依然可用，等于没有真正退出。
   * 吊销失败（如后端已挂）不阻断本地登出，但会保留票据交由服务端过期兜底。
   */
  async function logout({ silent = false } = {}) {
    admin.stopAdminPolling()
    audit.stopAuditPolling()
    audit.stopIntegrityPolling()
    audit.stopIntrusionPolling()
    try {
      if (getTicket()) await api.logout()
    } catch {
      /* 后端不可达时仍要完成本地登出，不能把用户卡在界面里 */
    }
    setTicket(null)
    currentUser.value = null
    admin.reset()
    audit.reset()
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

  // 恢复会话（刷新页面 / 重开窗口）时按角色预热数据并启动对应轮询。
  // 两条链路依旧分开：审计管理员拿审计数据，管理员拿用户数据，
  // 互不越界，避免刚恢复会话就在对方的接口上撞 403。
  if (role.value === ROLES.AUDIT_ADMIN) {
    audit.startAuditPolling()
    audit.startIntegrityPolling()
    audit.startIntrusionPolling()
    audit.refreshAuditData()
    audit.verifyIntegrity({ auto: true }).catch(() => {})
  } else if (isAdmin.value) {
    admin.startAdminPolling()
    admin.refreshAdminData()
  }

  return {
    // ---------------- 会话核心 ----------------
    currentUser,
    submitting,
    sendingCode,
    connection,
    lastSyncAt,
    transport,
    // 传输状态是**匿名**接口，登录页就要能显示；所以 App 启动探测到后端后就调它，
    // 不能只依赖 markOnline（那样要等登录成功才看得到"加密 / 明文"）。
    refreshTransport,
    isLoggedIn,
    role,
    roleLabel,
    isAdmin,
    isRoleAdmin,
    isAuditAdmin,
    status,
    isLocked,
    lockRemaining,
    stats,
    register,
    sendEmailCode,
    resetPassword,
    login,
    logout,
    changePassword,

    // ---------------- 用户管理域（Admin / UserAdmin） ----------------
    users: admin.users,
    loadingUsers: admin.loadingUsers,
    dormant: admin.dormant,
    pendingUsers: admin.pendingUsers,
    lockedUsers: admin.lockedUsers,
    enabledUsers: admin.enabledUsers,
    adminUsers: admin.adminUsers,
    auditUsers: admin.auditUsers,
    dormantThresholdDays: admin.dormantThresholdDays,
    dormantCandidates: admin.dormantCandidates,
    dormantProtected: admin.dormantProtected,
    frozenAccounts: admin.frozenAccounts,
    refreshUsers: admin.refreshUsers,
    refreshDormant: admin.refreshDormant,
    refreshAdminData: admin.refreshAdminData,
    approve: admin.approve,
    unlock: admin.unlock,
    freezeUser: admin.freezeUser,
    deleteUser: admin.deleteUser,
    createAccount: admin.createAccount,
    setRole: admin.setRole,
    startAdminPolling: admin.startAdminPolling,
    stopAdminPolling: admin.stopAdminPolling,

    // ---------------- 审计域（仅 AuditAdmin） ----------------
    logs: audit.logs,
    loadingLogs: audit.loadingLogs,
    shards: audit.shards,
    auditTotal: audit.auditTotal,
    auditFailed: audit.auditFailed,
    auditPage: audit.auditPage,
    integrity: audit.integrity,
    verifying: audit.verifying,
    tamperAlert: audit.tamperAlert,
    intrusionAlert: audit.intrusionAlert,
    refreshLogs: audit.refreshLogs,
    refreshShards: audit.refreshShards,
    refreshAuditData: audit.refreshAuditData,
    verifyIntegrity: audit.verifyIntegrity,
    dismissTamperAlert: audit.dismissTamperAlert,
    checkIntrusion: audit.checkIntrusion,
    dismissIntrusionAlert: audit.dismissIntrusionAlert,
    startAuditPolling: audit.startAuditPolling,
    stopAuditPolling: audit.stopAuditPolling,
    startIntegrityPolling: audit.startIntegrityPolling,
    stopIntegrityPolling: audit.stopIntegrityPolling,
    startIntrusionPolling: audit.startIntrusionPolling,
    stopIntrusionPolling: audit.stopIntrusionPolling
  }
})
