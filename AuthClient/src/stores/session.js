import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { ApiError, api, getTicket, setTicket } from '../api/client'
import { now } from '../composables/clock'
import { useToastStore } from './toast'

const STORAGE_KEY = 'auth.currentUser'
const ADMIN_REFRESH_MS = 20000
/** 完整性巡检间隔：自动发现"有人直接改库"这类渗透痕迹 */
const INTEGRITY_CHECK_MS = 30000

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

  /* ---- 审计完整性（实验二：篡改检测弹窗） ---- */
  const shards = ref([])
  const auditTotal = ref(0)
  const auditFailed = ref(0)
  /** 最近一次完整性校验结果；null 表示尚未校验 */
  const integrity = ref(null)
  /** 是否正在校验 */
  const verifying = ref(false)
  /** 篡改告警：非空时界面弹出阻断式对话框 */
  const tamperAlert = ref(null)
  /**
   * 已被用户关闭的告警标识（`断裂序号@分片`）。
   *
   * 没有这个标记时，自动巡检每 30 秒重算一次链，只要断裂还在就再弹一次 ——
   * 用户点掉对话框后 30 秒内必然又被弹回来，等于关不掉。
   * 记下被关闭的断裂标识后，自动巡检对**同一处**断裂保持静默；
   * 手动点「立即校验」会清掉标记，所以随时还能主动唤起告警。
   */
  const dismissedAlertKey = ref(null)
  /** 审计日志当前分页状态 */
  const auditPage = ref({ page: 1, pageSize: 50 })
  /**
   * 最近一次审计查询的完整条件（页码 + 筛选）。
   *
   * 后台轮询刷新日志时必须沿用它：原先轮询调用无参数的刷新，
   * 后端默认返回第 1 页，于是用户刚翻到第 2 页就被拉回最新页，
   * 连筛选条件一起丢掉。
   */
  const lastLogQuery = ref({ page: 1, pageSize: 50 })

  let adminTimer = null
  let integrityTimer = null
  /** 审计日志请求序号，用于丢弃被覆盖的过期响应 */
  let logRequestSeq = 0

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
      // 先落票据再改状态：后续刷新用户/日志都依赖它，
      // 顺序反了会在管理员登录后立刻打出 401 请求。
      if (res.data?.ticket) setTicket(res.data.ticket)
      currentUser.value = {
        username: res.data.username,
        status: res.data.status,
        isAdmin: res.data.isAdmin,
        lockoutEnd: null
      }
      persist()
      markOnline()
      // 先立即拉一次管理员数据，再启动轮询。
      // setInterval 要等一个完整周期才会首次执行，若只启动轮询，
      // 管理员登录后最长 20 秒内看到的都是空列表（用户数 0、审计 0 条），
      // 会被误认为数据丢失。这里不阻塞登录返回，失败也不影响登录结果。
      if (currentUser.value.isAdmin) {
        refreshAdminData().catch(() => {
          /* 首次加载失败由轮询兜底，不弹错 */
        })
      }
      startAdminPolling()
      // 管理员登录后立即开始完整性巡检：一旦库里被人直接改过，
      // 无需手动点"校验"也能在 30 秒内弹出阻断式告警。
      startIntegrityPolling()
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
    stopAdminPolling()
    stopIntegrityPolling()
    try {
      if (getTicket()) await api.logout()
    } catch {
      /* 后端不可达时仍要完成本地登出，不能把用户卡在界面里 */
    }
    setTicket(null)
    currentUser.value = null
    users.value = []
    logs.value = []
    shards.value = []
    integrity.value = null
    tamperAlert.value = null
    dismissedAlertKey.value = null
    lastLogQuery.value = { page: 1, pageSize: 50 }
    auditTotal.value = 0
    auditFailed.value = 0
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
   * 拉取审计日志（分页）。
   * query 为 { shard, keyword, action, result, page, pageSize }。
   * 分页信息写入 auditPage，供界面渲染翻页控件。
   */
  async function refreshLogs(query = {}) {
    if (!currentUser.value?.isAdmin) return
    // 记住本次条件，供后台轮询原样沿用（页码、筛选都不能丢）
    lastLogQuery.value = {
      page: query.page ?? 1,
      pageSize: query.pageSize ?? auditPage.value.pageSize ?? 50,
      ...(query.shard ? { shard: query.shard } : {}),
      ...(query.keyword ? { keyword: query.keyword } : {}),
      ...(query.action ? { action: query.action } : {}),
      ...(query.result ? { result: query.result } : {})
    }
    // 请求序号：后台轮询与用户翻页可能并发，只认最后发出的那一次结果，
    // 否则先发的慢响应后到，会把已经翻好的页又覆盖回去。
    const ticket = ++logRequestSeq
    loadingLogs.value = true
    try {
      const res = await api.getLogs(query)
      if (ticket !== logRequestSeq) return
      logs.value = res.data?.items ?? []
      auditTotal.value = res.data?.total ?? 0
      auditPage.value = {
        page: res.data?.page ?? 1,
        pageSize: res.data?.pageSize ?? 50
      }
      markOnline()
    } catch (err) {
      throw fail(err, '加载审计日志失败')
    } finally {
      if (ticket === logRequestSeq) loadingLogs.value = false
    }
  }

  /** 拉取分片清单（轮转结果），用于界面展示"撑得住"的证据。 */
  async function refreshShards() {
    if (!currentUser.value?.isAdmin) return
    try {
      const res = await api.getShards()
      shards.value = res.data ?? []
    } catch (err) {
      throw fail(err, '加载分片清单失败')
    }
  }

  /**
   * 完整性校验。
   *
   * 这是「改不掉」的验证入口：后端重算全链哈希，比对存储值。
   * 检出断裂时弹出阻断式告警，弹窗时机按触发来源区分：
   *   · 手动（auto=false）：每次都弹，并解除此前关闭留下的抑制；
   *   · 自动巡检（auto=true）：同一处断裂被关闭过就不再打扰，
   *     只有出现**新的**断裂才弹 —— 新发生的篡改不能被静默。
   *
   * @param {boolean} auto 是否为后台自动巡检触发
   */
  async function verifyIntegrity({ auto = false } = {}) {
    if (!currentUser.value?.isAdmin) return null
    verifying.value = true
    try {
      const res = await api.verifyAudit()
      const data = res.data
      integrity.value = { ...data, checkedAt: new Date().toISOString() }

      const key = `${data?.firstBrokenSeq}@${data?.brokenShard}`
      if (!data?.intact) {
        // 篡改被检出，是否弹窗按来源区分：
        //   · 手动点「立即校验」→ 无条件弹，并解除之前关闭留下的抑制。
        //     用户主动要看的告警，任何时候都该给。
        //   · 后台自动巡检 → 对**已被关闭过的同一处**断裂保持静默。
        //     否则用户点掉对话框后，下一个 30 秒巡检周期又会弹回来，
        //     等于关不掉。若断裂位置变化（出现了新的篡改），仍会弹一次
        //     —— 新发生的事件不能被静默掉。
        const isNewBreak = tamperAlert.value?.key !== key
        if (!auto) dismissedAlertKey.value = null
        const suppressed = auto && dismissedAlertKey.value === key
        if (isNewBreak && !suppressed) {
          tamperAlert.value = {
            key,
            seq: data.firstBrokenSeq,
            shard: data.brokenShard,
            brokenAt: data.brokenAt,
            reason: data.brokenReason,
            expected: data.expected,
            actual: data.actual,
            detail: data.detail,
            detectedBy: auto ? '自动巡检' : '手动校验',
            detectedAt: new Date().toISOString()
          }
        }
      } else {
        // 链已恢复完整（例如管理员重新灌入正确数据），撤下告警并解除抑制
        if (tamperAlert.value) tamperAlert.value = null
        dismissedAlertKey.value = null
      }

      markOnline()
      return integrity.value
    } catch (err) {
      throw fail(err, '完整性校验失败')
    } finally {
      verifying.value = false
    }
  }

  /**
   * 关闭告警对话框。
   *
   * 同时记下被关闭的断裂标识：自动巡检靠它判断"这处断裂用户已经看过了"，
   * 从而不再反复弹出。手动校验会清掉这个标记，所以随时还能主动唤起告警。
   */
  function dismissTamperAlert() {
    if (tamperAlert.value?.key) dismissedAlertKey.value = tamperAlert.value.key
    tamperAlert.value = null
  }

  /**
   * 刷新管理员视图数据（用户列表 + 审计日志 + 分片清单）。
   *
   * @param {boolean} preservePaging 是否沿用用户当前的页码与筛选条件。
   *   后台轮询**必须**传 true —— 原先无参数刷新日志，后端默认返回第 1 页，
   *   于是用户刚翻到第 2 页，20 秒后就被拽回最新页，筛选条件也一起丢掉。
   *   登录 / 恢复会话时传 false：那种场景本来就该落在最新一页。
   */
  async function refreshAdminData({ preservePaging = false } = {}) {
    if (!currentUser.value?.isAdmin) return
    const logQuery = preservePaging ? { ...lastLogQuery.value } : {}
    await Promise.allSettled([refreshUsers(), refreshLogs(logQuery), refreshShards()])
  }

  async function approve(username) {
    const res = await api.approve(username)
    markOnline()
    await refreshUsers()
    await refreshLogs()
    return res
  }

  async function unlock(username) {
    const res = await api.unlock(username)
    markOnline()
    await refreshUsers()
    await refreshLogs()
    return res
  }

  async function deleteUser(username) {
    const res = await api.deleteUser(username)
    markOnline()
    await refreshUsers()
    await refreshLogs()
    return res
  }

  /**
   * 管理员权限转让。
   *
   * 后端在转让成功后会吊销双方票据并要求重新登录（防止授权残留），
   * 因此这里不能沿用"刷新列表继续用"的老逻辑，必须直接登出。
   */
  async function transferAdmin(targetUsername, password) {
    const res = await api.transferAdmin(targetUsername, password)
    markOnline()
    toast.warning(res?.message || '权限已转让，请重新登录')
    setTimeout(() => logout({ silent: true }), 1800)
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
      // preservePaging：轮询只把新数据取回来，不改变用户正在看的页码与筛选
      if (document.visibilityState === 'visible') refreshAdminData({ preservePaging: true })
    }, ADMIN_REFRESH_MS)
  }

  function stopAdminPolling() {
    if (adminTimer) {
      clearInterval(adminTimer)
      adminTimer = null
    }
  }

  /**
   * 完整性自动巡检。
   *
   * 为什么需要定时跑：篡改往往发生在"没人点校验按钮"的时候
   * （有人直接在数据库里改了一条日志）。只有周期性校验，
   * 系统才能主动发现并弹窗，而不是等管理员偶然点一次才发现。
   */
  function startIntegrityPolling() {
    stopIntegrityPolling()
    if (!currentUser.value?.isAdmin) return
    integrityTimer = setInterval(() => {
      if (document.visibilityState === 'visible') {
        verifyIntegrity({ auto: true }).catch(() => {
          /* 巡检失败不打扰用户：网络抖动不该弹错误框 */
        })
      }
    }, INTEGRITY_CHECK_MS)
  }

  function stopIntegrityPolling() {
    if (integrityTimer) {
      clearInterval(integrityTimer)
      integrityTimer = null
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

  // 恢复会话时，管理员自动拉一次数据并开始完整性巡检
  if (currentUser.value?.isAdmin) {
    startAdminPolling()
    startIntegrityPolling()
    refreshAdminData()
    verifyIntegrity({ auto: true }).catch(() => {})
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
    // 审计增强
    shards,
    auditTotal,
    auditFailed,
    auditPage,
    integrity,
    verifying,
    tamperAlert,
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
    refreshShards,
    refreshAdminData,
    verifyIntegrity,
    dismissTamperAlert,
    approve,
    unlock,
    deleteUser,
    transferAdmin,
    startAdminPolling,
    stopAdminPolling,
    startIntegrityPolling,
    stopIntegrityPolling
  }
})
