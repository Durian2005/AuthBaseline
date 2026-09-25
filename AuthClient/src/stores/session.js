import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { ApiError, api, getTicket, setTicket } from '../api/client'
import { now } from '../composables/clock'
import { useToastStore } from './toast'

const STORAGE_KEY = 'auth.currentUser'
/**
 * 用户管理数据的轮询间隔。
 *
 * 注意它现在**只拉用户列表**，不再连带拉审计数据 ——
 * 角色分离后管理员无权查看审计，"顺手刷新一下日志"会直接撞 403 并
 * 在审计链里留下大量无意义的拒绝记录。审计数据由独立的轮询负责，
 * 且只在审计管理员登录时才启动。
 */
const ADMIN_REFRESH_MS = 20000
/** 审计数据的轮询间隔（仅审计管理员） */
const AUDIT_REFRESH_MS = 20000
/** 完整性巡检间隔：自动发现"有人直接改库"这类渗透痕迹 */
const INTEGRITY_CHECK_MS = 30000
/**
 * 越权访问巡检间隔。
 *
 * 比完整性巡检更密：越权尝试通常来自应用之外（用 curl / PowerShell 直接打接口），
 * 攻击者那几下敲门声不会在界面上留下任何痕迹，只有靠服务端的拒绝事件冒泡。
 * 间隔太长会让"被拒"与"看到告警"之间出现明显空档。
 */
const INTRUSION_CHECK_MS = 10000
/** 越权访问被拒的 action 取值，与后端 AuditAction.AuditAccessDenied 一一对应 */
const INTRUSION_ACTION = 'AUDIT_ACCESS_DENIED'

/**
 * 角色常量。与后端 UserRole 枚举一一对应。
 *
 * User       普通用户
 * Admin      管理员：管用户 + 任命角色，**看不到审计日志**
 * UserAdmin  用户管理员：管用户，不能任命角色
 * AuditAdmin 审计管理员：**只看审计日志**，不能进行任何用户管理
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
   * 越权访问告警：非空时界面弹出对话框。
   *
   * 与篡改告警分成两路状态，而不是共用一个弹窗槽位：
   * 两者来源不同（篡改＝库里的历史被改写，越权＝墙外有人敲门），
   * 可能先后或同时发生，各自独立才不会被对方的关闭动作误清掉。
   */
  const intrusionAlert = ref(null)
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
  let auditTimer = null
  let integrityTimer = null
  let intrusionTimer = null
  /**
   * 已知的最新越权事件序号（巡检基线）。
   *
   * null 表示尚未建立基线：此时首次巡检只记下当前最新序号、不弹窗。
   * 库里往往已经累积了若干历史越权记录，管理员每登录一次就重放一遍毫无意义，
   * 真正需要冒泡的是"本次会话期间**新发生**的越权尝试"。
   */
  let lastIntrusionSeq = null
  /** 审计日志请求序号，用于丢弃被覆盖的过期响应 */
  let logRequestSeq = 0

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

  const pendingUsers = computed(() => users.value.filter((u) => u.status === 'Pending'))
  const lockedUsers = computed(() => users.value.filter((u) => u.status === 'Locked'))
  const enabledUsers = computed(() => users.value.filter((u) => u.status === 'Enabled'))
  /** 具备用户管理能力的账号（Admin / UserAdmin） */
  const adminUsers = computed(() => users.value.filter((u) => u.isAdmin))
  /** 审计管理员账号 */
  const auditUsers = computed(() => users.value.filter((u) => u.role === ROLES.AUDIT_ADMIN))

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
        refreshAuditData().catch(() => {
          /* 首次加载失败由轮询兜底，不弹错 */
        })
      } else if (isAdmin.value) {
        refreshAdminData().catch(() => {
          /* 同上 */
        })
      }
      startAdminPolling()
      startAuditPolling()
      // 完整性巡检与越权巡检都只在审计管理员身份下启动 ——
      // 它们读的是审计接口，其他角色跑起来只会产生 403 噪声。
      startIntegrityPolling()
      startIntrusionPolling()
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
    stopAuditPolling()
    stopIntegrityPolling()
    stopIntrusionPolling()
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
    intrusionAlert.value = null
    lastIntrusionSeq = null
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
   * 拉取审计日志（分页）。
   * query 为 { shard, keyword, action, result, page, pageSize }。
   * 分页信息写入 auditPage，供界面渲染翻页控件。
   */
  async function refreshLogs(query = {}) {
    // 审计数据只对审计管理员开放。管理员/用户管理员在此直接短路，
    // 不发请求 —— 否则每次都撞 403，还会在审计链里留下自己制造的拒绝记录。
    if (!isAuditAdmin.value) return
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
    if (!isAuditAdmin.value) return
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
    if (!isAuditAdmin.value) return null
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
   * 越权访问巡检。
   *
   * 监测对象是服务端在鉴权失败时写下的 AUDIT_ACCESS_DENIED 事件。
   * 为什么要由服务端事件驱动：越权尝试往往压根不经过界面 ——
   * 有人用 curl / PowerShell 直接打 /api/audit/logs 或 /api/auth/logs，
   * 屏幕上不会出现任何异常，只有那条"拒绝了谁"的记录能把它暴露出来。
   *
   * 分两级取值是有意为之：
   *   1) 日常巡检只读概览统计（LatestDeniedSeq）——统计接口不写审计记录，
   *      若改为每 10 秒查一次日志，巡检自己就会持续往审计里灌 AUDIT_QUERY，
   *      等于用监控污染被监控的对象；
   *   2) 确认序号确实变大后，才回查一次详情用于展示。
   *      这次查询留下的"管理员查看了越权记录"记录属于正常审计语义，
   *      且只在真的发生越权时才产生，量级可控。
   *
   * 去重靠序号单调递增：只在 LatestDeniedSeq 大于基线时建立告警，
   * 弹过的序号不会再满足条件，所以不需要额外的"已读"标记。
   */
  async function checkIntrusion() {
    // 同样是审计数据，只有审计管理员有权读取
    if (!isAuditAdmin.value) return
    try {
      const stats = await api.getAuditStats()
      const seq = Number(stats.data?.latestDeniedSeq ?? 0)
      if (!seq) return
      if (lastIntrusionSeq === null) {
        // 建立基线：库里早已存在的历史越权记录属于背景信息，
        // 不该在管理员每次登录时重放一遍。真正要冒泡的是本次新发生的尝试。
        lastIntrusionSeq = seq
        return
      }
      if (seq <= lastIntrusionSeq) return
      lastIntrusionSeq = seq

      let detail = null
      try {
        const res = await api.getLogs({ action: INTRUSION_ACTION, page: 1, pageSize: 1 })
        detail = res.data?.items?.[0] ?? null
      } catch {
        /* 详情取不到不影响告警成立，弹窗退化为只显示序号 */
      }

      intrusionAlert.value = {
        seq,
        count: Number(stats.data?.accessDenied ?? 0),
        detail,
        detectedAt: new Date().toISOString()
      }
    } catch {
      /* 巡检失败静默：网络抖动不该弹错误框，下个周期自会重试 */
    }
  }

  /**
   * 关闭越权告警对话框。
   *
   * 不必像篡改告警那样另记"已关闭"标记：基线序号在告警成立的那一刻
   * 就已经推进，同一事件不会再满足"比基线新"，关闭后自然不会复现。
   */
  function dismissIntrusionAlert() {
    intrusionAlert.value = null
  }

  /**
   * 刷新用户管理数据（**只有用户列表**）。
   *
   * 角色分离后这里刻意不再连带拉取审计数据：
   * 管理员没有审计权限，顺手刷一下日志只会撞 403 并污染审计链。
   * 审计数据由 refreshAuditData 单独负责，只在审计管理员登录时调用。
   */
  async function refreshAdminData() {
    if (!isAdmin.value) return
    await Promise.allSettled([refreshUsers()])
  }

  /**
   * 刷新审计数据（日志 + 分片清单）。
   *
   * @param {boolean} preservePaging 是否沿用当前页码与筛选条件。
   *   后台轮询**必须**传 true —— 否则用户刚翻到第 2 页，
   *   20 秒后就被拽回最新页，筛选条件也一起丢掉。
   */
  async function refreshAuditData({ preservePaging = false } = {}) {
    if (!isAuditAdmin.value) return
    const logQuery = preservePaging ? { ...lastLogQuery.value } : {}
    await Promise.allSettled([refreshLogs(logQuery), refreshShards()])
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
    return res
  }

  async function deleteUser(username) {
    const res = await api.deleteUser(username)
    markOnline()
    await refreshUsers()
    return res
  }

  /**
   * 管理员创建账号（用户管理员 / 审计管理员）。
   *
   * 与注册不同：不需要邮箱与验证码，但需要操作者（管理员）本人的登录口令
   * 做二次确认 —— 后端在签发新管理员之前会再验一次。
   */
  async function createAccount(username, password, roleValue, operatorPassword) {
    const res = await api.createAccount(username, password, roleValue, operatorPassword)
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

  // ---------------- 后台轮询 ----------------

  /**
   * 用户数据轮询（Admin / UserAdmin）。
   * 只拉用户列表 —— 管理员没有审计权限，连带刷新日志会撞 403。
   */
  function startAdminPolling() {
    stopAdminPolling()
    if (!isAdmin.value) return
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

  /**
   * 审计数据轮询（**仅审计管理员**）。
   *
   * 为什么必须与用户轮询分开：
   *   改造前两者混在一个定时器里，一次刷新同时打 users / logs / shards / stats。
   *   角色分离后管理员无权看审计，若不拆开，管理员登录后会每 20 秒
   *   在四个审计接口各撞一次 403，同时往审计链里写入大量
   *   AUDIT_ACCESS_DENIED —— 告警会被自己制造噪声淹没。
   */
  function startAuditPolling() {
    stopAuditPolling()
    if (!isAuditAdmin.value) return
    auditTimer = setInterval(() => {
      // preservePaging：轮询只取回新数据，不改变审计员正在看的页码与筛选
      if (document.visibilityState === 'visible') refreshAuditData({ preservePaging: true })
    }, AUDIT_REFRESH_MS)
  }

  function stopAuditPolling() {
    if (auditTimer) {
      clearInterval(auditTimer)
      auditTimer = null
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
    // 只在审计管理员身份下巡检：校验接口属于审计数据，
    // 其他角色跑起来每个周期都会撞 403 并留下拒绝记录。
    if (!isAuditAdmin.value) return
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

  /**
   * 越权访问巡检。
   *
   * 与完整性巡检同样是"主动发现"，但盯的是另一类痕迹：
   * 完整性巡检回答"库里的历史有没有被改写"，
   * 越权巡检回答"这一刻有没有人在门外试门"。
   */
  function startIntrusionPolling() {
    stopIntrusionPolling()
    // 越权巡检读的是审计统计接口，同样只对审计管理员开放
    if (!isAuditAdmin.value) return
    // 先立即跑一次：首次调用即建立基线，同时让刚发生的越权尽快冒泡，
    // 否则管理员登录后要空等一整个巡检周期才可能看到告警。
    checkIntrusion()
    intrusionTimer = setInterval(() => {
      if (document.visibilityState === 'visible') checkIntrusion()
    }, INTRUSION_CHECK_MS)
  }

  function stopIntrusionPolling() {
    if (intrusionTimer) {
      clearInterval(intrusionTimer)
      intrusionTimer = null
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
    startAuditPolling()
    startIntegrityPolling()
    startIntrusionPolling()
    refreshAuditData()
    verifyIntegrity({ auto: true }).catch(() => {})
  } else if (isAdmin.value) {
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
    // 审计增强
    shards,
    auditTotal,
    auditFailed,
    auditPage,
    integrity,
    verifying,
    tamperAlert,
    intrusionAlert,
    // getters
    isLoggedIn,
    role,
    roleLabel,
    isAdmin,
    isRoleAdmin,
    isAuditAdmin,
    status,
    isLocked,
    lockRemaining,
    pendingUsers,
    lockedUsers,
    enabledUsers,
    adminUsers,
    auditUsers,
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
    refreshAuditData,
    verifyIntegrity,
    dismissTamperAlert,
    checkIntrusion,
    dismissIntrusionAlert,
    approve,
    unlock,
    deleteUser,
    createAccount,
    setRole,
    startAdminPolling,
    stopAdminPolling,
    startAuditPolling,
    stopAuditPolling,
    startIntegrityPolling,
    stopIntegrityPolling,
    startIntrusionPolling,
    stopIntrusionPolling
  }
})
