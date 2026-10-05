import { ref } from 'vue'
import { api } from '../../api/client'
import { createPoller } from '../../composables/poller'

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
 * 审计域：审计日志、分片清单、完整性巡检、越权巡检。
 *
 * 从 session store 里拆出来的判据 —— 这一域的**全部**数据只对审计管理员开放，
 * 与用户管理域（只对 Admin / UserAdmin 开放）在权限上完全互斥。
 * 二者揉在一个 store 里时，"这个接口该用哪个角色判断"只能靠逐处阅读确认；
 * 拆开后，每个域名下的守卫是同一套。
 *
 * ⚠️ 本模块不返回 store，而是返回一组 ref / computed / 函数，
 * 由 `stores/session.js` 组装成 store 的公开面。
 * 这样做的好处是**对外契约一个字符都没变** —— 所有 `useSessionStore()` 的
 * 消费方（4 个视图 + 2 个告警对话框 + App.vue）不需要任何改动。
 *
 * @param {object} core 共享上下文：{ isAuditAdmin, markOnline, fail }
 */
export function useAuditDomain(core) {
  const { isAuditAdmin, markOnline, fail } = core

  /* ---- state ---- */
  const logs = ref([])
  const loadingLogs = ref(false)

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

  /* ---- actions ---- */

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

  /** 登出时清空本域全部状态（含巡检基线与抑制标记）。 */
  function reset() {
    logs.value = []
    shards.value = []
    auditTotal.value = 0
    auditFailed.value = 0
    integrity.value = null
    tamperAlert.value = null
    intrusionAlert.value = null
    dismissedAlertKey.value = null
    lastLogQuery.value = { page: 1, pageSize: 50 }
    lastIntrusionSeq = null
  }

  /* ---- 后台轮询 ---- */

  /**
   * 审计数据轮询（**仅审计管理员**）。
   *
   * 为什么必须与用户轮询分开：
   *   改造前两者混在一个定时器里，一次刷新同时打 users / logs / shards / stats。
   *   角色分离后管理员无权看审计，若不拆开，管理员登录后会每 20 秒
   *   在四个审计接口各撞一次 403，同时往审计链里写入大量
   *   AUDIT_ACCESS_DENIED —— 告警会被自己制造噪声淹没。
   */
  const auditPoller = createPoller({
    name: 'audit',
    guard: () => isAuditAdmin.value,
    // preservePaging：轮询只取回新数据，不改变审计员正在看的页码与筛选
    task: () => refreshAuditData({ preservePaging: true }),
    intervalMs: AUDIT_REFRESH_MS,
  })

  /**
   * 完整性自动巡检。
   *
   * 为什么需要定时跑：篡改往往发生在"没人点校验按钮"的时候
   * （有人直接在数据库里改了一条日志）。只有周期性校验，
   * 系统才能主动发现并弹窗，而不是等管理员偶然点一次才发现。
   * swallowError：巡检失败不打扰用户（网络抖动不该弹错误框）。
   */
  const integrityPoller = createPoller({
    name: 'integrity',
    // 只在审计管理员身份下巡检：校验接口属于审计数据，
    // 其他角色跑起来每个周期都会撞 403 并留下拒绝记录。
    guard: () => isAuditAdmin.value,
    task: () => verifyIntegrity({ auto: true }),
    intervalMs: INTEGRITY_CHECK_MS,
    swallowError: true,
  })

  /**
   * 越权访问巡检。
   *
   * 与完整性巡检同样是"主动发现"，但盯的是另一类痕迹：
   * 完整性巡检回答"库里的历史有没有被改写"，
   * 越权巡检回答"这一刻有没有人在门外试门"。
   *
   * immediate：先立即跑一次 —— 首次调用即建立基线，同时让刚发生的越权
   * 尽快冒泡，否则管理员登录后要空等一整个巡检周期才可能看到告警。
   * （越权巡检读的是审计统计接口，同样只对审计管理员开放。）
   */
  const intrusionPoller = createPoller({
    name: 'intrusion',
    guard: () => isAuditAdmin.value,
    task: checkIntrusion,
    intervalMs: INTRUSION_CHECK_MS,
    immediate: true,
  })

  return {
    // state
    logs,
    loadingLogs,
    shards,
    auditTotal,
    auditFailed,
    integrity,
    verifying,
    tamperAlert,
    intrusionAlert,
    auditPage,
    // actions
    refreshLogs,
    refreshShards,
    verifyIntegrity,
    dismissTamperAlert,
    checkIntrusion,
    dismissIntrusionAlert,
    refreshAuditData,
    reset,
    // 轮询开关（对外仍是 startXxx/stopXxx 一对）
    startAuditPolling: () => auditPoller.start(),
    stopAuditPolling: () => auditPoller.stop(),
    startIntegrityPolling: () => integrityPoller.start(),
    stopIntegrityPolling: () => integrityPoller.stop(),
    startIntrusionPolling: () => intrusionPoller.start(),
    stopIntrusionPolling: () => intrusionPoller.stop()
  }
}
