/**
 * 后端 API 客户端。
 *
 * 约定（与 ASP.NET Core 后端 AuthController 完全对齐，不做任何后端改动）：
 *   - 所有接口位于 /api/auth/*
 *   - 成功：{ success: true, code: 'OK', message, data }
 *   - 失败：{ success: false, code, message, data } + 非 2xx 状态码
 *
 * 为了便于界面定位问题，错误被分为三类：
 *   kind = 'network' 浏览器根本没连上后端
 *   kind = 'http'    后端返回了非 2xx，但响应体不是预期结构
 *   kind = 'api'     后端按约定返回了业务失败
 */
/* ---------------- API 基址 ----------------
 * 浏览器（ASP.NET Core 托管）：页面与 API 同源，直接用相对路径 /api。
 * 桌面端（Tauri）：页面源是 tauri://，相对路径不可用，必须指向 sidecar 后端的真实地址；
 *   该地址由 Rust 侧动态分配空闲端口后通过 IPC 下发（见 src-tauri/src/lib.rs 的 get_backend_url）。
 */
let BACKEND_BASE = '' // 例如 'http://127.0.0.1:52341'；浏览器环境为空串
let API_ROOT = '/api'

/** 所有请求都会先等它落地，避免"会话恢复"抢在地址下发之前发请求 */
let apiRootReady = Promise.resolve()

function isTauri() {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

export function getBackendBase() {
  return BACKEND_BASE
}

export function setBackendBase(base) {
  BACKEND_BASE = typeof base === 'string' ? base.replace(/\/+$/, '') : ''
  API_ROOT = BACKEND_BASE ? `${BACKEND_BASE}/api` : '/api'
}

/**
 * 应用启动时调用：桌面端向 Rust 侧询问 sidecar 后端地址。
 * 浏览器环境直接跳过，保持同源相对路径，行为与改造前完全一致。
 */
export function initApiRoot() {
  apiRootReady = (async () => {
    if (!isTauri()) return null
    try {
      const { invoke } = await import('@tauri-apps/api/core')
      const base = await invoke('get_backend_url')
      if (typeof base === 'string' && base) {
        setBackendBase(base)
        return BACKEND_BASE
      }
    } catch (err) {
      console.warn('[tauri] 未能获取后端地址，回退为同源 /api：', err)
    }
    return null
  })()
  return apiRootReady
}

export class ApiError extends Error {
  constructor(message, { code = '', status = 0, data = null, kind = 'api' } = {}) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
    this.data = data
    this.kind = kind
  }
}

/* ---------------- 会话票据 ----------------
 * 后端签发的不透明随机票据，管理员接口需通过 Authorization: Bearer 携带。
 *
 * 为什么放在内存 + localStorage：
 *   管理员接口必须有它才能通过，刷新页面不该要求重新登录；
 *   但它终究是凭证，登出时务必调用后端吊销并清空本地副本。
 */
const TICKET_KEY = 'auth.ticket'
let ticket = null

try {
  ticket = localStorage.getItem(TICKET_KEY) || null
} catch {
  /* 隐私模式下 localStorage 可能不可写 */
}

export function setTicket(value) {
  ticket = value || null
  try {
    if (ticket) localStorage.setItem(TICKET_KEY, ticket)
    else localStorage.removeItem(TICKET_KEY)
  } catch {
    /* 忽略写入失败：内存中仍持有票据，本次会话可用 */
  }
}

export function getTicket() {
  return ticket
}

function authHeaders(base) {
  if (!ticket) return base
  return { ...(base || {}), Authorization: `Bearer ${ticket}` }
}

async function request(path, { method = 'GET', body, signal } = {}) {
  await apiRootReady
  let res
  try {
    res = await fetch(API_ROOT + path, {
      method,
      headers: authHeaders(body === undefined ? undefined : { 'Content-Type': 'application/json' }),
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
      cache: 'no-store'
    })
  } catch (err) {
    if (err?.name === 'AbortError') throw err
    throw new ApiError(
      `无法连接后端服务。请确认 MongoDB 已启动、后端进程正在运行${
        BACKEND_BASE ? `（${BACKEND_BASE}）` : '（http://localhost:5007）'
      }。`,
      { kind: 'network', status: 0 }
    )
  }

  const text = await res.text()
  let payload = null
  try {
    payload = text ? JSON.parse(text) : null
  } catch {
    payload = null
  }

  if (!res.ok) {
    // 票据失效（过期 / 被吊销 / 未携带）时清掉本地副本，
    // 否则界面会一直拿着废票据重试，用户看到的只是"无管理员权限"而不知为何。
    //
    // ⚠️ 判据必须是**具体的原因码**，不能是"凡是 401 就清"：
    //   401 在本系统里至少有两种完全不同的含义 ——
    //     · 会话层面的失败（NO_TICKET / SESSION_*）⇒ 票据确实废了，该清；
    //     · 凭据层面的失败（INVALID_CREDENTIALS：改口令时旧口令错、
    //       删人脸/录入人脸时二次口令错）⇒ 票据**好着呢**，是这一次校验没过。
    //   若按"401 一律清"，用户只是把二次口令输错一次，就会被悄悄登出，
    //   而界面上只看到"口令错误"——原因与现象对不上，极难归因。
    const code = payload?.code || `HTTP_${res.status}`
    const SESSION_GONE = ['NO_TICKET', 'SESSION_INVALID', 'SESSION_EXPIRED', 'SESSION_REVOKED']
    if (SESSION_GONE.includes(code)) {
      setTicket(null)
    }
    throw new ApiError(payload?.message || `服务器返回 HTTP ${res.status}`, {
      code,
      status: res.status,
      data: payload?.data ?? null,
      kind: 'http'
    })
  }

  if (payload && payload.success === false) {
    throw new ApiError(payload.message || '操作失败', {
      code: payload.code,
      status: res.status,
      data: payload.data ?? null,
      kind: 'api'
    })
  }

  return payload
}

/**
 * 后端连通性探测。
 *
 * 刻意不调用业务接口：非管理员调用 /api/auth/users 必然得到 401，
 * 即使 JS 侧已 catch，浏览器仍会在控制台留下红色错误，属于误导性噪声。
 *
 * 改用对 /favicon.svg 发 GET —— 轻量静态资源，且不会产生 4xx 业务噪声。
 * 注意：不能用 HEAD 打站点根路径，浏览器会对该请求抛 net::ERR_ABORTED，
 * 从而污染 requestfailed 日志。
 *
 * 判定标准用 status < 500 而不是 res.ok：
 * 桌面端的 sidecar 只带走 exe，wwwroot 不一定随行，/favicon.svg 可能返回 404；
 * 但只要拿到了 HTTP 响应，就说明后端进程确实在监听。
 */
export async function probe() {
  await apiRootReady
  try {
    const res = await fetch(`${BACKEND_BASE}/favicon.svg`, { method: 'GET', cache: 'no-store' })
    return res.status < 500
  } catch {
    return false
  }
}

/**
 * 传输层状态：当前链路是否加密（TLS）。
 *
 * 为什么不放进 `api.*`：那里每一个方法的语义都是"业务调用，失败要抛错"。
 * 而这是状态栏的装饰性信息，必须**永不抛错** —— 后端若是本次改造之前的版本，
 * 该接口根本不存在，此时正确行为是"指示灯不显示"，而不是让界面报错。
 *
 * 判断依据取后端返回的 `tls`（它有 Request.IsHttps 作依据，是实际链路的事实），
 * 而不是"地址是 https:// 开头"—— 后者只说明我们**打算**加密。
 */
export async function transportInfo() {
  await apiRootReady
  try {
    const res = await fetch(`${API_ROOT}/auth/transport`, { cache: 'no-store' })
    if (!res.ok) return null
    const body = await res.json()
    return body?.data ?? null
  } catch {
    return null
  }
}

export const api = {
  /** 注册：邮箱验证通过后才真正建号（email/code 在老流程下可为空串） */
  register: (username, password, email, code) =>
    request('/auth/register', { method: 'POST', body: { username, password, email, code } }),

  /** 发送邮箱验证码。purpose 取 'REGISTER' | 'RESET'，用途严格隔离 */
  sendEmailCode: (purpose, username, email) =>
    request('/auth/send-email-code', { method: 'POST', body: { purpose, username, email } }),

  /** 忘记密码：用户名 + 邮箱 + 验证码 → 直接设置新密码（不建立任何会话） */
  resetPassword: (username, email, code, newPassword) =>
    request('/auth/reset-password', {
      method: 'POST',
      body: { username, email, code, newPassword }
    }),

  login: (username, password) =>
    request('/auth/login', { method: 'POST', body: { username, password } }),

  /** 登出：吊销服务端票据。前端随后清空本地副本 */
  logout: () => request('/auth/logout', { method: 'POST' }),

  changePassword: (username, oldPassword, newPassword) =>
    request('/auth/change-password', {
      method: 'POST',
      body: { username, oldPassword, newPassword }
    }),

  approve: (username) => request('/auth/approve', { method: 'POST', body: { username } }),

  unlock: (username) => request('/auth/unlock', { method: 'POST', body: { username } }),

  /**
   * 冻结账号（沉睡账号治理）。
   *
   * 与 deleteUser 的区别是**可逆性**：冻结只是置为不可登录，
   * 用 unlock 即可恢复；注销则是永久删除。这两个动作在界面上
   * 必须用不同的措辞与颜色，避免"想冻结却点成注销"。
   */
  freezeUser: (username, reason = '') =>
    request('/auth/freeze-user', { method: 'POST', body: { username, reason } }),

  /**
   * 沉睡账号清单（只读）。
   * 返回 { thresholdDays, items, protectedItems, frozenItems }。
   */
  getDormantUsers: (signal) => request('/auth/dormant-users', { signal }),

  deleteUser: (username) => request('/auth/delete-user', { method: 'POST', body: { username } }),

  /**
   * 管理员创建账号（普通用户 / 用户管理员 / 审计管理员）。
   *
   * 与 register 的区别：不发验证码、建号即启用。
   * email 是**可选**的：留空即只凭口令登录（该账号用不了「忘记密码」）；
   * 填写则后端登记为已验证，随后即可走找回密码。
   * operatorPassword 是操作者本人的登录口令 —— 后端要求二次确认身份，
   * 仅凭会话票据不足以发起这种高权限操作。
   */
  createAccount: (username, password, role, operatorPassword, email) =>
    request('/auth/create-account', {
      method: 'POST',
      body: { username, password, role, operatorPassword, email }
    }),

  /**
   * 变更他人角色 —— "指定某位管理员为审计管理员"就是调它。
   * role 取 'User' | 'UserAdmin' | 'AuditAdmin'（后端拒绝 'Admin'）。
   */
  setRole: (username, role, operatorPassword) =>
    request('/auth/set-role', {
      method: 'POST',
      body: { username, role, operatorPassword }
    }),

  getUsers: (signal) => request('/auth/users', { signal }),

  /**
   * 审计日志分页查询。
   * shard 为空表示跨全部分片（含归档）；分片名可从 getShards() 获得。
   */
  getLogs: ({ shard = '', keyword = '', action = 'all', result = 'all', page = 1, pageSize = 50 } = {}, signal) => {
    const qs = new URLSearchParams()
    if (shard) qs.set('shard', shard)
    if (keyword) qs.set('keyword', keyword)
    if (action && action !== 'all') qs.set('action', action)
    if (result && result !== 'all') qs.set('result', result)
    qs.set('page', String(page))
    qs.set('pageSize', String(pageSize))
    qs.set('includeArchived', shard ? 'false' : 'true')
    return request(`/audit/logs?${qs.toString()}`, { signal })
  },

  /** 审计分片清单（轮转结果） */
  getShards: (signal) => request('/audit/shards', { signal }),

  /** 完整性校验：返回是否完整、断点序号、期望/实际哈希 */
  verifyAudit: (signal) => request('/audit/verify', { signal }),

  /** 审计概览统计 */
  getAuditStats: (signal) => request('/audit/stats', { signal }),

  /* ---------------- 人脸（可选第二因子） ----------------
   * 两个刻意的共同点：
   *   · 请求体里**从不出现特征或画面** —— 采集、检测、特征提取全在服务端进程内完成。
   *     这一条是这条功能的立身之本：一旦允许前端上送特征，
   *     攻击者就能不碰摄像头、直接 POST 一个向量，活体挑战形同虚设。
   *   · 挑战 token ≠ 会话票据。前者只代表"口令那一因子刚过"，
   *     拿它去访问任何业务接口都应当失败。
   */

  /**
   * 登录第二阶段：提交一次性挑战（`FACE_REQUIRED` 里返回的那张）。
   * 成功后返回的对象与 login 完全同构 —— 里面才有真正的票据。
   */
  loginFace: (challengeToken) =>
    request('/auth/login/face', { method: 'POST', body: { challengeToken } }),

  /** 本人人脸状态：是否已录、几张、最近一次录入时刻、本机引擎是否可用 */
  faceStatus: (signal) => request('/auth/face', { signal }),

  /**
   * 识别画面的地址（**注意：这不是一次 request()**，返回体是 image/jpeg）。
   *
   * 由 FacePreview 组件用 fetch + canvas 逐帧拉取渲染。之所以不走 <img src>：
   * 桌面壳的 CSP 只给 img-src 放行了 'self' / asset: / data:，既不含后端源
   * 也不含 blob:；而 connect-src 是放行后端的 —— 走 fetch 就**不必为这个功能
   * 给 CSP 开任何新的口子**，顺带还能读到随帧下发的检测状态响应头。
   *
   * 携带的是**一次性挑战 token**，不是会话票据；token 过期 / 被消费 / 采集结束，
   * 这个地址立刻失效（服务端门禁绑在挑战上，见 FacePreviewService）。
   */
  facePreviewUrl: (challengeToken) =>
    `${API_ROOT}/auth/face/preview?token=${encodeURIComponent(challengeToken)}`,

  /** 录入第一步：验当前口令 → 换一张动作挑战（动作由服务端随机决定） */
  faceEnrollStart: (password) =>
    request('/auth/face/enroll', { method: 'POST', body: { password } }),

  /** 录入第二步：提交挑战，服务端采集一帧并写入模板 */
  faceEnrollComplete: (challengeToken) =>
    request('/auth/face/enroll/complete', { method: 'POST', body: { challengeToken } }),

  /** 删除本人全部人脸模板。需当前口令 —— 这是"降级通道"上唯一的闸门 */
  faceDelete: (password) => request('/auth/face/delete', { method: 'POST', body: { password } }),

  /**
   * 管理员重置他人人脸（处置类，与注销同一个权限出口）。
   * 用途：换人 / 换设备 / 疑似泄露后作废，以及"录入者摄像头损坏、
   * 第二因子无法完成"时**唯一**的恢复路径。
   */
  resetFace: (username) => request('/auth/reset-face', { method: 'POST', body: { username } })
}

export { API_ROOT }
