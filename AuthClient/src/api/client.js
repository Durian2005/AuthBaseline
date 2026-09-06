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

async function request(path, { method = 'GET', body, signal } = {}) {
  await apiRootReady
  let res
  try {
    res = await fetch(API_ROOT + path, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
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
    throw new ApiError(payload?.message || `服务器返回 HTTP ${res.status}`, {
      code: payload?.code || `HTTP_${res.status}`,
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

export const api = {
  register: (username, password) =>
    request('/auth/register', { method: 'POST', body: { username, password } }),

  login: (username, password) =>
    request('/auth/login', { method: 'POST', body: { username, password } }),

  changePassword: (username, oldPassword, newPassword) =>
    request('/auth/change-password', {
      method: 'POST',
      body: { username, oldPassword, newPassword }
    }),

  approve: (username, adminUsername) =>
    request('/auth/approve', { method: 'POST', body: { username, adminUsername } }),

  unlock: (username, adminUsername) =>
    request('/auth/unlock', { method: 'POST', body: { username, adminUsername } }),

  deleteUser: (username, adminUsername) =>
    request('/auth/delete-user', { method: 'POST', body: { username, adminUsername } }),

  transferAdmin: (targetUsername, adminUsername, password) =>
    request('/auth/transfer-admin', {
      method: 'POST',
      body: { targetUsername, adminUsername, password }
    }),

  getUsers: (adminUsername, signal) =>
    request(`/auth/users?adminUsername=${encodeURIComponent(adminUsername)}`, { signal }),

  getLogs: (adminUsername, signal) =>
    request(`/auth/logs?adminUsername=${encodeURIComponent(adminUsername)}`, { signal })
}

export { API_ROOT }
