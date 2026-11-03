/**
 * 一次性口令（哈希链）的**客户端**。
 *
 * 职责只有三件，且刻意不越界：
 *   ① 取参 —— 向 `POST /api/auth/login/challenge` 要 `R / k / N / 迭代次数`；
 *   ② 算值 —— 把口令交给 Rust 侧算出 `x_k`（可选地顺带算一条续期用的新链）；
 *   ③ 换票 —— 把它送进登录接口，或换成一张供敏感操作消费的一次性确认凭据。
 *
 * `x_k` 到底怎么算，这里一个字都不写 —— 那是一份必须与 C# 逐字节一致的实现，
 * 只允许存在一处（`src-tauri/src/otp.rs`）。本文件即使写错，也只会"算错"，
 * 不会"算出另一种链"，因为根本没有第二份实现。
 *
 * ⚠️ P8 删掉了原来那套 `hint`（localStorage 里的"这个账号有没有链"）。
 *    它只在**两条路并存**时才有意义：防枚举让 challenge 对"有链/无链/不存在"
 *    返回逐字相同的参数，客户端分不出该走哪条，只好先猜一条。
 *    现在只剩一条路，猜的对象没了 —— 留着它只会让下一次登录多读一次 localStorage，
 *    并在"账号刚被重建链"时给出一个过期判断。
 */

import { ApiError, api } from './client'

/** 链的续期线（`k ≤ N × 5%`）。必须与 `OtpVerifier.RenewThresholdPercent` 一致。 */
const RENEW_THRESHOLD_PERCENT = 5

/**
 * 六个敏感操作的用途标识。
 *
 * 与服务端 `OtpConfirmPurpose` 逐字一致 —— 这是**协议常量**，不是界面文案：
 * 写错一个字符不会"看起来不对"，而是服务端回 400 `InvalidPurpose`，
 * 于是确认永远换不到票、敏感操作永远走旧路径（在口令路径被移除前，谁都发现不了）。
 */
export const PURPOSE = {
  CREATE_ACCOUNT: 'create-account',
  SET_ROLE: 'set-role',
  FACE_ENROLL: 'face-enroll',
  FACE_DELETE: 'face-delete',
  FACE_ID_ENROLL: 'faceid-enroll',
  FACE_ID_DELETE: 'faceid-delete'
}

/* ---------------- Tauri 命令通道 ---------------- */

let invokePromise = null
let invokeRef = null

/**
 * 取 `@tauri-apps/api/core` 的 `invoke`。拿不到就返回 null（浏览器里跑 dev 时就是这种）。
 *
 * 为什么用动态 import：桌面壳里它是内置的，浏览器里它**不存在** ——
 * 静态 import 会让 `npm run dev` 直接在浏览器里白屏，而"能在浏览器里跑"是本项目
 * 一直保留的调试通路（前端改动不必每次都打包）。
 */
function getInvoke() {
  if (invokeRef) return Promise.resolve(invokeRef)
  if (invokePromise) return invokePromise

  invokePromise = (async () => {
    if (typeof window === 'undefined' || !('__TAURI_INTERNALS__' in window)) return null
    try {
      const { invoke } = await import('@tauri-apps/api/core')
      invokeRef = invoke
      return invoke
    } catch (err) {
      console.warn('[otp] 未能加载 Tauri 命令通道，将退回口令登录：', err)
      return null
    }
  })()
  return invokePromise
}

/* ---------------- 判定（与 C# 同一套整数运算） ---------------- */

/**
 * 是否该续期。**整数交叉相乘**而不是 `k / n <= 0.05`：
 * 浮点在边界上会给出 `0.05000000000000001` 这类值，把"刚好处在线上"的一次判成"不用续"，
 * 而这条线越过的代价是链在无人察觉的情况下少掉最后一截缓冲。
 */
export function needsRenewal(k, n) {
  return n > 1 && k * 100 <= n * RENEW_THRESHOLD_PERCENT
}

/* ---------------- 计算 ---------------- */

/**
 * 调 Rust 算一格（可选地顺带算一条新链）。
 *
 * `renew=true` 会多付一次完整派生（约与主计算同价），所以只由调用方按
 * `needsRenewal()` 的结论决定 —— 这里不自己判断，因为"该不该续期"的判据
 * 必须与服务端**同一个时刻**的 `k`（挑战里给出的那个，即核销前）。
 */
async function compute({ password, challenge, renew }) {
  const invoke = await getInvoke()
  if (!invoke) {
    throw new ApiError('当前环境无法本地计算口令凭据', {
      code: 'OTP_CLIENT_UNAVAILABLE',
      kind: 'client'
    })
  }

  const c = challenge || {}
  try {
    return await invoke('otp_compute', {
      password,
      r: c.r,
      k: c.k,
      n: c.n,
      iterations: c.iterations,
      renew: !!renew
    })
  } catch (err) {
    // Rust 侧返回的是给人看的中文原因（入参越界 / 随机源不可用）。
    // 包装成 ApiError 是为了让上层的 `fail()` 与其它失败走同一套展示逻辑。
    throw new ApiError(`本地计算失败：${err}`, { code: 'OTP_CLIENT_CRYPTO', kind: 'client' })
  }
}

/* ---------------- 对外：三条使用路径 ---------------- */

/**
 * 本机能不能算一格 —— 只看桌面壳在不在（能不能调到 Rust 侧的实现）。
 *
 * P8 之前这里还要问"这个账号有没有链"，因为算不出来还能退回口令；
 * 现在没有退路，所以答案只剩一个：算不出来就登不上，界面必须直说。
 */
export async function available() {
  return !!(await getInvoke())
}

/**
 * 组装一次链值登录的请求体。
 *
 * 返回 `{ body, meta }`：`body` 直接交给 `api.loginOtp`，
 * `meta` 只给调用方做提示与度量（含本次客户端计算耗时），不参与任何判定。
 */
export async function buildLogin({ username, password }) {
  const chRes = await api.otpChallenge(username)
  const challenge = chRes?.data ?? {}

  const renew = needsRenewal(challenge.k, challenge.n)
  const out = await compute({ password, challenge, renew })

  return {
    body: {
      username,
      otpCode: out.code,
      challengeToken: challenge.challengeToken,
      // 没续期就**不要**带 nextChain：服务端在窗口外会忽略它，
      // 但"带了一个会被忽略的东西"会让日志里多出无意义的记录。
      nextChain: out.nextR ? { r: out.nextR, head: out.nextHead } : null
    },
    meta: {
      k: challenge.k,
      n: challenge.n,
      renewed: !!out.nextR,
      elapsedMs: out.elapsedMs
    }
  }
}

/** 组装一次改密的请求体（旧凭据 = 链值）。 */
export async function buildChangePassword({ username, password, newPassword }) {
  const chRes = await api.otpChallenge(username)
  const challenge = chRes?.data ?? {}

  // 改密**不续期**：这条链在这一刻之后就不存在了（服务端会用新口令整条重建），
  // 于是算一条新链出来既无用、又多付一次 PBKDF2。
  const out = await compute({ password, challenge, renew: false })

  return {
    username,
    oldOtpCode: out.code,
    oldChallengeToken: challenge.challengeToken,
    newPassword
  }
}

/**
 * 为一次敏感操作换取一次性确认凭据。**只返回 `{ confirmToken }`，或者抛错。**
 *
 * P8 之前这里有一个 `null` 返回值，含义是"请走旧的口令路径"。
 * 旧路径已经不存在，于是 `null` 变得没有接收者 —— 保留它只会让调用方
 * 写出 `token ?? { operatorPassword: password }` 这种"看起来还在回退"的代码，
 * 而那一行恰好就是把口令送上网络的那一行。
 *
 * ⚠️ 凭据错误（链值不符 / 已用尽 / 被节流）**必须抛出去**：
 *    吞掉它会变成"用户以为确认过了、其实没有"，而且下一次请求会拿着
 *    一个不存在的凭据去撞 401 —— 现象与原因完全对不上。
 */
export async function confirmCredential({ purpose, target, username, password }) {

  // 目标只在"操作别人"的用途里有意义；自助操作（四个 face*）传自己的用户名，
  // 服务端也会强制把它归一成本人（见 OtpController.Reconfirm）。
  const tgt = target || username

  const chRes = await api.otpChallenge(username)
  const challenge = chRes?.data ?? {}

  const out = await compute({ password, challenge, renew: false })

  const res = await api.otpReconfirm({ purpose, target: tgt, otpCode: out.code })
  const token = res?.data?.confirmToken
  if (!token) {
    throw new ApiError('服务端未返回确认凭据', { code: 'OTP_CONFIRM_EMPTY', kind: 'api' })
  }
  return { confirmToken: token }
}
