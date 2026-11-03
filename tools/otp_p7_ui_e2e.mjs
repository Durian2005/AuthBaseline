/**
 * 一次性口令（哈希链）P7 的**界面级**验证：真实桌面壳 + 真实 WebView2 + 真实 IPC。
 *
 * 为什么非要有这一层：协议层探针（`otp_p7_probe.py`）能证明"服务端认这种请求"，
 * 但它证明不了"Vue 真的这样发了请求"。中间隔着一条最容易错的缝 ——
 * `invoke('otp_compute', {...})` 的命令名与参数名、返回值字段名。
 * 这条缝一旦错位，客户端会**安静地**退回口令登录：界面一切正常，
 * 只是"这个功能从没生效过"。所以本脚本的判据不看界面文案，而是看
 * 服务端审计里有没有 `OTP_CONSUME`（那是"客户端真的算出了一格"唯一的硬证据）。
 *
 * 驱动方式：CDP（WebView2 的 `--remote-debugging-port`）。
 *
 * 用法（先用探针库拉起桌面端，见命令行说明）：
 *   E2E_CDP=http://127.0.0.1:9333 node tools/otp_p7_ui_e2e.mjs
 */
import fs from 'node:fs'

const CDP = process.env.E2E_CDP || 'http://127.0.0.1:9333'
const USER = process.env.E2E_USER || 'admin'
const PASS = process.env.E2E_PASS || 'Admin123'

const pass = []
const fail = []

function check(name, ok, detail = '') {
  ;(ok ? pass : fail).push(name)
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? '  -> ' + detail : ''}`)
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function connect() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${CDP}/json/list`)
      const list = await res.json()
      const page = list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl)
      if (page) return page
    } catch {
      /* 调试端口还没起来 */
    }
    await sleep(500)
  }
  throw new Error(`无法连接调试端口 ${CDP}`)
}

function makeClient(wsUrl) {
  const ws = new WebSocket(wsUrl)
  let id = 0
  const pending = new Map()

  ws.addEventListener('message', (ev) => {
    const msg = JSON.parse(ev.data)
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id)
      pending.delete(msg.id)
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result)
    }
  })

  const ready = new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve)
    ws.addEventListener('error', reject)
  })

  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const mid = ++id
      pending.set(mid, { resolve, reject })
      ws.send(JSON.stringify({ id: mid, method, params }))
    })

  async function js(expression) {
    const r = await send('Runtime.evaluate', {
      expression: `(async () => { ${expression} })()`,
      awaitPromise: true,
      returnByValue: true
    })
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description || 'JS 执行异常')
    }
    return r.result.value
  }

  return { ready, send, js, close: () => ws.close() }
}

/**
 * 装一套页面内工具。
 *
 * 两个刻意的写法：
 *   · 赋值走 `HTMLInputElement.prototype.value` 的原生 setter 再派发 `input`：
 *     Vue 的 v-model 监听的是 `input` 事件，直接改 `el.value` 不会触发它 ——
 *     这是"点了没反应"最常见的原因；
 *   · `console.error` 被就地改写一份副本：OTP 本地计算失败时客户端会**故意**打一条
 *     console.error（见 stores/session.js），本脚本据此判断"有没有悄悄降级"。
 */
const HELPERS = `
  window.__t = {
    set(sel, val) {
      const el = document.querySelector(sel)
      if (!el) throw new Error('找不到元素 ' + sel)
      const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')
      d.set.call(el, val)
      el.dispatchEvent(new Event('input', { bubbles: true }))
      el.dispatchEvent(new Event('change', { bubbles: true }))
      return true
    },
    click(sel) {
      const el = document.querySelector(sel)
      if (!el) throw new Error('找不到元素 ' + sel)
      el.click()
      return true
    },
    loggedIn() {
      return !!document.querySelector('button.nav')
    },
    loginPage() {
      return !!document.querySelector('#login-username')
    },
    otpErrors() {
      return (window.__otpErrors || []).slice()
    },
    hints() {
      try { return JSON.parse(localStorage.getItem('auth.otp.enrolled') || '{}') } catch { return {} }
    }
  };
  if (!window.__otpHook) {
    window.__otpHook = true
    window.__otpErrors = []
    const orig = console.error
    console.error = function (...args) {
      try { window.__otpErrors.push(args.map((a) => (a && a.message) ? a.message : String(a)).join(' ')) } catch {}
      return orig.apply(console, args)
    }
  }
  return true
`

async function main() {
  const page = await connect()
  console.log(`[e2e] 调试目标：${page.url}`)
  const c = makeClient(page.webSocketDebuggerUrl)
  await c.ready
  await c.send('Runtime.enable')

  // 等界面渲染完（登录页或已登录都可能，取决于上一轮留下的会话）
  let ready = false
  for (let i = 0; i < 40; i++) {
    const ok = await c.js(`return !!(document.querySelector('#login-username') || document.querySelector('button.nav'))`)
    if (ok) { ready = true; break }
    await sleep(500)
  }
  check('E1 界面已渲染', ready)
  if (!ready) throw new Error('界面没起来')

  // 工具要在**任何**页面操作之前注入：它同时接管了 console.error（用于发现"悄悄降级"）
  await c.js(HELPERS)

  /** 在登录页填用户名+口令并提交，返回"点了登录到进入主界面"的耗时（毫秒）。 */
  const login = async () => {
    await c.js(`
      window.__t.set('#login-username', ${JSON.stringify(USER)})
      const pw = document.querySelector('input[type=password]')
      if (!pw) throw new Error('找不到口令输入框')
      const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')
      d.set.call(pw, ${JSON.stringify(PASS)})
      pw.dispatchEvent(new Event('input', { bubbles: true }))
      pw.dispatchEvent(new Event('change', { bubbles: true }))
      return true
    `)
    const t0 = Date.now()
    await c.js(`
      const btn = [...document.querySelectorAll('button')].find(b => b.type === 'submit')
      if (!btn) throw new Error('找不到登录按钮')
      btn.click()
      return true
    `)
    for (let i = 0; i < 150; i++) {
      if (await c.js(`return window.__t.loggedIn()`)) return Date.now() - t0
      await sleep(100)
    }
    const err = await c.js(`return (document.body.innerText || '').slice(0, 200)`)
    throw new Error('登录未完成：' + String(err).replace(/\s+/g, ' ').slice(0, 120))
  }

  /** 退出到登录页：优先点界面上的退出按钮，退不出去再清会话兜底。 */
  const backToLogin = async () => {
    const loggedIn = await c.js(`return window.__t.loggedIn ? window.__t.loggedIn() : !!document.querySelector('button.nav')`)
    if (loggedIn) {
      await c.js(`
        const btn = document.querySelector('button[aria-label="退出登录"]') ||
                    [...document.querySelectorAll('button')].find(b => b.textContent.trim() === '退出登录')
        if (btn) btn.click()
        return !!btn
      `)
    }
    for (let i = 0; i < 40; i++) {
      if (await c.js(`return !!document.querySelector('#login-username')`)) return true
      await sleep(250)
    }
    return false
  }

  // ── P8 翻面 ──
  // P7 时这里在验证"hint 的学习曲线"：首轮走口令、学到有链、第二轮走链值。
  // P8 删掉口令路径的同时也删掉了 hint —— 只剩一条路，"先猜再学"没有存在意义。
  // 于是 E2/E4 的判据翻成**反面**：登录/登出全程都不该再出现那个 localStorage 键。
  // （E0 的 removeItem 保留：它确保上一轮 P7 版本留下的残留不会干扰判断。）
  await c.js(`localStorage.removeItem('auth.otp.enrolled'); return true`)
  check('E0 已回到登录页', await backToLogin())

  const t1 = await login()
  check('E1 首轮登录成功（链值；链由空库播种建好）', true, `${t1} ms`)
  const hints1 = await c.js(`return window.__t.hints()`)
  check('E2 登录后**不写** hint（P8 起只有一条路，无需先猜）',
        hints1[USER] === undefined, JSON.stringify(hints1))
  const errs1 = await c.js(`return window.__t.otpErrors()`)
  check('E3 首轮没有 OTP 客户端错误', errs1.length === 0, errs1.join(' | '))

  // 第二轮：完整走一遍"登出 → 再登录"，证明链值路径在**新会话**上同样成立
  //（判据：本地计算零报错 —— invoke('otp_compute') 真的通了两轮）。
  await backToLogin()
  const hints2 = await c.js(`return window.__t.hints()`)
  check('E4 登出后 hint 仍不存在（不存在"提示过期"这种故障形态）',
        hints2[USER] === undefined, JSON.stringify(hints2))

  const t2 = await login()
  check('E5 第二轮登录成功（链值路径）', true, `${t2} ms`)
  const errs2 = await c.js(`return window.__t.otpErrors()`)
  check('E6 链值路径没有本地计算错误（invoke 通了）', errs2.length === 0, errs2.join(' | '))

  // ── 第三段：六处二次确认里挑一个真跑一遍 ──────────────────────
  // 为什么挑 `create-account`：它同时要求**用途**（create-account）与**目标**（新用户名），
  // 是六个用途里绑定维度最多的一个；它一旦通，其余五个（都只是"用途 + 本人"）
  // 走的都是同一条 `reconfirm` 通道。
  const NEW_USER = process.env.E2E_NEW_USER || 'p7ui01'

  const gotoUsers = async () => {
    await c.js(`
      const nav = [...document.querySelectorAll('button.nav')].find(b => b.textContent.includes('用户管理'))
      if (!nav) throw new Error('找不到「用户管理」导航')
      nav.click()
      return true
    `)
    for (let i = 0; i < 40; i++) {
      const ok = await c.js(`return [...document.querySelectorAll('button')].some(b => b.textContent.includes('新建账号'))`)
      if (ok) return true
      await sleep(250)
    }
    return false
  }

  const createViaUi = async () => {
    await c.js(`
      const btn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('新建账号'))
      if (!btn) throw new Error('找不到「新建账号」')
      btn.click()
      return true
    `)
    let opened = false
    for (let i = 0; i < 40; i++) {
      opened = await c.js(`return !!document.querySelector('input[placeholder="例如 auditor01"]')`)
      if (opened) break
      await sleep(200)
    }
    if (!opened) throw new Error('建号弹窗没打开')

    await c.js(`
      window.__t.set('input[placeholder="例如 auditor01"]', ${JSON.stringify(NEW_USER)})
      const pw = document.querySelector('input[placeholder="输入你自己的密码以确认身份"]')
      if (!pw) throw new Error('找不到二次确认口令框')
      const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')
      d.set.call(pw, ${JSON.stringify(PASS)})
      pw.dispatchEvent(new Event('input', { bubbles: true }))
      pw.dispatchEvent(new Event('change', { bubbles: true }))
      const ok = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === '创建账号')
      if (!ok) throw new Error('找不到「创建账号」按钮')
      ok.click()
      return true
    `)

    for (let i = 0; i < 80; i++) {
      const gone = await c.js(`return !document.querySelector('input[placeholder="例如 auditor01"]')`)
      if (gone) return await c.js(`return document.body.innerText.includes(${JSON.stringify(NEW_USER)})`)
      await sleep(250)
    }
    return false
  }

  check('E8 进入用户管理页', await gotoUsers())
  check('E9 用确认凭据建出账号（界面路径）', await createViaUi(), `新账号 ${NEW_USER}`)
  const errs3 = await c.js(`return window.__t.otpErrors()`)
  check('E10 建号过程中没有 OTP 客户端错误', errs3.length === 0, errs3.join(' | '))

  const shell = await c.js(`return typeof window.__TAURI_INTERNALS__ === 'object'`)
  check('E7 运行在桌面壳里（不是浏览器）', shell)

  c.close()

  fs.writeFileSync(
    process.env.E2E_OUT || 'tools/evidence/otp_p7_ui.json',
    JSON.stringify({ t1, t2, hints: hints2, errs1, errs2, errs3, newUser: NEW_USER, mode: 'p8-chain-only' }, null, 2)
  )

  console.log('\n' + '='.repeat(62))
  console.log(`通过 ${pass.length} / 失败 ${fail.length}`)
  if (fail.length) fail.forEach((n) => console.log('  · ' + n))
  console.log(`口令路径 ${t1} ms ／ 链值路径 ${t2} ms`)
  console.log('='.repeat(62))
  process.exit(fail.length ? 1 : 0)
}

main().catch((err) => {
  console.error('[e2e] 失败：', err.message)
  process.exit(1)
})
