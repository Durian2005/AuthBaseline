/**
 * 界面级验证：桌面端整条链路确实走 TLS，且业务功能不受影响。
 *
 * 为什么必须做界面级验证（而不是只看接口返回）：
 *   1) 页面本身由后端**同源提供**，一旦证书不被 WebView2 接受，用户看到的是
 *      **白窗口** —— 没有任何可读错误。只有真启动一次才能证明"界面能渲染"。
 *   2) 接口层探针（transport_func_check.py）证明不了 **CSP** 放行了 https：
 *      connect-src 少一条，接口通、页面里的 fetch 全被拦，界面看似正常但什么都点不动。
 *      所以在页面内 fetch 一次才算覆盖到。
 *   3) 状态栏那句「加密」是验收时唯一能"讲出来"的东西，必须证明它真的渲染出来了。
 *
 * 断言分两类：
 *   A. 正向：页面为 https、状态栏出现「加密」徽记（含证书信息）、接口 tls=true、登录与用户列表可用
 *   B. 反向：状态栏**不得**出现「明文」；页面内取到的传输状态不得为 tls=false
 *
 * 用法（必须由 Python 侧在同一进程内先启动应用，见 tools/ui_tls_check.py）：
 *   E2E_CDP 调试端口，默认 http://127.0.0.1:9333
 *   E2E_USER / E2E_PASS 登录凭据（不内置默认值，由外层传入）
 *   E2E_SHOTDIR 截图目录，默认 tools
 */
import fs from 'node:fs'

const CDP = process.env.E2E_CDP || 'http://127.0.0.1:9333'
const OUT = process.env.E2E_SHOTDIR || 'tools'
const USER = process.env.E2E_USER || ''
const PASS = process.env.E2E_PASS || ''

const pass = []
const fail = []
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function check(name, ok, detail = '') {
  ;(ok ? pass : fail).push(name)
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? '  -> ' + detail : ''}`)
}

async function connect() {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (await fetch(`${CDP}/json/list`)).json()
      const page = list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl)
      if (page) return page.webSocketDebuggerUrl
    } catch {
      /* 端口未就绪 */
    }
    await sleep(500)
  }
  throw new Error('无法连接 WebView2 调试端口 ' + CDP)
}

function makeClient(wsUrl) {
  const ws = new WebSocket(wsUrl)
  let id = 0
  const pending = new Map()
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data)
    if (m.id && pending.has(m.id)) {
      const { resolve, reject } = pending.get(m.id)
      pending.delete(m.id)
      m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result)
    }
  })
  const ready = new Promise((res, rej) => {
    ws.addEventListener('open', res)
    ws.addEventListener('error', rej)
  })
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const n = ++id
      pending.set(n, { resolve, reject })
      ws.send(JSON.stringify({ id: n, method, params }))
    })
  return { ready, send, close: () => ws.close() }
}

async function evalJs(c, expr) {
  const r = await c.send('Runtime.evaluate', {
    expression: `(async () => { ${expr} })()`,
    awaitPromise: true,
    returnByValue: true
  })
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval 异常')
  return r.result?.value
}

async function shot(c, name) {
  try {
    const r = await c.send('Page.captureScreenshot', { format: 'png' })
    fs.writeFileSync(`${OUT}/${name}`, Buffer.from(r.data, 'base64'))
    console.log(`  截图 -> ${OUT}/${name}`)
  } catch (e) {
    console.log(`  截图失败（不影响断言）：${e.message}`)
  }
}

async function main() {
  const c = makeClient(await connect())
  await c.ready
  await c.send('Runtime.enable')
  await c.send('Page.enable')
  await sleep(1200)

  // 等 Vue 首屏 —— 同时就是"白窗口"检测：CSP 放行了、证书被接受了，才有内容
  let rendered = false
  for (let i = 0; i < 60; i++) {
    rendered = await evalJs(c, `return !!document.querySelector('#app')?.children?.length`)
    if (rendered) break
    await sleep(500)
  }
  check('界面已渲染（非白窗口）', rendered === true)

  if (!rendered) {
    const html = await evalJs(c, `return (document.body.innerHTML || '').slice(0, 200)`)
    console.log('    body 前 200 字符：' + html)
  }

  /* ---------- A. 传输层：页面自身 ---------- */
  const proto = await evalJs(c, `return location.protocol + '//' + location.host`)
  check('页面本身由 https 加载', proto.startsWith('https://'), proto)

  /* ---------- A. 传输层：状态栏「加密」徽记 ---------- */
  // 传输状态是 App 启动探活**之后**才发起的一次异步 fetch，落定时间不固定。
  // 不等它就直接断言，会得到一个"有时通过有时失败"的假阴性 —— 那是测试的毛病，
  // 不是功能的毛病，报出去会让人白查一轮。所以先轮询等徽记出现（或确认它确实没出现）。
  let waited = 0
  for (let i = 0; i < 24; i++) {
    const has = await evalJs(c, `
      const f = document.querySelector('footer.status')
      if (!f) return false
      return [...f.querySelectorAll('.conn')].some(e => /加密|明文/.test(e.textContent || ''))
    `)
    if (has) break
    waited += 500
    await sleep(500)
  }
  console.log(`  传输状态指示灯在 ${waited} ms 后落定`)

  const bar = await evalJs(c, `
    const f = document.querySelector('footer.status')
    if (!f) return null
    const badges = [...f.querySelectorAll('.conn')].map(e => ({
      text: (e.textContent || '').trim(),
      title: e.getAttribute('title') || '',
      cls: e.className
    }))
    return { text: (f.innerText || '').replace(/\\s+/g, ' ').trim(), badges }
  `)
  if (!bar) {
    check('状态栏存在', false)
  } else {
    const texts = bar.badges.map((b) => b.text)
    const enc = bar.badges.find((b) => b.text.includes('加密'))
    check('状态栏出现「加密」徽记', !!enc, texts.join(' / ') || '(无徽记)')
    if (enc) {
      check('加密徽记带证书信息（悬停可见）', /TLS/.test(enc.title),
        enc.title.replace(/\n/g, ' | ').slice(0, 100))
    }
    // ---- B. 反向断言：不得出现「明文」 ----
    const plain = bar.badges.filter((b) => b.text.includes('明文'))
    check('状态栏不存在「明文」徽记', plain.length === 0,
      plain.length ? '命中：' + plain.map((p) => p.text).join(' / ') : '0 个')
  }

  /* ---------- A. CSP + 接口：在页面内请求一次 ---------- */
  const t = await evalJs(c, `
    try {
      const r = await fetch('/api/auth/transport', { cache: 'no-store' })
      const j = await r.json()
      return { ok: true, status: r.status, data: j.data || null }
    } catch (e) {
      return { ok: false, err: String(e && e.message || e) }
    }
  `)
  check('页面内可请求 /api/auth/transport（证明 CSP 放行了 https）', t.ok === true,
    t.ok ? `HTTP ${t.status}` : t.err)
  check('后端自述 tls=true 且 scheme=https',
    !!t.data && t.data.tls === true && t.data.scheme === 'https',
    t.data ? `tls=${t.data.tls} scheme=${t.data.scheme} 到期=${(t.data.notAfter || '').slice(0, 10)}` : '(无数据)')

  await shot(c, 'tls_01_login_encrypted.png')

  /* ---------- 业务功能：登录 ---------- */
  const logged = await evalJs(c, `return !!localStorage.getItem('auth.ticket')`)
  if (!logged) {
    if (!USER || !PASS) {
      console.error('  ✗ 缺少 E2E_USER / E2E_PASS，无法在界面上登录。')
      process.exit(2)
    }
    console.log('  未登录，在界面里登录…')
    await evalJs(c, `
      const setVal = (el, v) => {
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set
        setter.call(el, v)
        el.dispatchEvent(new Event('input', { bubbles: true }))
        el.dispatchEvent(new Event('change', { bubbles: true }))
      }
      const inputs = [...document.querySelectorAll('input')]
      const pw = inputs.filter(i => i.type === 'password')[0]
      const user = inputs.find(i => i !== pw)
      if (user) setVal(user, ${JSON.stringify(USER)})
      if (pw) setVal(pw, ${JSON.stringify(PASS)})
      await new Promise(r => setTimeout(r, 900))
      const f = document.querySelector('form')
      if (f) f.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
      return true
    `)
    for (let i = 0; i < 30; i++) {
      if (await evalJs(c, `return !!localStorage.getItem('auth.ticket')`)) break
      await sleep(500)
    }
  }
  const okLogin = await evalJs(c, `return !!localStorage.getItem('auth.ticket')`)
  check('在加密链路上登录成功并拿到票据', okLogin === true)
  if (!okLogin) {
    const why = await evalJs(c, `return (document.body.innerText || '').replace(/\\s+/g, ' ').slice(0, 300)`)
    console.log('    登录未成功，界面文本：' + why)
  }

  /* ---------- 业务功能：进入用户管理并读到数据 ---------- */
  if (okLogin) {
    await sleep(1500)
    await evalJs(c, `
      const els = [...document.querySelectorAll('a, button, div, span, li')]
      const t = els.find(e => (e.textContent || '').trim() === '用户管理')
      if (t) t.click()
      return true
    `)
    await sleep(3500)

    const rows = await evalJs(c, `
      const trs = [...document.querySelectorAll('table tbody tr')]
      const heads = [...document.querySelectorAll('th')].map(th => (th.textContent || '').trim())
      return { count: trs.length, heads: heads.slice(0, 8) }
    `)
    check('用户管理页读到用户数据（后端 ↔ MongoDB 正常）', rows.count > 0,
      `表格 ${rows.count} 行，列：${rows.heads.join(' / ')}`)

    // 状态栏在登录后应当依旧显示「加密」
    const after = await evalJs(c, `
      const f = document.querySelector('footer.status')
      return f ? (f.innerText || '').replace(/\\s+/g, ' ').trim() : ''
    `)
    check('登录后状态栏仍显示加密', /加密/.test(after) && !/明文/.test(after), after.slice(0, 90))

    await shot(c, 'tls_02_after_login.png')
  }

  c.close()
  console.log('\n' + '='.repeat(60))
  console.log(`  TLS 界面验证：通过 ${pass.length} 项，失败 ${fail.length} 项`)
  if (fail.length) {
    console.log('  失败清单：')
    fail.forEach((f) => console.log('    - ' + f))
  }
  console.log('  结论：' + (fail.length ? 'FAIL' : 'PASS —— 桌面端全链路 TLS 生效且功能正常'))
  console.log('='.repeat(60))
  process.exit(fail.length ? 1 : 0)
}

main().catch((e) => {
  console.error('异常：', e.message)
  process.exit(2)
})
