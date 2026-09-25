/**
 * 界面级验证：审计日志页不存在任何"清空 / 删除日志"入口。
 *
 * 背景：用户看到审计页工具栏上有个「清空」按钮，问"为什么日志页面还有清空这个选项？
 * 日志要做到谁都不能修改"。那个按钮其实只重置查询条件（改名前的 clearFilters），
 * 但名字与"清空"两字连在一起，读起来就是"清空日志"。
 *
 * 这件事光改名字不够 —— 必须证明整页**再也找不到任何可能被读成"删日志"的控件**。
 * 因此断言分两类：
 *   A. 正向：界面文案变成「重置筛选」，只读徽记出现，且说明文字点明"不提供删除入口"；
 *   B. 反向：全页按钮里不含"清空/删除/清除/移除/销毁"字样的日志操作入口。
 *
 * 做法同 ui_audit_events.mjs：不模拟鼠标，走 WebView2 CDP 直接操作 DOM，
 * 测的仍是真实打包后的前端产物。
 *
 * 用法（必须由 Python 侧在同一进程内先启动应用，见 tools/ui_readonly_check.py）。
 */
import fs from 'node:fs'

const CDP = process.env.E2E_CDP || 'http://127.0.0.1:9333'
const OUT = process.env.E2E_SHOTDIR || 'tools'
/**
 * 账号与口令一律走环境变量，**不留默认值**（理由同 ui_audit_events.mjs：
 * 写真实账号名等于随仓库泄漏，写测试库名字换库即静默失败）。
 */
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
  const r = await c.send('Page.captureScreenshot', { format: 'png' })
  fs.writeFileSync(`${OUT}/${name}`, Buffer.from(r.data, 'base64'))
  console.log(`  截图 -> ${OUT}/${name}`)
}

async function main() {
  const c = makeClient(await connect())
  await c.ready
  await c.send('Runtime.enable')
  await c.send('Page.enable')
  await sleep(1500)

  for (let i = 0; i < 40; i++) {
    if (await evalJs(c, `return !!document.querySelector('#app')?.children?.length`)) break
    await sleep(500)
  }

  if (!(await evalJs(c, `return !!localStorage.getItem('auth.ticket')`))) {
    console.log('  未登录，先在界面里登录…')
    if (!USER || !PASS) {
      console.error('  ✗ 缺少 E2E_USER / E2E_PASS 环境变量，无法在界面上登录。')
      console.error('    脚本不内置默认账号：写真实账号会随仓库泄漏，写测试库名字换库即静默失败。')
      console.error('    例：E2E_USER=<审计管理员> E2E_PASS=<口令> 由外层 ui_readonly_check.py 传入。')
      process.exit(2)
    }
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
    for (let i = 0; i < 24; i++) {
      if (await evalJs(c, `return !!localStorage.getItem('auth.ticket')`)) break
      await sleep(500)
    }
    if (!(await evalJs(c, `return !!localStorage.getItem('auth.ticket')`))) {
      const why = await evalJs(c, `
        return (document.body.innerText || '').replace(/\\s+/g, ' ').slice(0, 300)
      `)
      console.log('    登录未成功，界面文本：' + why)
    }
  }

  check('已建立登录会话', (await evalJs(c, `return !!localStorage.getItem('auth.ticket')`)) === true)

  // 进入审计页
  await evalJs(c, `
    const els = [...document.querySelectorAll('a, button, div, span, li')]
    const t = els.find(e => (e.textContent||'').trim() === '审计日志')
    if (t) t.click()
    return true
  `)
  await sleep(3500)
  await shot(c, 'readonly_01_audit_page.png')

  // ---- A. 正向断言 ----
  const texts = await evalJs(c, `
    const btns = [...document.querySelectorAll('button')].map(b => (b.textContent||'').trim()).filter(Boolean)
    const panelTitle = [...document.querySelectorAll('.panel__title')].map(e => (e.textContent||'').trim())
    const readonlyEl = document.querySelector('.readonly')
    const pageText = (document.body.innerText || '')
    return {
      btns,
      panelTitle,
      readonlyText: readonlyEl ? (readonlyEl.textContent||'').trim() : null,
      hasNote: /不提供修改与删除入口/.test(pageText),
      hasResetBtn: btns.some(t => t.includes('重置筛选'))
    }
  `)

  check('工具栏出现「重置筛选」（原「清空」已消失）', texts.hasResetBtn === true,
    texts.btns.filter((b) => /筛选|清空|重置/.test(b)).join(' / ') || '(未找到)')

  check('「操作记录」标题旁出现「只读」徽记', texts.readonlyText !== null &&
    texts.readonlyText.includes('只读'), `徽记=${JSON.stringify(texts.readonlyText)}`)

  check('页面写明"不提供修改与删除入口"', texts.hasNote === true)

  // ---- B. 反向断言：全页不得存在任何可被读成"删日志"的按钮 ----
  const danger = await evalJs(c, `
    const words = ['清空', '删', '清除', '移除', '销毁', '重置日志', 'wipe', 'purge']
    const hits = []
    for (const b of document.querySelectorAll('button')) {
      const t = (b.textContent || '').trim()
      if (!t) continue
      if (words.some(w => t.includes(w))) hits.push(t)
    }
    return hits
  `)
  check('全页按钮中不存在清空/删除日志类操作', danger.length === 0,
    danger.length ? '命中：' + danger.join(' / ') : '0 个')

  // 点名"清空"两字在审计页彻底不出现（含 title 等提示文案）
  const clearWord = await evalJs(c, `
    const html = document.body.innerHTML || ''
    // 只在审计页主区域内找，避免误伤全局
    const page = document.querySelector('.page')
    const scope = page ? page.innerHTML : html
    const hits = []
    const re = /清空/g
    let m
    while ((m = re.exec(scope))) {
      hits.push(scope.slice(Math.max(0, m.index - 40), m.index + 20).replace(/</g, '‹'))
    }
    return hits.slice(0, 5)
  `)
  check('审计页内不再出现「清空」字样', clearWord.length === 0,
    clearWord.length ? clearWord.join(' || ') : '0 处')

  // ---- C. 重置筛选确实还能用（改名不能改坏功能）----
  const resetWorks = await evalJs(c, `
    // 先设一个筛选条件，确认下拉真的变了
    const sel = [...document.querySelectorAll('select')].find(s =>
      [...s.options].some(o => o.value === 'AUDIT_QUERY'))
    if (!sel) return { ok: false, why: '未找到动作下拉' }
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set
    setter.call(sel, 'AUDIT_QUERY')
    sel.dispatchEvent(new Event('change', { bubbles: true }))
    await new Promise(r => setTimeout(r, 2500))
    const before = sel.value
    const btn = [...document.querySelectorAll('button')].find(b => /重置筛选/.test(b.textContent))
    if (!btn) return { ok: false, why: '未找到重置筛选按钮', before }
    btn.click()
    await new Promise(r => setTimeout(r, 2500))
    return { ok: true, before, after: sel.value }
  `)
  check('「重置筛选」仍能恢复默认查询条件（功能未被改名改坏）',
    resetWorks.ok === true && resetWorks.before === 'AUDIT_QUERY' && resetWorks.after === 'all',
    JSON.stringify(resetWorks))

  await sleep(1500)
  await shot(c, 'readonly_02_after_reset.png')

  c.close()
  console.log('\n' + '='.repeat(60))
  console.log(`  只读验证：通过 ${pass.length} 项，失败 ${fail.length} 项`)
  if (fail.length) {
    console.log('  失败清单：')
    fail.forEach((f) => console.log('    - ' + f))
  }
  console.log('  结论：' + (fail.length ? 'FAIL ❌' : 'PASS ✅ 审计页不存在任何日志删除入口'))
  console.log('='.repeat(60))
  process.exit(fail.length ? 1 : 0)
}

main().catch((e) => {
  console.error('异常：', e.message)
  process.exit(2)
})
