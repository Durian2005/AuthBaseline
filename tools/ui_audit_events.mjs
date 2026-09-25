/**
 * 界面级验证：审计员能在界面上单独捞出「改密失败」等失败类事件。
 *
 * 背景：用户问过"admin 改密不符合要求失败，有没有记进日志"。后端已验证
 * （tools/password_event_probe.py 直接查库确认 seq 1431~1434 四条带原因码的记录），
 * 但还要证明**审计员在界面上真的看得到** —— 一条查不到的事件，等于没记。
 *
 * 排查方式的变化（重要）：
 *   早先审计页有个「安全事件」一键筛选按钮，本脚本点的是那个按钮；
 *   该按钮已按需求移除，筛选入口收敛为「操作类型」下拉。
 *   失败类事件依旧可查，而且查法更直接：写入时成功/失败就已分开命名
 *   （CHANGE_PASSWORD_FAILED 是独立动作），选下拉即可，不必叠加结果条件。
 *   因此脚本改为走下拉，并**额外断言那个按钮确实不存在了** ——
 *   被删掉的入口如果悄悄回来，这里要能立刻发现。
 *
 * 做法：不模拟鼠标（本机 WebView2 的合成窗口对 SetForegroundWindow 不响应，
 * 点击落不进去），而是启动桌面端时打开 WebView2 调试端口，用 CDP 直接操作 DOM。
 * 这样测的仍是真实打包后的前端产物，而不是 dev server。
 *
 * 用法（必须由 Python 侧在同一进程内先启动应用，见 tools/ui_audit_check.py）。
 */
import fs from 'node:fs'

const CDP = process.env.E2E_CDP || 'http://127.0.0.1:9333'
const OUT = process.env.E2E_SHOTDIR || 'tools'
/**
 * 注：用户名与口令一律走环境变量传入，**不留默认值**。
 * 两头都试过，都不行：
 *   写真实库的账号名  → 账号名随仓库一起公开，等于泄漏；
 *   写测试库的 auditor01 → 换库即静默失败（"字段填了、按钮点了，就是进不去"）。
 * 所以这里留空，缺变量时在下面直接报错退出，把问题摆到明面上。
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

/** 在页面里求值，返回 JSON 可序列化的结果 */
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

/**
 * 驱动 <select> 的片段。
 * 与 input 同理：直接 sel.value = x 改的是 DOM 属性，
 * Vue 的 v-model 监听 change 事件，组件状态不会更新 ——
 * 界面看着选中了，查询条件其实没变。
 */
const SET_SELECT = (selExpr, value) => `
  const sel = ${selExpr}
  if (!sel) return { found: false }
  const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set
  setter.call(sel, ${JSON.stringify(value)})
  sel.dispatchEvent(new Event('change', { bubbles: true }))
  return { found: true }
`

/**
 * 读表格当前行。
 * **按表头名字定位列**，不写死下标 —— 表格列会随需求增减
 * （这轮就动过），写死 td[3] / td[4] 会在下次改列时静默取错值。
 */
const READ_ROWS = `
  const heads = [...document.querySelectorAll('th')].map(th => (th.textContent||'').trim())
  const actIdx = heads.indexOf('动作')
  const resIdx = heads.indexOf('结果')
  const rsnIdx = heads.indexOf('原因')
  const rows = [...document.querySelectorAll('tbody tr')].map(tr => {
    const tds = [...tr.querySelectorAll('td')].map(td => (td.textContent||'').trim())
    if (tds.length <= actIdx) return null
    return { action: tds[actIdx], result: resIdx >= 0 ? tds[resIdx] : '', reason: rsnIdx >= 0 ? tds[rsnIdx] : '' }
  }).filter(Boolean)
  return { heads, rows, n: rows.length }
`

async function main() {
  const wsUrl = await connect()
  const c = makeClient(wsUrl)
  await c.ready
  await c.send('Runtime.enable')
  await c.send('Page.enable')
  await sleep(1500)

  // 等 Vue 挂载完成
  for (let i = 0; i < 40; i++) {
    const ready = await evalJs(c, `return !!document.querySelector('#app')?.children?.length`)
    if (ready) break
    await sleep(500)
  }

  const loggedIn = await evalJs(c, `
    return !!localStorage.getItem('auth.ticket')
  `)

  if (!loggedIn) {
    console.log('  未登录，先在界面里登录…')
    if (!USER || !PASS) {
      console.error('  ✗ 缺少 E2E_USER / E2E_PASS 环境变量，无法在界面上登录。')
      console.error('    脚本不内置默认账号：写真实账号会随仓库泄漏，写测试库名字换库即静默失败。')
      console.error('    例：E2E_USER=<审计管理员> E2E_PASS=<口令> 由外层 ui_audit_check.py 传入。')
      process.exit(2)
    }
    // 关键：必须用**原生 setter + input 事件**驱动，不能用 el.value = x。
    //
    // 直接赋值改的是 DOM 属性，Vue 的 v-model 监听的是 input 事件；
    // 只赋值不发事件时，界面看上去填好了，但组件里的 loginForm 仍是空串，
    // 提交函数的第一行 `if (!username || !password) return` 直接静默返回
    // —— 既不报错也不发请求，表现为"按钮点了没反应"。
    // 这里同时补 change/blur，覆盖不同组件绑的事件类型。
    const filled = await evalJs(c, `
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
      return { user: user ? user.value : null, pwLen: pw ? pw.value.length : 0 }
    `)
    console.log(`    填入 用户名=${filled.user} 口令长度=${filled.pwLen}`)

    // 用 Enter 键提交：登录表单监听的是表单 submit，
    // 而 Enter 的按键事件会走浏览器默认行为触发 submit，
    // 比找按钮 click 更贴近真人操作，也不受按钮 disabled 状态影响。
    const clickedLogin = await evalJs(c, `
      const pw = [...document.querySelectorAll('input')].filter(i => i.type === 'password')[0]
      if (pw) {
        pw.focus()
        for (const type of ['keydown', 'keypress', 'keyup']) {
          pw.dispatchEvent(new KeyboardEvent(type, {
            key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true
          }))
        }
      }
      await new Promise(r => setTimeout(r, 500))
      const form = document.querySelector('form')
      if (form) form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
      return { ok: true }
    `)
    console.log(`    提交登录：${JSON.stringify(clickedLogin)}`)

    for (let i = 0; i < 24; i++) {
      const tk = await evalJs(c, `return !!localStorage.getItem('auth.ticket')`)
      if (tk) break
      await sleep(500)
    }

    // 登录没成功时把界面上的报错文字抓回来 —— 否则只能看到 ticket=false，
    // 完全不知道是口令错、账号锁定，还是表单压根没提交。
    const tk2 = await evalJs(c, `return !!localStorage.getItem('auth.ticket')`)
    if (!tk2) {
      const why = await evalJs(c, `
        const alertEl = document.querySelector('.alert, [role=alert], .field__error, .toast, .toast__item')
        return {
          visibleText: (document.body.innerText || '').replace(/\\s+/g, ' ').slice(0, 300),
          alert: alertEl ? (alertEl.textContent || '').trim() : null
        }
      `)
      console.log('    登录未成功，界面提示：' + JSON.stringify(why))
    }
  }

  const after = await evalJs(c, `
    return {
      ticket: !!localStorage.getItem('auth.ticket'),
      nav: [...document.querySelectorAll('nav a, aside a, .nav a, [role=tab]')].map(a => (a.textContent||'').trim()).filter(Boolean).slice(0, 12),
      bodyText: (document.body.innerText || '').slice(0, 400)
    }
  `)
  check('已建立登录会话', after.ticket === true, `ticket=${after.ticket}`)

  // 点侧边栏"审计日志"
  const clicked = await evalJs(c, `
    const els = [...document.querySelectorAll('a, button, div, span, li')]
    const t = els.find(e => (e.textContent||'').trim() === '审计日志')
    if (!t) return false
    t.click()
    return true
  `)
  check('能从侧边栏进入审计页', clicked === true)
  await sleep(3500)
  await shot(c, 'audit_01_page.png')

  // ---- 回归断言：被移除的「安全事件」按钮不得复活 ----
  const toolbar = await evalJs(c, `
    const btns = [...document.querySelectorAll('button')].map(b => (b.textContent||'').trim()).filter(Boolean)
    const heads = [...document.querySelectorAll('th')].map(th => (th.textContent||'').trim())
    return { btns, heads, pageText: (document.body.innerText || '') }
  `)
  check('工具栏不再出现「安全事件」按钮', !toolbar.btns.some((b) => b.includes('安全事件')),
    toolbar.btns.filter((b) => /安全事件/.test(b)).join(' / ') || '0 个')
  check('审计页正文里不再出现「安全事件」字样', !toolbar.pageText.includes('安全事件'),
    toolbar.pageText.includes('安全事件') ? '仍有残留' : '0 处')
  check('表格保留「原因」列', toolbar.heads.includes('原因'), toolbar.heads.join(' / '))

  // ---- 失败类事件仍然可查：走操作类型下拉 ----
  const byAction = await evalJs(c, `
    const sel = [...document.querySelectorAll('select')].find(s =>
      [...s.options].some(o => o.value === 'CHANGE_PASSWORD_FAILED'))
    if (!sel) return { found: false }
    const opt = [...sel.options].find(o => o.value === 'CHANGE_PASSWORD_FAILED')
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set
    setter.call(sel, 'CHANGE_PASSWORD_FAILED')
    sel.dispatchEvent(new Event('change', { bubbles: true }))
    return { found: true, label: opt.textContent.trim() }
  `)
  check('动作下拉里有「改密失败」选项', byAction.found === true, byAction.label || '')

  // ---- 时钟异常事件也要能筛得到（本次硬化新增的动作） ----
  // 只读选项、不动当前选中值：下面几步还依赖"动作筛选停在改密失败"这个状态，
  // 顺手改掉会让后续断言失去意义。
  const clockOpt = await evalJs(c, `
    const sel = [...document.querySelectorAll('select')].find(s =>
      [...s.options].some(o => o.value === 'CLOCK_ANOMALY'))
    if (!sel) return { found: false }
    const opt = [...sel.options].find(o => o.value === 'CLOCK_ANOMALY')
    return { found: true, label: opt.textContent.trim(), current: sel.value }
  `)
  check('动作下拉里有「时钟异常」选项（可单独筛出拨钟事件）', clockOpt.found === true,
    `label=${clockOpt.label || '(无)'}  当前选中=${clockOpt.current || ''}`)
  await sleep(3500)
  await shot(c, 'audit_02_change_pw_failed.png')

  const filtered = await evalJs(c, READ_ROWS)
  const pager = await evalJs(c, `return (document.body.innerText.match(/共\\s*\\d+\\s*条/) || [''])[0]`)
  check('按动作筛选返回的整页都是「改密失败」', filtered.n > 0 &&
    filtered.rows.every((r) => r.action === '改密失败'),
    `${filtered.n} 行，动作集合=${JSON.stringify([...new Set(filtered.rows.map((r) => r.action))])} ${pager}`)

  const reasonFilled = filtered.rows.filter((r) => r.reason && r.reason !== '—').length
  check('失败记录的原因列有中文说明（不再空白）', reasonFilled > 0,
    `有原因 ${reasonFilled} / ${filtered.rows.length}  例：${filtered.rows[0]?.reason || '无'}`)

  check('筛出的记录结果均为「失败」', filtered.rows.every((r) => r.result === '失败'),
    [...new Set(filtered.rows.map((r) => r.result))].join(','))

  // 打开一条"改密失败"的详情，确认原因码也展示了
  const detailOk = await evalJs(c, `
    const heads = [...document.querySelectorAll('th')].map(th => (th.textContent||'').trim())
    const actIdx = heads.indexOf('动作')
    const trs = [...document.querySelectorAll('tbody tr')]
    const target = trs.find(tr => (tr.querySelectorAll('td')[actIdx]?.textContent || '').includes('改密失败'))
    if (!target) return { opened: false }
    const btn = [...target.querySelectorAll('button')].find(b => /详情/.test(b.textContent))
    if (btn) btn.click()
    await new Promise(r => setTimeout(r, 900))
    const txt = (document.body.innerText || '')
    return {
      opened: true,
      hasReasonCode: /WEAK_PASSWORD|WRONG_OLD_PASSWORD|PASSWORD_REUSED/.test(txt),
      hasReasonLabel: /口令复杂度不达标|旧口令错误|新旧口令相同/.test(txt)
    }
  `)
  await sleep(1200)
  await shot(c, 'audit_03_detail.png')
  check('可打开改密失败的详情', detailOk.opened === true)
  check('详情里同时给出中文原因与原始原因码',
    detailOk.hasReasonCode === true && detailOk.hasReasonLabel === true,
    `code=${detailOk.hasReasonCode} label=${detailOk.hasReasonLabel}`)

  // 关掉详情窗，否则会挡住后面的下拉操作
  await evalJs(c, `
    const close = [...document.querySelectorAll('button')].find(b => (b.textContent||'').trim() === '关闭')
    if (close) close.click()
    await new Promise(r => setTimeout(r, 600))
    return true
  `)

  // ---- 全局失败筛查：动作=all + 结果=仅失败（不依赖任何"安全事件"预设）----
  // 必须先把动作选回 all，否则"全局"是假的 —— 上一段还停在 CHANGE_PASSWORD_FAILED 上，
  // 那样即使断言通过，也只证明了"改密失败里都是失败"。
  await evalJs(c, SET_SELECT(
    `[...document.querySelectorAll('select')].find(s => [...s.options].some(o => o.value === 'CHANGE_PASSWORD_FAILED'))`,
    'all'
  ))
  await sleep(2500)
  const onlyFailed = await evalJs(c, SET_SELECT(
    `[...document.querySelectorAll('select')].find(s => [...s.options].some(o => o.value === '失败'))`,
    '失败'
  ))
  await sleep(3500)
  await shot(c, 'audit_04_only_failed.png')
  const failedRows = await evalJs(c, READ_ROWS)
  const distinctActions = [...new Set(failedRows.rows.map((r) => r.action))]
  check('「结果 = 仅失败」可做全局失败筛查',
    onlyFailed.found === true && failedRows.n > 0 && failedRows.rows.every((r) => r.result === '失败'),
    `${failedRows.n} 行，覆盖 ${distinctActions.length} 类动作：${distinctActions.slice(0, 5).join(' / ')}`)

  // ---- 重置筛选：确认删掉那个按钮没影响这个入口 ----
  const reset = await evalJs(c, `
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set
    const actSel = [...document.querySelectorAll('select')].find(s =>
      [...s.options].some(o => o.value === 'AUDIT_QUERY'))
    if (actSel) {
      setter.call(actSel, 'AUDIT_QUERY')
      actSel.dispatchEvent(new Event('change', { bubbles: true }))
    }
    await new Promise(r => setTimeout(r, 2500))
    const before = actSel ? actSel.value : null
    const btn = [...document.querySelectorAll('button')].find(b => /重置筛选/.test(b.textContent))
    if (!btn) return { ok: false, why: '未找到重置筛选按钮', before }
    btn.click()
    await new Promise(r => setTimeout(r, 2500))
    return { ok: true, before, after: actSel ? actSel.value : null }
  `)
  check('「重置筛选」仍能把查询条件恢复默认',
    reset.ok === true && reset.before === 'AUDIT_QUERY' && reset.after === 'all',
    JSON.stringify(reset))

  c.close()
  console.log('\n' + '='.repeat(60))
  console.log(`  界面验证：通过 ${pass.length} 项，失败 ${fail.length} 项`)
  if (fail.length) {
    console.log('  失败清单：')
    fail.forEach((f) => console.log('    - ' + f))
  }
  console.log('  结论：' + (fail.length ? 'FAIL ❌' : 'PASS ✅ 失败类事件仍可单独捞出，且旧入口已移除'))
  console.log('='.repeat(60))
  process.exit(fail.length ? 1 : 0)
}

main().catch((e) => {
  console.error('异常：', e.message)
  process.exit(2)
})
