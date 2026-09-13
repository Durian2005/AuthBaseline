/**
 * 真实浏览器界面端到端验证（Edge 无头 + CDP）。
 *
 * 验证两条新流程在界面层是否真的可用：
 *   功能一 注册绑定邮箱：填邮箱 -> 获取验证码 -> 填码 -> 提交 -> 转待审核
 *   功能二 忘记密码：用户名+邮箱 -> 验证码 -> 设置新密码 -> 用新密码登录
 *
 * 驱动方式：Runtime.evaluate 注入 JS 操作 DOM / 触发 Vue 的 input 事件。
 */
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const CDP = 'http://127.0.0.1:9222'
const APP = 'http://localhost:5007/'
const LOG = path.join(os.tmpdir(), 'be.log')

const pass = []
const fail = []

function check(name, ok, detail = '') {
  ;(ok ? pass : fail).push(name)
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? '  -> ' + detail : ''}`)
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function codesInLog() {
  try {
    const txt = fs.readFileSync(LOG, 'utf8')
    return [...txt.matchAll(/:\s*(\d{6})\s*$/gm)].map((m) => m[1])
  } catch {
    return []
  }
}

async function waitNewCode(before, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const c = codesInLog()
    if (c.length > before) return c[c.length - 1]
    await sleep(200)
  }
  return null
}

async function connect() {
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`${CDP}/json/list`)
      const list = await res.json()
      const page = list.find((t) => t.type === 'page')
      if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl
    } catch {
      /* 浏览器还没起来 */
    }
    await sleep(500)
  }
  throw new Error('无法连接 Edge 调试端口 9222')
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

  /** 在页面里执行 JS，返回可序列化的结果 */
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

/** 注入的一组页面内操作工具 */
const HELPERS = `
  window.__t = {
    byText: (sel, text) => [...document.querySelectorAll(sel)].find(e => e.textContent.trim().includes(text)),
    set: (sel, val) => {
      const el = document.querySelector(sel)
      if (!el) throw new Error('找不到元素 ' + sel)
      const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')
      d.set.call(el, val)
      el.dispatchEvent(new Event('input', { bubbles: true }))
      el.dispatchEvent(new Event('change', { bubbles: true }))
    },
    click: (sel) => { const el = document.querySelector(sel); if (!el) throw new Error('找不到元素 ' + sel); el.click() },
    text: () => document.body.innerText.replace(/\\n{2,}/g, '\\n').trim()
  };
  return 'helpers ready'
`

async function main() {
  const wsUrl = await connect()
  const c = makeClient(wsUrl)
  await c.ready

  await c.send('Page.enable')
  await c.send('Runtime.enable')
  await c.send('Page.navigate', { url: APP })
  await sleep(2500)
  await c.js(HELPERS)

  const stamp = String(Date.now()).slice(-6)
  const user = `ui${stamp}`
  const email = `${user}@example.com`

  /** 截图留证 */
  async function shot(name) {
    const r = await c.send('Page.captureScreenshot', { format: 'png' })
    fs.writeFileSync(name, Buffer.from(r.data, 'base64'))
    console.log(`   截图：${name}`)
  }

  /* ---------------- 功能一：注册绑定邮箱 ---------------- */
  console.log('\n== 界面 · 功能一 注册绑定邮箱 ==')
  console.log(`   测试账号：${user} / ${email}`)

  await c.js(`__t.byText('.tab', '注册').click(); return 1`)
  await sleep(400)
  check(
    '切到注册页后出现邮箱与验证码输入框',
    (await c.js(`return !!document.querySelector('#reg-email') && !!document.querySelector('#reg-code')`)) === true
  )

  await c.js(`__t.set('#reg-username', ${JSON.stringify(user)}); __t.set('#reg-email', ${JSON.stringify(email)}); return 1`)
  const before = codesInLog().length
  await c.js(`__t.byText('button', '获取验证码').click(); return 1`)

  const code = await waitNewCode(before)
  check('点击"获取验证码"后后端生成验证码', !!code, String(code))

  await sleep(1600)
  const btnText = await c.js(`const b = __t.byText('button','s') || __t.byText('button','获取验证码'); return document.querySelectorAll('button')[1] ? [...document.querySelectorAll('button')].map(b=>b.textContent.trim()).join('|') : ''`)
  check('重发按钮进入 60 秒倒计时', /\d+s\|\d+s/.test(btnText) || /\d+s/.test(btnText), btnText.slice(0, 80))

  await c.js(`
    __t.set('#reg-code', ${JSON.stringify(code || '000000')});
    __t.set('#reg-username', ${JSON.stringify(user)});
    return 1
  `)
  await c.js(`
    const inputs = [...document.querySelectorAll('input[type=password]')];
    __t.set('#' + inputs[0].id, 'Passw0rdX');
    __t.set('#' + inputs[1].id, 'Passw0rdX');
    return 1
  `)
  await sleep(200)
  await shot('ui_register_form.png')
  await c.js(`__t.byText('button', '提交注册').click(); return 1`)
  await sleep(1800)

  let body = await c.js(`return __t.text()`)
  check('注册成功后回到登录页', body.includes('登录') && !body.includes('提交注册'), body.slice(0, 60).replace(/\n/g, ' / '))
  check('提示注册成功等待审核', body.includes('注册成功') || body.includes('等待管理员审核'), body.slice(0, 120).replace(/\n/g, ' / '))

  /* ---------------- 审核通过，便于测试找回密码 ---------------- */
  const approve = await fetch('http://localhost:5007/api/auth/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, adminUsername: 'admin' })
  }).then((r) => r.json())
  check('管理员审核通过（准备找回密码场景）', approve.success === true, approve.message)

  /* ---------------- 功能二：忘记密码 ---------------- */
  console.log('\n== 界面 · 功能二 忘记密码 ==')

  await c.js(`__t.byText('button', '忘记密码').click(); return 1`)
  await sleep(400)
  check(
    '进入找回密码面板',
    (await c.js(`return !!document.querySelector('#reset-username') && !!document.querySelector('#reset-email') && !!document.querySelector('#reset-code')`)) === true
  )

  await c.js(`__t.set('#reset-username', ${JSON.stringify(user)}); __t.set('#reset-email', ${JSON.stringify(email)}); return 1`)
  const before2 = codesInLog().length
  await c.js(`__t.byText('button', '获取验证码').click(); return 1`)
  const code2 = await waitNewCode(before2)
  check('找回密码可获取验证码', !!code2, String(code2))

  await c.js(`__t.set('#reset-code', ${JSON.stringify(code2 || '000000')}); return 1`)
  await c.js(`
    const inputs = [...document.querySelectorAll('input[type=password]')];
    __t.set('#' + inputs[0].id, 'NewPassw0rd');
    __t.set('#' + inputs[1].id, 'NewPassw0rd');
    return 1
  `)
  await sleep(200)
  await shot('ui_reset_form.png')
  await c.js(`__t.byText('button', '重置密码').click(); return 1`)
  await sleep(1800)

  body = await c.js(`return __t.text()`)
  check('重置成功后回到登录页', body.includes('忘记密码？'), body.slice(0, 80).replace(/\n/g, ' / '))
  check('提示密码已重置', body.includes('密码已重置'), body.slice(0, 120).replace(/\n/g, ' / '))

  /* ---------------- 用新密码登录 ---------------- */
  await c.js(`__t.set('#login-username', ${JSON.stringify(user)}); return 1`)
  await c.js(`
    const inputs = [...document.querySelectorAll('input[type=password]')];
    __t.set('#' + inputs[0].id, 'NewPassw0rd');
    return 1
  `)
  await sleep(200)
  // 注意：必须点表单的提交按钮 —— 顶部还有个叫"登录"的 tab，
  // 用文本模糊匹配会误点到 tab，导致"看起来点了登录其实没提交"。
  await c.js(`__t.click('form button[type=submit]'); return 1`)
  await sleep(2500)

  body = await c.js(`return __t.text()`)
  check(
    '用重置后的新密码可登录进主界面',
    !body.includes('忘记密码？') && body.length > 0,
    body.slice(0, 110).replace(/\n/g, ' / ')
  )

  // 截图留证
  await shot(process.argv[2] || 'ui_shot.png')

  c.close()
}

main()
  .then(() => {
    console.log(`\n${'='.repeat(46)}`)
    console.log(`通过 ${pass.length} 项，失败 ${fail.length} 项`)
    if (fail.length) {
      console.log('失败项：')
      fail.forEach((f) => console.log('  -', f))
    }
    console.log('='.repeat(46))
    process.exit(fail.length ? 1 : 0)
  })
  .catch((e) => {
    console.error('执行失败：', e.message)
    process.exit(1)
  })
