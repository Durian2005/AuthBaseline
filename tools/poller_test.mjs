// 轮询器语义回归：验证 composables/poller.js 的 createPoller 行为。
//
// 为什么需要一个 JS 侧的测试：四个轮询点里**有三个跑在审计管理员角色下**，
// 而审计管理员的登录口令不在自动化脚本掌握范围内 —— 界面级验证覆盖不到它们。
// 这个测试直接对工厂函数做单元级断言，把"门禁 / 可见性 / 重复启动 / 立即执行 /
// 错误吞没"这些容易在重构中走样的语义固定下来。
//
// 用法：node tools/poller_test.mjs      （退出码 0 = 全部通过）
//
// 直接验证 createPoller 的语义（不依赖 Vue / 浏览器）
import { createPoller } from '../AuthClient/src/composables/poller.js'

let pass = 0, fail = 0
const ok = (n, c, x) => { c ? pass++ : fail++; console.log('  [' + (c ? 'OK  ' : 'FAIL') + '] ' + n + (x ? '  — ' + x : '')) }

// —— 可控的假 setInterval / document ——
let intervals = []
const realSetInterval = globalThis.setInterval
const realClearInterval = globalThis.clearInterval
globalThis.setInterval = (fn, ms) => { const id = { fn, ms }; intervals.push(id); return id }
globalThis.clearInterval = (id) => { intervals = intervals.filter(i => i !== id) }
globalThis.document = { visibilityState: 'visible' }
const tick = () => intervals.forEach(i => i.fn())

console.log('='.repeat(60))
console.log('  createPoller 语义验证')
console.log('='.repeat(60))

// 1) 门禁不通过 → 完全不起定时器
let runs = 0
const p1 = createPoller({ name: 'g', guard: () => false, task: () => { runs++ }, intervalMs: 1000 })
p1.start()
ok('门禁不通过时不起定时器', intervals.length === 0 && runs === 0, 'timers=' + intervals.length)

// 2) 门禁通过 → 起一个定时器，周期正确
const p2 = createPoller({ name: 'a', guard: () => true, task: () => { runs++ }, intervalMs: 20000 })
p2.start()
ok('门禁通过后起 1 个定时器', intervals.length === 1)
ok('周期与传入一致 (20000)', intervals[0].ms === 20000, 'ms=' + intervals[0].ms)

// 3) 重复 start 不叠加（先 stop 再 start）
p2.start(); p2.start()
ok('重复 start 不叠加定时器', intervals.length === 1, 'timers=' + intervals.length)

// 4) 页面不可见 → 跳过
runs = 0
globalThis.document.visibilityState = 'hidden'
tick()
ok('不可见时跳过调用', runs === 0, 'runs=' + runs)

// 5) 可见 → 正常调用
globalThis.document.visibilityState = 'visible'
tick()
ok('可见时正常调用', runs === 1, 'runs=' + runs)

// 6) stop 后清空
p2.stop()
ok('stop 后无定时器', intervals.length === 0)

// 7) immediate：立即跑一次，且【不受可见性限制】
runs = 0
globalThis.document.visibilityState = 'hidden'
const p3 = createPoller({ name: 'i', guard: () => true, task: () => { runs++ }, intervalMs: 10000, immediate: true })
p3.start()
ok('immediate 立即触发一次（即使页面不可见）', runs === 1, 'runs=' + runs)
globalThis.document.visibilityState = 'visible'
p3.stop()

// 8) 非 immediate 不会立即触发
runs = 0
const p4 = createPoller({ name: 'n', guard: () => true, task: () => { runs++ }, intervalMs: 1000 })
p4.start()
ok('非 immediate 不立即触发', runs === 0, 'runs=' + runs)
p4.stop()

// 9) swallowError 吞掉 Promise 拒绝
let unhandled = null
process.removeAllListeners('unhandledRejection')
process.on('unhandledRejection', e => { unhandled = e })
const p5 = createPoller({
  name: 's', guard: () => true, task: () => Promise.reject(new Error('boom')),
  intervalMs: 1000, swallowError: true,
})
p5.start(); tick(); p5.stop()
await new Promise(r => setTimeout(r, 50))
ok('swallowError=true 时拒绝被吞', unhandled === null, unhandled ? 'unhandled=' + unhandled.message : '')

// 10) swallowError=false 时拒绝会冒泡（对照组）
unhandled = null
const p6 = createPoller({
  name: 's2', guard: () => true, task: () => Promise.reject(new Error('boom2')),
  intervalMs: 1000, swallowError: false,
})
p6.start(); tick(); p6.stop()
await new Promise(r => setTimeout(r, 50))
ok('swallowError=false 时拒绝会冒泡（对照）', unhandled !== null, unhandled ? unhandled.message : '未冒泡')

// 11) running 反映状态
const p7 = createPoller({ name: 'r', guard: () => true, task: () => {}, intervalMs: 1000 })
ok('未启动时 running=false', p7.running === false)
p7.start(); ok('启动后 running=true', p7.running === true)
p7.stop(); ok('停止后 running=false', p7.running === false)

// 12) 无 guard 时视为"始终允许"（不传 guard 不应崩）
runs = 0
const p8 = createPoller({ name: 'ng', task: () => { runs++ }, intervalMs: 1000 })
p8.start(); tick(); p8.stop()
ok('不传 guard 也能正常工作', runs === 1, 'runs=' + runs)

globalThis.setInterval = realSetInterval
globalThis.clearInterval = realClearInterval

const verdict = fail ? 'FAIL' : 'PASS'
console.log('='.repeat(60))
console.log('  通过 ' + pass + ' 项，失败 ' + fail + ' 项')
console.log('  结论：' + verdict + (fail ? '' : ' ✅ 轮询器语义与原实现逐条一致'))
console.log('='.repeat(60))
process.exit(fail ? 1 : 0)
