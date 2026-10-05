/**
 * 轮询器工厂 —— 把"清旧定时器 → 角色门禁 → 可见性检查 → setInterval"
 * 这套在每个轮询点都要重写一遍的样板收敛到一处。
 *
 * 为什么是工厂函数而不是 `useXxx()` 组合式函数
 * ============================================
 * `use*()` 的约定是"依赖组件实例"（内部用 `onMounted`/`onUnmounted` 管生命周期）。
 * 但本项目的四个轮询点全都挂在 **Pinia store 的 setup 里**，store 只初始化一次、
 * 没有组件实例可依附，`onUnmounted` 永远不会触发 —— 套用 `use*()` 命名只会
 * 误导读者以为"组件卸载时会自动清理"。所以这里用中性的 `createPoller`。
 *
 * 三个必须保持一致的行为（改这里之前先想清楚）
 * ============================================
 * 1. **先 stop 再 start**：重复调用 start 不能叠加出两个定时器。
 * 2. **角色门禁不通过就整个不起定时器**，而不是"起了但每次都跳过"——
 *    后者仍会周期性唤醒事件循环，且在角色切换的瞬间可能漏放一次请求。
 * 3. **页面不可见时跳过**：后台标签页/最小化窗口不产生网络请求。
 *    但 `immediate` 的首次调用**不受此限制** —— 它发生在用户刚登录/刚恢复会话时，
 *    页面必然是可见的，加限制只会让首次数据延迟一整个周期。
 */
export function createPoller({ name, guard, task, intervalMs, immediate = false, swallowError = false }) {
  let timer = null

  /**
   * 真正的调用点。`swallowError` 用于"后台巡检"这类场景：
   * 网络抖一下不该弹错误框打断用户 —— 但**不能吞掉所有异常**，
   * 所以只对返回的 Promise 挂 catch，同步抛出的异常仍会冒泡（那是代码 bug）。
   */
  function invoke() {
    const result = task()
    if (swallowError && result && typeof result.catch === 'function') {
      result.catch(() => {})
    }
  }

  function tick() {
    if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return
    invoke()
  }

  function stop() {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  }

  function start() {
    stop()
    if (guard && !guard()) return
    if (immediate) invoke()
    timer = setInterval(tick, intervalMs)
  }

  return {
    start,
    stop,
    get running() {
      return timer !== null
    },
    name,
  }
}
