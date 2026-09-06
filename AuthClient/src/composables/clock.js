import { ref } from 'vue'

/**
 * 全局共享的 1 秒心跳。
 * 用于：锁定倒计时、状态栏时钟、审计日志相对时间。
 * 单一 interval 服务所有消费者，避免每个组件各自起定时器。
 */
export const now = ref(Date.now())

setInterval(() => {
  now.value = Date.now()
}, 1000)
