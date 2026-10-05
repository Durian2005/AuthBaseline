import { computed, ref } from 'vue'
import { now } from './clock'

export const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/
export const isEmail = (v) => EMAIL_RE.test(String(v || '').trim())

const emptyCodeState = () => ({ sentTo: '', resendAt: 0, hint: '' })

/**
 * 邮箱验证码状态机：发送结果 + 60 秒重发倒计时 + 给用户看的提示语。
 *
 * 为什么抽成 composable：注册与「忘记密码」两个表单都要这套逻辑，
 * 而它们的差异只有 purpose（REGISTER / RESET）与措辞。
 * 拆出表单组件后若各自复制一份，两处的倒计时口径与提示语会慢慢走样 ——
 * 这类"看起来一样、细节不同"的不一致，正是验收时最容易被追问的地方。
 *
 * 倒计时只记一个截止时刻、由全局心跳 `now` 驱动，不自建定时器 ——
 * 与项目里其它轮询/倒计时保持同一种做法。
 */
export function useEmailCode() {
  const state = ref(emptyCodeState())

  const remain = computed(() => {
    if (!state.value.resendAt) return 0
    return Math.max(0, Math.ceil((state.value.resendAt - now.value) / 1000))
  })

  /** 用后端返回的结果刷新状态（含"是否真的发了邮件"的降级提示）。 */
  function apply(res) {
    const d = res?.data ?? {}
    state.value = {
      sentTo: d.maskedEmail || '',
      resendAt: Date.now() + (Number(d.resendAfter) || 60) * 1000,
      hint:
        d.deliversRealMail === false
          ? '当前为控制台发件器，验证码请查看后端日志'
          : `验证码已发送至 ${d.maskedEmail || '您的邮箱'}，5 分钟内有效`
    }
  }

  function reset() {
    state.value = emptyCodeState()
  }

  return { state, remain, apply, reset }
}
