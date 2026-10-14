import { ref } from 'vue'
import { api } from '../../api/client'

/**
 * 人脸（可选第二因子）自助域：状态查询、录入两步、删除。
 *
 * 为什么单独成域、而不是塞进 session 或 admin：
 *   它的**权限边界**与两者都不同 —— 不要求任何管理角色，只要求"本人已登录"，
 *   而且后端用票据判定"本人是谁"（请求体里连用户名都没有）。
 *   放进 adminDomain 会让"用户管理"这一域凭空多出一个不受 isAdmin 守卫的动作；
 *   放进 session 又会把三段式录入的状态机混进会话核心。
 *
 * ⚠️ 与其它两个域一样，本模块只返回一组 ref / 函数，由 stores/session.js 组装。
 *    区别是它**刻意不带轮询**：人脸状态只在登录后与操作后各拉一次就够，
 *    定时去问一个几乎不变的值纯属浪费（登录第二因子那一侧才需要实时性）。
 *
 * @param {object} core 共享上下文：{ markOnline, fail }
 */
export function useFaceDomain(core) {
  const { markOnline, fail } = core

  /** 本人人脸状态：`{ enrolled, templateCount, enrolledAt, threshold, engineReady, engineMessage }` */
  const status = ref(null)
  const loading = ref(false)

  /** 录入 / 删除进行中（这两个动作都要开摄像头，界面必须在此期间锁住按钮） */
  const busy = ref(false)

  /**
   * 录入用的动作挑战。非 null 表示"正处在录入的第二步"。
   * 只存录像所需的指令文本与 token —— 里面没有任何画面或特征。
   */
  const challenge = ref(null)

  async function refreshStatus() {
    loading.value = true
    try {
      const res = await api.faceStatus()
      status.value = res.data ?? null
      markOnline()
      return status.value
    } catch (err) {
      status.value = null
      throw fail(err, '加载人脸状态失败')
    } finally {
      loading.value = false
    }
  }

  /**
   * 录入第一步：用当前口令换一张动作挑战。
   * 口令由**后端**校验 —— 前端不做任何本地判定，失败原因（含计次结果）以服务端为准。
   */
  async function startEnroll(password) {
    const res = await api.faceEnrollStart(password)
    challenge.value = res.data ?? null
    markOnline()
    return challenge.value
  }

  /** 录入第二步：提交挑战。画面由服务端自己采，这里只递一张票。 */
  async function completeEnroll() {
    if (!challenge.value?.challengeToken) {
      throw fail(new Error('没有待完成的录入挑战'), '录入失败')
    }
    busy.value = true
    try {
      const res = await api.faceEnrollComplete(challenge.value.challengeToken)
      // 无论成败都作废本地那张挑战：它已在服务端被消费（一次性），留着只会误导界面
      challenge.value = null
      await refreshStatus()
      return res
    } catch (err) {
      challenge.value = null
      throw fail(err, '录入失败')
    } finally {
      busy.value = false
    }
  }

  /** 删除本人全部模板（需当前口令）。 */
  async function remove(password) {
    busy.value = true
    try {
      const res = await api.faceDelete(password)
      await refreshStatus()
      return res
    } catch (err) {
      throw fail(err, '删除人脸失败')
    } finally {
      busy.value = false
    }
  }

  /** 放弃本次录入（用户关掉面板 / 点了取消）。同时**作废服务端那张挑战**由 TTL 兜底。 */
  function cancelEnroll() {
    challenge.value = null
  }

  /** 登出时清空本域状态。 */
  function reset() {
    status.value = null
    challenge.value = null
    busy.value = false
  }

  return {
    status,
    loading,
    busy,
    challenge,
    refreshStatus,
    startEnroll,
    completeEnroll,
    remove,
    cancelEnroll,
    reset
  }
}
