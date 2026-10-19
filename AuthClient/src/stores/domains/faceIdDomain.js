import { ref } from 'vue'
import { api } from '../../api/client'

/**
 * 纯人脸登录（FaceId）自助域：状态查询、录入、删除。
 *
 * 为什么单独成域，而不是塞进 faceDomain（第二因子）：
 *   两者路由不同、权限边界相同但**语义不同**：
 *     · faceDomain 是"口令之后的第二因子"，界面是一套动作挑战的状态机；
 *     · 本域是"用户名 + 人脸"这条独立登录方式的开关，没有挑战、没有预览，
 *       只有"录 / 删 / 看状态"三个动作。
 *   合成一个域会让 `faceBusy` 同时代表"正在做动作挑战"和"正在录入 FaceId"，
 *   两处代码迟早互相误判。
 *
 * 与其它域一样：只返回 ref + 函数，由 stores/session.js 组装。
 * 也刻意**不带轮询** —— 这些值几乎不变，只在登录后与操作后各拉一次。
 *
 * @param {object} core 共享上下文：{ markOnline, fail }
 */
export function useFaceIdDomain(core) {
  const { markOnline, fail } = core

  /**
   * 本人 FaceId 状态：
   * `{ enabled, enrolled, templateCount, usableCount, modelMismatchCount,
   *    enrolledAt, maxTemplates, threshold, modelId, engineReady, engineMessage }`
   */
  const faceIdStatus = ref(null)
  const faceIdLoading = ref(false)

  /** 录入 / 删除进行中（都会开摄像头，界面必须在此期间锁住按钮） */
  const faceIdBusy = ref(false)

  async function refreshFaceIdStatus() {
    faceIdLoading.value = true
    try {
      const res = await api.faceIdStatus()
      faceIdStatus.value = res.data ?? null
      markOnline()
      return faceIdStatus.value
    } catch (err) {
      // 拉不到状态不该打断整个账号页：卡片里显示一行错误即可。
      faceIdStatus.value = null
      throw fail(err, '加载纯人脸登录状态失败')
    } finally {
      faceIdLoading.value = false
    }
  }

  /**
   * 录入 / 追加一张模板（需当前口令）。
   *
   * 口令由**后端**校验，前端不做任何本地判定 —— 失败原因（含是否计次、
   * 是否触发锁定）一律以服务端为准，与改密、2FA 录入保持同一套口径。
   */
  async function enrollFaceId(password) {
    faceIdBusy.value = true
    try {
      const res = await api.faceIdEnroll(password)
      await refreshFaceIdStatus()
      return res
    } catch (err) {
      // 失败后也刷一次状态：口令错会累计失败次数，界面要能显示"还剩几次"的口径
      // 由后端决定，前端不猜。
      try {
        await refreshFaceIdStatus()
      } catch {
        /* 状态刷新失败不掩盖真正的录入错误 */
      }
      throw fail(err, '录入人脸失败')
    } finally {
      faceIdBusy.value = false
    }
  }

  /** 删除本人全部 FaceId 模板（需当前口令）。 */
  async function removeFaceId(password) {
    faceIdBusy.value = true
    try {
      const res = await api.faceIdDelete(password)
      await refreshFaceIdStatus()
      return res
    } catch (err) {
      throw fail(err, '删除人脸失败')
    } finally {
      faceIdBusy.value = false
    }
  }

  /** 登出时清空本域状态。 */
  function reset() {
    faceIdStatus.value = null
    faceIdBusy.value = false
  }

  return {
    faceIdStatus,
    faceIdLoading,
    faceIdBusy,
    refreshFaceIdStatus,
    enrollFaceId,
    removeFaceId,
    reset
  }
}
