<script setup>
import { computed, onMounted, ref } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import PasswordField from '../components/PasswordField.vue'
import PasswordRules from '../components/PasswordRules.vue'
import Spinner from '../components/Spinner.vue'
import StatusBadge from '../components/StatusBadge.vue'
import FaceCapturePanel from '../components/face/FaceCapturePanel.vue'
import { useSessionStore } from '../stores/session'
import { useToastStore } from '../stores/toast'
import { ApiError } from '../api/client'
import { isPasswordStrong } from '../utils/password'
import { formatDateTime, formatDuration } from '../utils/format'

const session = useSessionStore()
const toast = useToastStore()

const form = ref({ old: '', next: '', confirm: '' })
const touched = ref(false)
const formError = ref('')

const errors = computed(() => {
  const f = form.value
  return {
    old: !f.old ? '请输入当前密码' : '',
    next: !f.next
      ? '请输入新密码'
      : !isPasswordStrong(f.next)
        ? '新口令复杂度不满足要求'
        : f.next === f.old
          ? '新密码不能与旧密码相同'
          : '',
    confirm: f.confirm !== f.next ? '两次输入的新密码不一致' : ''
  }
})

/**
 * 是否允许提交到后端。
 *
 * 刻意**不**把 isPasswordStrong 放进这个门禁 —— 复杂度由服务端裁决。
 *
 * 原先这里是本地拦截：口令不合规时按钮直接禁用、请求根本不发。
 * 后果是"改密失败"这件事在审计日志里彻底看不到 —— 本地拦下的尝试
 * 后端毫不知情，而"某人反复尝试把口令设成弱口令"恰恰是需要留痕的
 * 安全事件（口令策略被试探、或被诱导着设弱口令）。
 *
 * 现在的分工：
 *   · 本地只做**提示**（PasswordRules 实时显示哪条未满足、错误文案照样红字标出），
 *     用户不需要来回试错就能改对；
 *   · 判定权交给服务端，失败会被记入 CHANGE_PASSWORD_FAILED，
 *     并带 WEAK_PASSWORD / PASSWORD_REUSED 等原因码，可被单独检索。
 */
const canSubmit = computed(
  () => !!form.value.old && !!form.value.next && !!form.value.confirm
)

async function submit() {
  touched.value = true
  formError.value = ''
  if (!canSubmit.value) return

  // 本地已能确定的问题（两次不一致）先拦下：这类是界面输入错误，
  // 与口令策略无关，发到后端只会产生无意义的审计噪声。
  if (form.value.confirm !== form.value.next) return

  try {
    const res = await session.changePassword(form.value.old, form.value.next)
    toast.success(res?.message || '密码修改成功')
    form.value = { old: '', next: '', confirm: '' }
    touched.value = false
    // 与后端语义保持一致：口令已变更，旧会话需重新认证
    await new Promise((r) => setTimeout(r, 600))
    session.logout({ silent: true })
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    formError.value = e.message
  }
}

/* ==================== 刷脸登录（可选第二因子） ====================
 *
 * 交互形状是三个状态的小状态机，而不是一个"点一下就好"的按钮，
 * 因为这条路**每一步都有安全含义**：
 *
 *   idle     ── 展示状态；两个入口都要先输当前口令
 *   enroll   ── 输口令（服务端验）→ 换一张动作挑战
 *   capture  ── 按服务端下发的动作做，然后由服务端采集一帧
 *   delete   ── 输口令 + 二次确认。这是**降级**动作，必须比录入更慎重
 *
 * 口令一律交给后端判定，前端不做任何本地校验 ——
 * 与"改密"那条路径保持同一套口径（本地只提示，裁决权在服务端，
 * 失败会留下 FACE_WRONG_PASSWORD 审计并可被锁定策略累计）。
 */
const faceMode = ref('idle')
const facePw = ref('')
const faceError = ref('')
const faceNotice = ref('')

const faceStatus = computed(() => session.faceStatus)

async function loadFace() {
  faceError.value = ''
  try {
    await session.refreshFaceStatus()
  } catch (err) {
    // 拉不到状态不该打断整个账号页：只在人脸卡片里显示一行错误。
    faceError.value = err instanceof ApiError ? err.message : '加载人脸状态失败'
  }
}

onMounted(loadFace)

function startFaceEnroll() {
  faceMode.value = 'enroll'
  facePw.value = ''
  faceError.value = ''
  faceNotice.value = ''
}

function startFaceDelete() {
  faceMode.value = 'delete'
  facePw.value = ''
  faceError.value = ''
  faceNotice.value = ''
}

function cancelFaceFlow() {
  if (faceMode.value === 'capture') session.cancelFaceEnroll()
  faceMode.value = 'idle'
  facePw.value = ''
  faceError.value = ''
}

/** 第一步：用当前口令换一张动作挑战。口令错会被服务端拒绝并计次。 */
async function submitFacePassword() {
  faceError.value = ''
  if (!facePw.value) {
    faceError.value = '请输入当前登录口令'
    return
  }

  if (faceMode.value === 'delete') {
    try {
      const res = await session.faceDelete(facePw.value)
      facePw.value = ''
      faceMode.value = 'idle'
      faceNotice.value = res?.message || '已删除人脸模板'
      toast.success('已删除人脸模板，该账号不再需要刷脸登录')
    } catch (err) {
      faceError.value = err instanceof ApiError ? err.message : '删除人脸失败'
    }
    return
  }

  try {
    await session.faceEnrollStart(facePw.value)
    facePw.value = ''
    faceMode.value = 'capture'
  } catch (err) {
    faceError.value = err instanceof ApiError ? err.message : '口令校验失败'
  }
}

/** 第二步：提交挑战 —— 后端自己开摄像头采集，这里只递一张票。 */
async function runFaceCapture() {
  faceError.value = ''
  try {
    const res = await session.faceEnrollComplete()
    faceMode.value = 'idle'
    faceNotice.value = res?.message || '已录入人脸'
    toast.success('已录入人脸，下次登录需要刷脸')
  } catch (err) {
    faceError.value = err instanceof ApiError ? err.message : '录入失败'
    // 挑战是一次性的（提交过即作废）⇒ 无论成败都退回 idle 重新来过
    faceMode.value = 'idle'
  }
}
</script>

<template>
  <div class="page">
    <header class="head">
      <div>
        <h2 class="head__title">账号与口令</h2>
        <p class="head__sub">修改口令后，旧口令立即失效，需要重新登录。</p>
      </div>
    </header>

    <div class="cols">
      <!-- 修改口令 -->
      <section class="panel">
        <div class="panel__head">
          <h3 class="panel__title"><AppIcon name="key" :size="15" /><span>修改密码</span></h3>
        </div>

        <div class="panel__body">
          <form class="stack" novalidate @submit.prevent="submit">
            <div v-if="formError" class="alert" role="alert">
              <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
              <span class="selectable">{{ formError }}</span>
            </div>

            <PasswordField
              v-model="form.old"
              label="当前密码"
              placeholder="请输入当前使用的密码"
              autocomplete="off"
              :invalid="touched && !!errors.old"
              :error="touched ? errors.old : ''"
              autofocus
            />

            <hr class="divider" />

            <PasswordField
              v-model="form.next"
              label="新密码"
              placeholder="设置新的登录密码"
              autocomplete="new-password"
              :invalid="touched && !!errors.next"
              :error="touched ? errors.next : ''"
            />

            <PasswordRules :value="form.next" />

            <PasswordField
              v-model="form.confirm"
              label="确认新密码"
              placeholder="再次输入新密码"
              autocomplete="new-password"
              :invalid="touched && !!errors.confirm"
              :error="touched ? errors.confirm : ''"
              @enter="submit"
            />

            <div class="actions">
              <button type="submit" class="btn btn--primary" :disabled="session.submitting">
                <Spinner v-if="session.submitting" :size="14" />
                <AppIcon v-else name="check-circle" :size="15" />
                <span>确认修改</span>
              </button>
              <button
                type="button"
                class="btn btn--ghost"
                @click="form = { old: '', next: '', confirm: '' }; touched = false; formError = ''"
              >
                清空
              </button>
            </div>
          </form>
        </div>
      </section>

      <!-- 账号状态 -->
      <section class="panel">
        <div class="panel__head">
          <h3 class="panel__title"><AppIcon name="shield" :size="15" /><span>安全状态</span></h3>
        </div>

        <div class="panel__body sec">
          <div class="sec__row">
            <span class="sec__label">登录账号</span>
            <span class="sec__value selectable">{{ session.currentUser?.username }}</span>
          </div>
          <div class="sec__row">
            <span class="sec__label">账号状态</span>
            <StatusBadge :status="session.status" />
          </div>
          <div class="sec__row">
            <span class="sec__label">口令存储</span>
            <span class="sec__value">BCrypt 哈希（不存明文）</span>
          </div>
          <div class="sec__row">
            <span class="sec__label">锁定阈值</span>
            <span class="sec__value">连续 3 次错误 / 锁定 {{ formatDuration(180) }}</span>
          </div>

          <hr class="divider" />

          <ul class="tips">
            <li><AppIcon name="check-circle" :size="13" />口令至少 8 位，含大小写字母与数字</li>
            <li><AppIcon name="check-circle" :size="13" />不要与其他站点复用同一口令</li>
            <li><AppIcon name="check-circle" :size="13" />所有口令操作均记入审计日志</li>
          </ul>
        </div>
      </section>

      <!-- 刷脸登录（可选第二因子） -->
      <section class="panel">
        <div class="panel__head">
          <h3 class="panel__title"><AppIcon name="face" :size="15" /><span>刷脸登录</span></h3>
          <span class="pill">可选</span>
        </div>

        <div class="panel__body sec">
          <div v-if="faceError" class="alert" role="alert">
            <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
            <span class="selectable">{{ faceError }}</span>
          </div>
          <div v-else-if="faceNotice" class="notice" role="status">
            <AppIcon name="check-circle" :size="15" />
            <span>{{ faceNotice }}</span>
          </div>

          <!-- 采集进行中：动作由服务端随机下发，客户端无法指定 -->
          <FaceCapturePanel
            v-if="faceMode === 'capture'"
            compact
            :action="session.faceChallenge?.action"
            :action-text="session.faceChallenge?.actionText"
            :action-hint="session.faceChallenge?.actionHint"
            :busy="session.faceBusy"
            confirm-text="开始采集"
            @capture="runFaceCapture"
            @cancel="cancelFaceFlow"
          />

          <!-- 二次口令：录入与删除共用同一段，但措辞与按钮色调刻意不同 -->
          <template v-else-if="faceMode === 'enroll' || faceMode === 'delete'">
            <p class="hint">
              <template v-if="faceMode === 'delete'">
                删除后将退回<strong>只用口令登录</strong>。人脸是第二因子，拿掉它等于降低这个账号的强度，
                因此需要重新输入当前口令确认。
              </template>
              <template v-else>
                录入前需要重新输入当前口令 —— 这道闸门是必需的：否则拿到一个已登录会话的人，
                就能把自己的脸加进来，第二因子会被完整绕开。
              </template>
            </p>
            <PasswordField
              v-model="facePw"
              label="当前登录口令"
              placeholder="请输入当前使用的密码"
              autocomplete="off"
              autofocus
              @enter="submitFacePassword"
            />
            <div class="actions">
              <button
                type="button"
                class="btn"
                :class="faceMode === 'delete' ? 'btn--danger' : 'btn--primary'"
                @click="submitFacePassword"
              >
                <AppIcon :name="faceMode === 'delete' ? 'trash' : 'face'" :size="15" />
                <span>{{ faceMode === 'delete' ? '确认删除' : '验证并开始采集' }}</span>
              </button>
              <button type="button" class="btn btn--ghost" @click="cancelFaceFlow">取消</button>
            </div>
          </template>

          <!-- 空闲：状态 + 入口 -->
          <template v-else>
            <div class="sec__row">
              <span class="sec__label">刷脸登录</span>
              <span class="sec__value">
                <span class="dot" :class="faceStatus?.enrolled ? 'dot--on' : 'dot--off'" />
                {{ faceStatus?.enrolled ? `已启用 · ${faceStatus.templateCount} 张模板` : '未启用' }}
              </span>
            </div>
            <div class="sec__row">
              <span class="sec__label">最近录入</span>
              <span class="sec__value">
                {{ faceStatus?.enrolledAt ? formatDateTime(faceStatus.enrolledAt) : '—' }}
              </span>
            </div>
            <div class="sec__row">
              <span class="sec__label">判定阈值</span>
              <span class="sec__value">
                余弦相似度 ≥ {{ faceStatus?.threshold != null ? faceStatus.threshold.toFixed(2) : '—' }}
              </span>
            </div>
            <div class="sec__row">
              <span class="sec__label">本机引擎</span>
              <span class="sec__value">
                {{ faceStatus?.engineReady ? '可用' : faceStatus?.engineMessage || '未知' }}
              </span>
            </div>

            <hr class="divider" />

            <p class="hint">
              刷脸是<strong>第二因子</strong>：启用后光有口令还不能登录，必须再通过一次人脸验证。
              不录入人脸则完全按原来的口令登录，不受任何影响；管理类账号默认都不启用。
            </p>

            <div class="actions">
              <button
                v-if="faceStatus?.engineReady"
                type="button"
                class="btn btn--primary"
                @click="startFaceEnroll"
              >
                <AppIcon name="face" :size="15" />
                <span>{{ faceStatus?.enrolled ? '追加人脸' : '录入人脸' }}</span>
              </button>
              <button
                v-if="faceStatus?.enrolled"
                type="button"
                class="btn btn--danger"
                @click="startFaceDelete"
              >
                <AppIcon name="trash" :size="15" />
                <span>删除人脸</span>
              </button>
              <span v-if="faceStatus && !faceStatus.engineReady" class="hint hint--inline">
                本机没有可用摄像头 / 模型，暂时无法录入
              </span>
            </div>
          </template>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: var(--sp-4);
  max-width: 980px;
}

.head__title {
  font-size: var(--fs-xl);
  font-weight: 650;
  color: var(--c-text);
}
.head__sub {
  margin-top: var(--sp-2);
  font-size: var(--fs-sm);
  color: var(--c-text-muted);
}

.cols {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: var(--sp-3);
  align-items: start;
}

.stack {
  display: flex;
  flex-direction: column;
  gap: var(--sp-4);
}

.actions {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
}

.alert {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  padding: var(--sp-2) var(--sp-3);
  border-radius: var(--r-md);
  border: 1px solid color-mix(in srgb, var(--c-danger) 30%, transparent);
  background: var(--c-danger-soft);
  color: var(--c-text);
  font-size: var(--fs-sm);
  line-height: 1.5;
}
.alert > svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--c-danger);
}

.sec {
  display: flex;
  flex-direction: column;
  gap: var(--sp-3);
}

.sec__row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-3);
  font-size: var(--fs-base);
}
.sec__label {
  color: var(--c-text-muted);
}
.sec__value {
  color: var(--c-text);
  text-align: right;
  word-break: break-all;
}

.tips {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
  margin: 0;
  padding: 0;
  list-style: none;
}
.tips li {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  font-size: var(--fs-sm);
  line-height: 1.5;
  color: var(--c-text-muted);
}
.tips svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--st-enabled-fg);
}

/* ---------- 刷脸登录卡片 ---------- */

/* 「可选」徽记：这三个字是这块卡片最重要的口径 ——
   刷脸不是强制的（不录入完全不影响登录），界面必须自己说清楚，
   否则很容易被读成"系统启用了双因子认证"。 */
.pill {
  padding: 1px var(--sp-2);
  border: 1px solid var(--c-border-strong);
  border-radius: var(--r-full);
  background: var(--c-surface-2);
  color: var(--c-text-muted);
  font-size: var(--fs-xs);
  line-height: 1.6;
}

.hint {
  font-size: var(--fs-sm);
  line-height: 1.6;
  color: var(--c-text-muted);
}
.hint strong {
  color: var(--c-text);
  font-weight: 600;
}
.hint--inline {
  color: var(--c-text-subtle);
}

.notice {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  padding: var(--sp-2) var(--sp-3);
  border-radius: var(--r-md);
  border: 1px solid color-mix(in srgb, var(--st-enabled-fg) 30%, transparent);
  background: var(--st-enabled-bg);
  color: var(--c-text);
  font-size: var(--fs-sm);
  line-height: 1.5;
}
.notice > svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--st-enabled-fg);
}

/* 状态圆点：与 StatusBadge 不同，这里只是一行文字里的轻量提示，
   不做成徽章，免得跟"账号状态"那个徽章抢注意力。 */
.dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  margin-right: var(--sp-2);
  border-radius: var(--r-full);
  vertical-align: middle;
}
.dot--on {
  background: var(--st-enabled-fg);
}
.dot--off {
  background: var(--c-text-subtle);
  opacity: 0.7;
}
</style>
