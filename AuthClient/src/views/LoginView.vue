<script setup>
import { computed, ref } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import PasswordField from '../components/PasswordField.vue'
import Spinner from '../components/Spinner.vue'
import RegisterForm from '../components/auth/RegisterForm.vue'
import ResetPasswordForm from '../components/auth/ResetPasswordForm.vue'
import FaceCapturePanel from '../components/face/FaceCapturePanel.vue'
import { useSessionStore } from '../stores/session'
import { useToastStore } from '../stores/toast'
import { ApiError } from '../api/client'
import { formatDuration } from '../utils/format'
import { now } from '../composables/clock'

const session = useSessionStore()
const toast = useToastStore()

/** 'login' | 'register' | 'reset' */
const tab = ref('login')
const formError = ref('')
const lockNotice = ref(null) // { lockoutEnd } —— 由后端返回的锁定截止时刻驱动倒计时

/** 锁定剩余秒数，随全局心跳递减；归零后提示自动消失 */
const lockRemaining = computed(() => {
  if (!lockNotice.value?.lockoutEnd) return 0
  const end = new Date(lockNotice.value.lockoutEnd).getTime()
  if (Number.isNaN(end)) return 0
  return Math.max(0, Math.ceil((end - now.value) / 1000))
})

/**
 * 邮件服务不可用时的降级标记。
 * 后端未配置 SMTP 且邮件功能关闭时会返回 EMAIL_DISABLED，
 * 此时注册退化为"无需邮箱"的老流程，避免外部依赖不可用就完全无法注册。
 */
const emailUnavailable = ref(false)

/* ---------------- 登录 ---------------- */
const loginForm = ref({ username: '', password: '' })
const loginTouched = ref(false)

const loginErrors = computed(() => ({
  username: loginTouched.value && !loginForm.value.username.trim() ? '请输入用户名' : '',
  password: loginTouched.value && !loginForm.value.password ? '请输入密码' : ''
}))

async function submitLogin() {
  loginTouched.value = true
  formError.value = ''
  if (!loginForm.value.username.trim() || !loginForm.value.password) return

  lockNotice.value = null
  try {
    const res = await session.login(loginForm.value.username.trim(), loginForm.value.password)

    // 该账号已录入人脸 ⇒ 后端只发挑战、**不发票据**，流程停在第二阶段。
    // 此时不做"登录成功"的提示：登录并没有成功，票据还没出现。
    if (res?.code === 'FACE_REQUIRED') {
      // 口令已经用掉了，从界面上清掉；用户名留着，取消时不必重打。
      loginForm.value = { username: loginForm.value.username, password: '' }
      loginTouched.value = false
      return
    }

    toast.success(res?.message || '登录成功')
    loginForm.value = { username: '', password: '' }
    loginTouched.value = false
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    formError.value = e.message

    // 账号锁定时后端会随 401 返回 lockoutEnd / remainingSeconds，
    // 这里只用于展示倒计时，不会因此建立任何本地会话。
    if (e.data?.lockoutEnd) {
      lockNotice.value = { lockoutEnd: e.data.lockoutEnd }
    }
  }
}

/* ---------------- 登录第二阶段：人脸验证 ----------------
 * 面板展示的动作与指令都由**服务端**下发（动作随机，客户端无法指定）。
 * 这里只做一件事：把这张一次性挑战交回去，由后端自己开摄像头采集。
 */
async function captureFace() {
  formError.value = ''
  const token = session.pendingFace?.challengeToken
  if (!token) return

  try {
    const res = await session.loginFace(token)
    toast.success(res?.message || '登录成功')
    loginForm.value = { username: '', password: '' }
    loginTouched.value = false
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    formError.value = e.message
    // 挑战已被消费（服务端"先取出再校验"），失败后只能回到第一步重新口令登录，
    // 所以这里不保留任何中间态；锁定信息照旧交给倒计时展示。
    if (e.data?.lockoutEnd) lockNotice.value = { lockoutEnd: e.data.lockoutEnd }
  }
}

/** 放弃人脸验证，回到口令那一步（服务端那张挑战由有效期兜底作废）。 */
function cancelFace() {
  session.cancelFaceLogin()
  formError.value = ''
  loginTouched.value = false
}

/* ---------------- 子表单 → 页面级反馈 ----------------
 * 两个表单把异常与成功事件抛上来，由本页统一展示：顶部的错误框与锁定
 * 倒计时是**页面级**反馈，不属于任何一个表单；表单内部的 touched 状态
 * 则留在各自组件里，切换页签（v-if 卸载）时自然重置。
 */
function onFormError(e) {
  const msg = e?.message ?? ''
  if (!msg) {
    formError.value = ''
    return
  }
  if (e.emailDisabled) {
    emailUnavailable.value = true
    formError.value = '邮件服务未启用，本次注册无需填写邮箱'
    return
  }
  formError.value = msg
  if (e.lockoutEnd) lockNotice.value = { lockoutEnd: e.lockoutEnd }
}

/** 注册 / 重置成功后回到登录页并预填用户名，减少重复输入。 */
function onFormDone({ username }) {
  loginForm.value = { username, password: '' }
  tab.value = 'login'
}

function switchTab(next) {
  tab.value = next
  formError.value = ''
  lockNotice.value = null
}
</script>

<template>
  <div class="auth">
    <!-- 品牌侧栏：盾牌徽记 + 花体 Baseline，以渐变融入深色背景 -->
    <section class="brand" aria-hidden="true">
      <svg
        class="brand__art"
        viewBox="0 0 300 560"
        preserveAspectRatio="xMidYMid meet"
        focusable="false"
      >
        <defs>
          <!-- 盾牌描边：自上而下渐隐，底部尖端柔和融进背景但保留轮廓 -->
          <linearGradient
            id="shieldFade"
            gradientUnits="userSpaceOnUse"
            x1="0" y1="196" x2="0" y2="430"
          >
            <stop offset="0%" stop-color="#e8f2ff" stop-opacity="0.93" />
            <stop offset="35%" stop-color="#d3e6ff" stop-opacity="0.9" />
            <stop offset="68%" stop-color="#a9caf1" stop-opacity="0.64" />
            <stop offset="88%" stop-color="#7aa3d4" stop-opacity="0.34" />
            <stop offset="100%" stop-color="#5a83b0" stop-opacity="0.12" />
          </linearGradient>

          <!-- 盾面极淡填充：让轮廓读起来是一块实体，而不是空线框 -->
          <linearGradient
            id="shieldFill"
            gradientUnits="userSpaceOnUse"
            x1="0" y1="196" x2="0" y2="424"
          >
            <stop offset="0%" stop-color="#ffffff" stop-opacity="0.13" />
            <stop offset="55%" stop-color="#8fbcff" stop-opacity="0.06" />
            <stop offset="100%" stop-color="#ffffff" stop-opacity="0" />
          </linearGradient>

          <!-- 锁孔徽记：保持清晰实体，作为整幅的视觉焦点 -->
          <linearGradient
            id="emblemFade"
            gradientUnits="userSpaceOnUse"
            x1="0" y1="252" x2="0" y2="332"
          >
            <stop offset="0%" stop-color="#ffffff" stop-opacity="0.94" />
            <stop offset="100%" stop-color="#b9d7fa" stop-opacity="0.4" />
          </linearGradient>

          <!-- 背后柔光：给盾牌一点体积感，避免孤零零一条轮廓 -->
          <radialGradient id="shieldGlow" cx="50%" cy="40%" r="58%">
            <stop offset="0%" stop-color="#9ec8ff" stop-opacity="0.2" />
            <stop offset="68%" stop-color="#6f9fd8" stop-opacity="0.05" />
            <stop offset="100%" stop-color="#ffffff" stop-opacity="0" />
          </radialGradient>

          <!-- 花体 Baseline：左下淡入右上收亮 -->
          <linearGradient
            id="nameFade"
            gradientUnits="userSpaceOnUse"
            x1="20" y1="92" x2="280" y2="52"
          >
            <stop offset="0%" stop-color="#7ba5dd" stop-opacity="0.38" />
            <stop offset="40%" stop-color="#c3daf8" stop-opacity="0.88" />
            <stop offset="100%" stop-color="#ffffff" stop-opacity="1" />
          </linearGradient>

          <!-- 柔光：线条边缘自然晕开，去掉生硬的矢量感 -->
          <filter id="softGlow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="2.8" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <!-- ---------- 盾牌徽记（纹章式：外轮廓 + 内嵌边 + 横带 + 锁孔） ---------- -->
        <g class="brand__figure">
          <!-- 背后柔光 -->
          <ellipse cx="150" cy="300" rx="142" ry="170" fill="url(#shieldGlow)" />

          <g
            class="brand__shield"
            fill="none"
            stroke="url(#shieldFade)"
            stroke-width="2.5"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <!-- 外轮廓（带极淡填充，形成"盾面"） -->
            <path
              fill="url(#shieldFill)"
              d="M62,209 Q62,196 77,196 L223,196 Q238,196 238,209 L238,300
                 C238,362 208,404 150,424 C92,404 62,362 62,300 Z"
            />
            <!-- 内嵌边（bordure）：与外形保持均匀 ~14 的间距，不要贴上形成粗边 -->
            <path
              stroke-width="1.4"
              stroke-opacity="0.62"
              d="M76,222 Q76,210 88,210 L212,210 Q224,210 224,222 L224,300
                 C224,354 199,392 150,410 C101,392 76,354 76,300 Z"
            />
            <!-- 纹章横带：把盾面分成上下两区 -->
            <path stroke-width="1.4" stroke-opacity="0.5" d="M76,242 Q150,253 224,242" />
            <!-- 两枚铆钉 -->
            <circle cx="96" cy="230" r="2.6" stroke="none" fill="url(#emblemFade)" />
            <circle cx="204" cy="230" r="2.6" stroke="none" fill="url(#emblemFade)" />
          </g>

          <!-- 锁孔徽记：圆孔 + 下张锁芯，寓意口令认证 -->
          <g class="brand__emblem">
            <circle cx="150" cy="280" r="18" fill="url(#emblemFade)" />
            <path fill="url(#emblemFade)" d="M140.5,296 L159.5,296 L167.5,340 L132.5,340 Z" />
          </g>
        </g>

        <!-- ---------- 花体 Baseline ---------- -->
        <g class="brand__wordmark">
          <!-- 行云式装饰线 -->
          <path class="mark-flourish" d="M18,40 C84,26 190,22 280,30" />
          <text x="24" y="96">Baseline</text>
        </g>
      </svg>

      <div class="brand__foot">
        <AppIcon name="terminal" :size="13" />
        <span>ASP.NET Core · MongoDB · Vue 3</span>
      </div>
    </section>

    <!-- 表单区 -->
    <section class="form">
      <div class="form__inner">
        <!-- 第二因子：口令已通过，等一张人脸。此时没有任何票据 -->
        <div v-if="session.pendingFace" class="head">
          <button type="button" class="linkbtn" @click="cancelFace">
            <AppIcon name="arrow-left" :size="13" />
            <span>返回登录</span>
          </button>
          <h2 class="head__title">人脸验证</h2>
          <p class="head__desc">口令已通过，请按提示完成动作以完成登录</p>
        </div>

        <div v-else-if="tab !== 'reset'" class="tabs" role="tablist" aria-label="认证方式">
          <button
            type="button"
            class="tab"
            :class="{ 'is-active': tab === 'login' }"
            role="tab"
            :aria-selected="tab === 'login'"
            @click="switchTab('login')"
          >
            <AppIcon name="log-in" :size="15" />
            <span>登录</span>
          </button>
          <button
            type="button"
            class="tab"
            :class="{ 'is-active': tab === 'register' }"
            role="tab"
            :aria-selected="tab === 'register'"
            @click="switchTab('register')"
          >
            <AppIcon name="user" :size="15" />
            <span>注册</span>
          </button>
        </div>

        <!-- 找回密码：不用第三个 tab，避免看起来像第三种登录方式 -->
        <div v-else class="head">
          <button type="button" class="linkbtn" @click="switchTab('login')">
            <AppIcon name="arrow-left" :size="13" />
            <span>返回登录</span>
          </button>
          <h2 class="head__title">找回密码</h2>
          <p class="head__desc">校验注册邮箱后，直接设置新密码</p>
        </div>

        <!-- 错误汇总：便于定位问题，同时保留行内错误 -->
        <div v-if="formError" class="alert" role="alert">
          <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
          <span class="selectable">{{ formError }}</span>
        </div>

        <div v-else-if="lockRemaining > 0" class="alert alert--warn" role="status">
          <AppIcon name="lock" :size="15" :stroke-width="2" />
          <span>{{ tab === 'reset' ? '账号已锁定，暂不能找回密码' : '账号已锁定' }}，请在 {{ formatDuration(lockRemaining) }}后重试</span>
        </div>

        <!-- 人脸验证（登录第二阶段）：动作由服务端随机下发 -->
        <FaceCapturePanel
          v-if="session.pendingFace"
          :action="session.pendingFace.action"
          :action-text="session.pendingFace.actionText"
          :action-hint="session.pendingFace.actionHint"
          :busy="session.submitting"
          confirm-text="开始刷脸"
          :preview-token="session.pendingFace?.challengeToken || ''"
          :threshold="session.pendingFace?.threshold ?? null"
          @capture="captureFace"
          @cancel="cancelFace"
        />

        <!-- 登录 -->
        <form v-else-if="tab === 'login'" class="stack" novalidate @submit.prevent="submitLogin">
          <div class="field">
            <label class="field__label" for="login-username">用户名</label>
            <input
              id="login-username"
              v-model="loginForm.username"
              class="input"
              :class="{ 'input--invalid': loginErrors.username }"
              type="text"
              placeholder="请输入用户名"
              autocomplete="off"
              spellcheck="false"
              :aria-invalid="!!loginErrors.username || undefined"
              autofocus
            />
            <p v-if="loginErrors.username" class="field__error">
              <AppIcon name="alert-triangle" :size="12" /><span>{{ loginErrors.username }}</span>
            </p>
          </div>

          <!-- 登录框关闭浏览器自动填充：避免凭据被浏览器长期留存后被他人一键登录 -->
          <PasswordField
            v-model="loginForm.password"
            label="密码"
            placeholder="请输入密码"
            autocomplete="off"
            :invalid="!!loginErrors.password"
            :error="loginErrors.password"
            @enter="submitLogin"
          />

          <button
            type="submit"
            class="btn btn--primary btn--block btn--lg"
            :disabled="session.submitting"
          >
            <Spinner v-if="session.submitting" :size="14" />
            <AppIcon v-else name="log-in" :size="15" />
            <span>登录</span>
          </button>

          <p class="aux">
            <button type="button" class="linkbtn" @click="switchTab('reset')">忘记密码？</button>
          </p>
        </form>

        <!-- 注册：先验证邮箱，验证通过才建号 -->
        <RegisterForm
          v-else-if="tab === 'register'"
          :email-unavailable="emailUnavailable"
          @error="onFormError"
          @done="onFormDone"
        />

        <!-- 忘记密码 -->
        <ResetPasswordForm v-else @error="onFormError" @done="onFormDone" />
      </div>
    </section>
  </div>
</template>

<style scoped src="../styles/auth-form.css"></style>
<style scoped>
.auth {
  display: grid;
  grid-template-columns: minmax(280px, 340px) 1fr;
  height: 100%;
  min-height: 0;
}

/* ---------- 品牌区 ---------- */
.brand {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: var(--sp-3);
  padding: var(--sp-8) var(--sp-6);
  background:
    radial-gradient(120% 90% at 12% 8%, rgba(37, 99, 235, 0.28), transparent 62%),
    linear-gradient(165deg, #16304f 0%, #1e3a5f 48%, #14304d 100%);
  color: #eaf1fb;
  overflow: hidden;
}
.brand::after {
  content: '';
  position: absolute;
  inset: 0;
  background-image: linear-gradient(rgba(255, 255, 255, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.05) 1px, transparent 1px);
  background-size: 26px 26px;
  mask-image: radial-gradient(90% 70% at 30% 20%, #000 20%, transparent 78%);
  pointer-events: none;
}

/* 骑士简笔画：铺满侧栏，整体随高度缩放并保持留白 */
.brand__art {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
}

/* 整幅徽记挂一层柔光，线条与盾面边缘都不发硬 */
.brand__figure {
  filter: url(#softGlow);
}

/* 花体 Baseline：手写衬线字形，颜色随渐变淡入深色背景 */
.brand__wordmark text {
  font-family: 'Segoe Script', 'Brush Script MT', 'Lucida Handwriting', 'Palace Script MT',
    cursive;
  font-style: italic;
  font-size: 44px;
  fill: url(#nameFade);
}

.mark-flourish {
  fill: none;
  stroke: #cfe2ff;
  stroke-width: 1;
  stroke-opacity: 0.24;
  stroke-linecap: round;
}

.brand__foot {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  margin-top: auto;
  padding-top: var(--sp-4);
  font-size: var(--fs-xs);
  color: rgba(234, 241, 251, 0.52);
}

/* ---------- 表单区 ---------- */
.form {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--sp-6);
  min-height: 0;
  overflow-y: auto;
  background: var(--c-window);
}

.form__inner {
  width: 100%;
  max-width: 340px;
  display: flex;
  flex-direction: column;
  gap: var(--sp-4);
}

.tabs {
  display: flex;
  gap: 2px;
  padding: 3px;
  background: var(--c-surface-2);
  border-radius: var(--r-md);
}

.tab {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--sp-2);
  flex: 1;
  height: 28px;
  border: 0;
  border-radius: var(--r-sm);
  background: transparent;
  color: var(--c-text-muted);
  font-size: var(--fs-base);
  font-weight: 500;
  cursor: pointer;
  transition: background var(--t-fast) var(--ease), color var(--t-fast) var(--ease),
    box-shadow var(--t-fast) var(--ease);
}
.tab:hover {
  color: var(--c-text);
}
.tab:focus-visible {
  outline: none;
  box-shadow: var(--sh-focus);
}
.tab.is-active {
  background: var(--c-window);
  color: var(--c-text);
  box-shadow: var(--sh-card);
}

/* ---------- 找回密码标题 ---------- */
.head {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.head__title {
  font-size: var(--fs-lg);
  font-weight: 600;
  color: var(--c-text);
}
.head__desc {
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
}

.linkbtn {
  display: inline-flex;
  align-items: center;
  gap: var(--sp-1);
  align-self: flex-start;
  padding: 0;
  border: 0;
  background: none;
  color: var(--c-primary);
  font-size: var(--fs-xs);
  cursor: pointer;
}
.linkbtn:hover {
  text-decoration: underline;
}
.linkbtn:focus-visible {
  outline: none;
  box-shadow: var(--sh-focus);
  border-radius: var(--r-sm);
}

.aux {
  display: flex;
  justify-content: flex-end;
  margin-top: calc(-1 * var(--sp-2));
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
.alert--warn {
  border-color: color-mix(in srgb, var(--st-pending-fg) 34%, transparent);
  background: var(--st-pending-bg);
}
.alert--warn > svg {
  color: var(--st-pending-fg);
}

/* ---------- 窄屏 ---------- */
@media (max-width: 820px) {
  .auth {
    grid-template-columns: 1fr;
    overflow-y: auto;
  }
  .brand {
    display: none;
  }
  .form {
    padding: var(--sp-5);
  }
}
</style>
