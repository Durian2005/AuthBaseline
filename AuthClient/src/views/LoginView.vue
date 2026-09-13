<script setup>
import { computed, ref } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import PasswordField from '../components/PasswordField.vue'
import PasswordRules from '../components/PasswordRules.vue'
import Spinner from '../components/Spinner.vue'
import { useSessionStore } from '../stores/session'
import { useToastStore } from '../stores/toast'
import { ApiError } from '../api/client'
import { isPasswordStrong } from '../utils/password'
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

/* ---------------- 邮箱验证码公共逻辑 ---------------- */

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/
const isEmail = (v) => EMAIL_RE.test(String(v || '').trim())

/**
 * 邮件服务不可用时的降级标记。
 * 后端未配置 SMTP 且邮件功能关闭时会返回 EMAIL_DISABLED，
 * 此时注册退化为"无需邮箱"的老流程，避免外部依赖不可用就完全无法注册。
 */
const emailUnavailable = ref(false)

const emptyCodeState = () => ({ sentTo: '', resendAt: 0, hint: '' })
const regCode = ref(emptyCodeState())
const resetCode = ref(emptyCodeState())

/** 60 秒重发倒计时：只需记一个截止时刻，由全局心跳驱动，无需自建定时器 */
function remainSeconds(state) {
  if (!state.resendAt) return 0
  return Math.max(0, Math.ceil((state.resendAt - now.value) / 1000))
}
const regRemain = computed(() => remainSeconds(regCode.value))
const resetRemain = computed(() => remainSeconds(resetCode.value))

function applyCodeState(stateRef, res) {
  const d = res?.data ?? {}
  stateRef.value = {
    sentTo: d.maskedEmail || '',
    resendAt: Date.now() + (Number(d.resendAfter) || 60) * 1000,
    hint:
      d.deliversRealMail === false
        ? '当前为控制台发件器，验证码请查看后端日志'
        : `验证码已发送至 ${d.maskedEmail || '您的邮箱'}，5 分钟内有效`
  }
}

function handleCodeError(err) {
  const e = err instanceof ApiError ? err : new ApiError(err.message)
  if (e.code === 'EMAIL_DISABLED') {
    emailUnavailable.value = true
    formError.value = '邮件服务未启用，本次注册无需填写邮箱'
    return
  }
  formError.value = e.message
  if (e.data?.lockoutEnd) lockNotice.value = { lockoutEnd: e.data.lockoutEnd }
}

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

/* ---------------- 注册（绑定邮箱） ---------------- */
const regForm = ref({ username: '', password: '', confirm: '', email: '', code: '' })
const regTouched = ref(false)

const regErrors = computed(() => {
  if (!regTouched.value) return { username: '', email: '', code: '', password: '', confirm: '' }
  const f = regForm.value
  const needEmail = !emailUnavailable.value
  return {
    username: !f.username.trim() ? '请输入用户名' : '',
    email: needEmail && !isEmail(f.email) ? '请输入有效的邮箱地址' : '',
    code: needEmail && !f.code.trim() ? '请输入邮箱验证码' : '',
    password: !f.password
      ? '请输入密码'
      : !isPasswordStrong(f.password)
        ? '口令复杂度不满足要求'
        : '',
    confirm: f.confirm !== f.password ? '两次输入的密码不一致' : ''
  }
})

async function sendRegCode() {
  formError.value = ''
  const f = regForm.value
  if (!f.username.trim()) {
    formError.value = '请先填写用户名'
    return
  }
  if (!isEmail(f.email)) {
    formError.value = '请输入有效的邮箱地址'
    return
  }
  try {
    const res = await session.sendEmailCode('REGISTER', f.username.trim(), f.email.trim())
    applyCodeState(regCode, res)
    toast.success('验证码已发送')
  } catch (err) {
    handleCodeError(err)
  }
}

async function submitRegister() {
  regTouched.value = true
  formError.value = ''
  const f = regForm.value
  const needEmail = !emailUnavailable.value
  if (!f.username.trim() || !isPasswordStrong(f.password) || f.confirm !== f.password) return
  if (needEmail && (!isEmail(f.email) || !f.code.trim())) return

  try {
    const res = await session.register(
      f.username.trim(),
      f.password,
      needEmail ? f.email.trim() : '',
      needEmail ? f.code.trim() : ''
    )
    toast.success(res?.message || '注册成功，等待管理员审核')
    // 注册成功后切回登录页并带上用户名，减少重复输入
    loginForm.value = { username: f.username.trim(), password: '' }
    regForm.value = { username: '', password: '', confirm: '', email: '', code: '' }
    regCode.value = emptyCodeState()
    regTouched.value = false
    tab.value = 'login'
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    formError.value = e.message
  }
}

/* ---------------- 忘记密码（用户名 + 邮箱 → 验证码 → 设置新密码） ---------------- */
const resetForm = ref({ username: '', email: '', code: '', password: '', confirm: '' })
const resetTouched = ref(false)

const resetErrors = computed(() => {
  if (!resetTouched.value) return { username: '', email: '', code: '', password: '', confirm: '' }
  const f = resetForm.value
  return {
    username: !f.username.trim() ? '请输入用户名' : '',
    email: !isEmail(f.email) ? '请输入注册时绑定的邮箱' : '',
    code: !f.code.trim() ? '请输入邮箱验证码' : '',
    password: !f.password
      ? '请输入新密码'
      : !isPasswordStrong(f.password)
        ? '口令复杂度不满足要求'
        : '',
    confirm: f.confirm !== f.password ? '两次输入的密码不一致' : ''
  }
})

async function sendResetCode() {
  formError.value = ''
  const f = resetForm.value
  if (!f.username.trim()) {
    formError.value = '请先填写用户名'
    return
  }
  if (!isEmail(f.email)) {
    formError.value = '请输入注册时绑定的邮箱'
    return
  }
  try {
    const res = await session.sendEmailCode('RESET', f.username.trim(), f.email.trim())
    applyCodeState(resetCode, res)
    toast.success('验证码已发送')
  } catch (err) {
    handleCodeError(err)
  }
}

async function submitReset() {
  resetTouched.value = true
  formError.value = ''
  const f = resetForm.value
  if (
    !f.username.trim() ||
    !isEmail(f.email) ||
    !f.code.trim() ||
    !isPasswordStrong(f.password) ||
    f.confirm !== f.password
  ) {
    return
  }

  try {
    const res = await session.resetPassword(
      f.username.trim(),
      f.email.trim(),
      f.code.trim(),
      f.password
    )
    toast.success(res?.message || '密码已重置，请使用新密码登录')
    // 重置只改口令、不建立会话，必须回到登录页用新口令重新登录
    loginForm.value = { username: f.username.trim(), password: '' }
    resetForm.value = { username: '', email: '', code: '', password: '', confirm: '' }
    resetCode.value = emptyCodeState()
    resetTouched.value = false
    tab.value = 'login'
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    formError.value = e.message
    if (e.data?.lockoutEnd) lockNotice.value = { lockoutEnd: e.data.lockoutEnd }
  }
}

function switchTab(next) {
  tab.value = next
  formError.value = ''
  lockNotice.value = null
  regTouched.value = false
  resetTouched.value = false
}
</script>

<template>
  <div class="auth">
    <!-- 品牌侧栏：桌面软件登录窗的常规构图 -->
    <section class="brand" aria-hidden="true">
      <div class="brand__logo">
        <AppIcon name="shield-check" :size="26" :stroke-width="1.6" />
      </div>
      <h1 class="brand__name">口令认证基线系统</h1>
      <p class="brand__tagline">实验一 · 建立可运行的口令认证基线</p>

      <div class="brand__foot">
        <AppIcon name="terminal" :size="13" />
        <span>ASP.NET Core · MongoDB · Vue 3</span>
      </div>
    </section>

    <!-- 表单区 -->
    <section class="form">
      <div class="form__inner">
        <div v-if="tab !== 'reset'" class="tabs" role="tablist" aria-label="认证方式">
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

        <!-- 登录 -->
        <form v-if="tab === 'login'" class="stack" novalidate @submit.prevent="submitLogin">
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
        <form v-else-if="tab === 'register'" class="stack" novalidate @submit.prevent="submitRegister">
          <div class="field">
            <label class="field__label" for="reg-username">用户名</label>
            <input
              id="reg-username"
              v-model="regForm.username"
              class="input"
              :class="{ 'input--invalid': regErrors.username }"
              type="text"
              placeholder="字母、数字或下划线，登录时自动转小写"
              autocomplete="username"
              spellcheck="false"
              :aria-invalid="!!regErrors.username || undefined"
            />
            <p v-if="regErrors.username" class="field__error">
              <AppIcon name="alert-triangle" :size="12" /><span>{{ regErrors.username }}</span>
            </p>
          </div>

          <div class="field">
            <label class="field__label" for="reg-email">邮箱</label>
            <div class="field__row">
              <input
                id="reg-email"
                v-model="regForm.email"
                class="input"
                :class="{ 'input--invalid': regErrors.email }"
                type="email"
                placeholder="用于接收验证码"
                autocomplete="email"
                spellcheck="false"
                :disabled="emailUnavailable"
                :aria-invalid="!!regErrors.email || undefined"
              />
              <button
                type="button"
                class="btn code-btn"
                :disabled="session.sendingCode || regRemain > 0 || emailUnavailable"
                @click="sendRegCode"
              >
                <Spinner v-if="session.sendingCode" :size="13" />
                <span v-else>{{ regRemain > 0 ? `${regRemain}s` : '获取验证码' }}</span>
              </button>
            </div>
            <p v-if="regErrors.email" class="field__error">
              <AppIcon name="alert-triangle" :size="12" /><span>{{ regErrors.email }}</span>
            </p>
            <p v-else-if="emailUnavailable" class="field__hint">邮件服务未启用，本次注册无需填写邮箱。</p>
          </div>

          <div v-if="!emailUnavailable" class="field">
            <label class="field__label" for="reg-code">邮箱验证码</label>
            <input
              id="reg-code"
              v-model="regForm.code"
              class="input"
              :class="{ 'input--invalid': regErrors.code }"
              type="text"
              inputmode="numeric"
              maxlength="6"
              placeholder="6 位数字"
              autocomplete="one-time-code"
              spellcheck="false"
              :aria-invalid="!!regErrors.code || undefined"
              @input="regForm.code = String(regForm.code).replace(/\D/g, '').slice(0, 6)"
            />
            <p v-if="regErrors.code" class="field__error">
              <AppIcon name="alert-triangle" :size="12" /><span>{{ regErrors.code }}</span>
            </p>
            <p v-else-if="regCode.hint" class="field__hint">{{ regCode.hint }}</p>
          </div>

          <PasswordField
            v-model="regForm.password"
            label="密码"
            placeholder="设置登录密码"
            autocomplete="new-password"
            :invalid="regTouched && !!regErrors.password"
            :error="regTouched ? regErrors.password : ''"
          />

          <PasswordRules :value="regForm.password" />

          <PasswordField
            v-model="regForm.confirm"
            label="确认密码"
            placeholder="再次输入密码"
            autocomplete="new-password"
            :invalid="regTouched && !!regErrors.confirm"
            :error="regTouched ? regErrors.confirm : ''"
            @enter="submitRegister"
          />

          <button
            type="submit"
            class="btn btn--primary btn--block btn--lg"
            :disabled="session.submitting"
          >
            <Spinner v-if="session.submitting" :size="14" />
            <AppIcon v-else name="user" :size="15" />
            <span>提交注册</span>
          </button>

          <p class="field__hint">注册后需管理员审核通过才能登录。</p>
        </form>

        <!-- 忘记密码 -->
        <form v-else class="stack" novalidate @submit.prevent="submitReset">
          <div class="field">
            <label class="field__label" for="reset-username">用户名</label>
            <input
              id="reset-username"
              v-model="resetForm.username"
              class="input"
              :class="{ 'input--invalid': resetErrors.username }"
              type="text"
              placeholder="请输入用户名"
              autocomplete="username"
              spellcheck="false"
              :aria-invalid="!!resetErrors.username || undefined"
              autofocus
            />
            <p v-if="resetErrors.username" class="field__error">
              <AppIcon name="alert-triangle" :size="12" /><span>{{ resetErrors.username }}</span>
            </p>
          </div>

          <div class="field">
            <label class="field__label" for="reset-email">绑定邮箱</label>
            <div class="field__row">
              <input
                id="reset-email"
                v-model="resetForm.email"
                class="input"
                :class="{ 'input--invalid': resetErrors.email }"
                type="email"
                placeholder="注册时绑定的邮箱"
                autocomplete="email"
                spellcheck="false"
                :aria-invalid="!!resetErrors.email || undefined"
              />
              <button
                type="button"
                class="btn code-btn"
                :disabled="session.sendingCode || resetRemain > 0"
                @click="sendResetCode"
              >
                <Spinner v-if="session.sendingCode" :size="13" />
                <span v-else>{{ resetRemain > 0 ? `${resetRemain}s` : '获取验证码' }}</span>
              </button>
            </div>
            <p v-if="resetErrors.email" class="field__error">
              <AppIcon name="alert-triangle" :size="12" /><span>{{ resetErrors.email }}</span>
            </p>
            <p v-else class="field__hint">需与账号绑定的邮箱完全一致。</p>
          </div>

          <div class="field">
            <label class="field__label" for="reset-code">邮箱验证码</label>
            <input
              id="reset-code"
              v-model="resetForm.code"
              class="input"
              :class="{ 'input--invalid': resetErrors.code }"
              type="text"
              inputmode="numeric"
              maxlength="6"
              placeholder="6 位数字"
              autocomplete="one-time-code"
              spellcheck="false"
              :aria-invalid="!!resetErrors.code || undefined"
              @input="resetForm.code = String(resetForm.code).replace(/\D/g, '').slice(0, 6)"
            />
            <p v-if="resetErrors.code" class="field__error">
              <AppIcon name="alert-triangle" :size="12" /><span>{{ resetErrors.code }}</span>
            </p>
            <p v-else-if="resetCode.hint" class="field__hint">{{ resetCode.hint }}</p>
          </div>

          <PasswordField
            v-model="resetForm.password"
            label="新密码"
            placeholder="设置新的登录密码"
            autocomplete="new-password"
            :invalid="resetTouched && !!resetErrors.password"
            :error="resetTouched ? resetErrors.password : ''"
          />

          <PasswordRules :value="resetForm.password" />

          <PasswordField
            v-model="resetForm.confirm"
            label="确认新密码"
            placeholder="再次输入新密码"
            autocomplete="new-password"
            :invalid="resetTouched && !!resetErrors.confirm"
            :error="resetTouched ? resetErrors.confirm : ''"
            @enter="submitReset"
          />

          <button
            type="submit"
            class="btn btn--primary btn--block btn--lg"
            :disabled="session.submitting"
          >
            <Spinner v-if="session.submitting" :size="14" />
            <AppIcon v-else name="mail-check" :size="15" />
            <span>重置密码</span>
          </button>
        </form>
      </div>
    </section>
  </div>
</template>

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

.brand__logo {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 46px;
  height: 46px;
  border-radius: var(--r-lg);
  background: rgba(255, 255, 255, 0.12);
  border: 1px solid rgba(255, 255, 255, 0.2);
  color: #fff;
}

.brand__name {
  font-size: var(--fs-xl);
  font-weight: 650;
  letter-spacing: 0.01em;
}

.brand__tagline {
  font-size: var(--fs-sm);
  color: rgba(234, 241, 251, 0.72);
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

.stack {
  display: flex;
  flex-direction: column;
  gap: var(--sp-4);
}

.btn--lg {
  height: 34px;
  font-size: var(--fs-md);
}

/* ---------- 邮箱 + 验证码同一行 ---------- */
.field__row {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
}
.field__row .input {
  flex: 1;
  min-width: 0;
}
.code-btn {
  flex: 0 0 auto;
  height: 32px;
  padding: 0 var(--sp-3);
  font-size: var(--fs-sm);
  font-variant-numeric: tabular-nums;
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
