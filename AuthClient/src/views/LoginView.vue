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

/* ---------------- 注册 ---------------- */
const regForm = ref({ username: '', password: '', confirm: '' })
const regTouched = ref(false)

const regErrors = computed(() => {
  if (!regTouched.value) return { username: '', password: '', confirm: '' }
  const f = regForm.value
  return {
    username: !f.username.trim() ? '请输入用户名' : '',
    password: !f.password
      ? '请输入密码'
      : !isPasswordStrong(f.password)
        ? '口令复杂度不满足要求'
        : '',
    confirm: f.confirm !== f.password ? '两次输入的密码不一致' : ''
  }
})

async function submitRegister() {
  regTouched.value = true
  formError.value = ''
  const f = regForm.value
  if (!f.username.trim() || !isPasswordStrong(f.password) || f.confirm !== f.password) return

  try {
    const res = await session.register(f.username.trim(), f.password)
    toast.success(res?.message || '注册成功，等待管理员审核')
    // 注册成功后切回登录页并带上用户名，减少重复输入
    loginForm.value = { username: f.username.trim(), password: '' }
    regForm.value = { username: '', password: '', confirm: '' }
    regTouched.value = false
    tab.value = 'login'
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    formError.value = e.message
  }
}

function switchTab(next) {
  tab.value = next
  formError.value = ''
  lockNotice.value = null
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
        <div class="tabs" role="tablist" aria-label="认证方式">
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

        <!-- 错误汇总：便于定位问题，同时保留行内错误 -->
        <div v-if="formError" class="alert" role="alert">
          <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
          <span class="selectable">{{ formError }}</span>
        </div>

        <div v-else-if="lockRemaining > 0" class="alert alert--warn" role="status">
          <AppIcon name="lock" :size="15" :stroke-width="2" />
          <span>账号已锁定，请在 {{ formatDuration(lockRemaining) }}后重试</span>
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
        </form>

        <!-- 注册 -->
        <form v-else class="stack" novalidate @submit.prevent="submitRegister">
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
            <p v-else class="field__hint">注册后需管理员审核通过才能登录。</p>
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

.stack {
  display: flex;
  flex-direction: column;
  gap: var(--sp-4);
}

.btn--lg {
  height: 34px;
  font-size: var(--fs-md);
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
