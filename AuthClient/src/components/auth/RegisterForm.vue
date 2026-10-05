<script setup>
import { computed, ref } from 'vue'
import AppIcon from '../AppIcon.vue'
import PasswordField from '../PasswordField.vue'
import PasswordRules from '../PasswordRules.vue'
import Spinner from '../Spinner.vue'
import { ApiError } from '../../api/client'
import { useSessionStore } from '../../stores/session'
import { useToastStore } from '../../stores/toast'
import { isPasswordStrong } from '../../utils/password'
import { isEmail, useEmailCode } from '../../composables/useEmailCode'

/**
 * 注册表单（先验证邮箱，验证通过才建号）。
 *
 * 表单状态、校验与提交全部自持；对外的两个出口：
 *   · `error` —— 父级顶部的错误汇总框（含邮件服务降级、锁定截止时刻）
 *   · `done`  —— 注册成功，带上用户名，供父级切回登录页并预填
 *
 * 复杂度校验**故意不在提交前拦**：本地只拦"两次输入不一致"这类纯输入错误，
 * 弱口令要交给服务端裁决并留痕 —— 反复提交弱口令本身就是要记进审计的安全事件。
 */
const props = defineProps({
  emailUnavailable: { type: Boolean, default: false }
})
const emit = defineEmits(['error', 'done'])

const session = useSessionStore()
const toast = useToastStore()

const form = ref({ username: '', password: '', confirm: '', email: '', code: '' })
const touched = ref(false)
const { state: code, remain, apply, reset: resetCode } = useEmailCode()

const errors = computed(() => {
  if (!touched.value) return { username: '', email: '', code: '', password: '', confirm: '' }
  const f = form.value
  const needEmail = !props.emailUnavailable
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

/** 把异常交给父级的错误汇总框；`emailDisabled` 用于触发"无需邮箱"的降级。 */
function reportError(err) {
  const e = err instanceof ApiError ? err : new ApiError(err.message)
  emit('error', {
    message: e.message,
    emailDisabled: e.code === 'EMAIL_DISABLED',
    lockoutEnd: e.data?.lockoutEnd ?? null
  })
}

async function sendCode() {
  emit('error', { message: '' })
  const f = form.value
  if (!f.username.trim()) {
    emit('error', { message: '请先填写用户名' })
    return
  }
  if (!isEmail(f.email)) {
    emit('error', { message: '请输入有效的邮箱地址' })
    return
  }
  try {
    const res = await session.sendEmailCode('REGISTER', f.username.trim(), f.email.trim())
    apply(res)
    toast.success('验证码已发送')
  } catch (err) {
    reportError(err)
  }
}

async function submit() {
  touched.value = true
  emit('error', { message: '' })
  const f = form.value
  const needEmail = !props.emailUnavailable
  // 复杂度同样不在这里判：交给服务端裁决并留痕（本地只管"两次是否一致"这类输入错误）。
  if (!f.username.trim() || f.confirm !== f.password) return
  if (needEmail && (!isEmail(f.email) || !f.code.trim())) return

  try {
    const res = await session.register(
      f.username.trim(),
      f.password,
      needEmail ? f.email.trim() : '',
      needEmail ? f.code.trim() : ''
    )
    toast.success(res?.message || '注册成功，等待管理员审核')
    const username = f.username.trim()
    form.value = { username: '', password: '', confirm: '', email: '', code: '' }
    resetCode()
    touched.value = false
    emit('done', { username })
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    emit('error', { message: e.message })
  }
}
</script>

<template>
  <!-- 注册：先验证邮箱，验证通过才建号 -->
  <form class="stack" novalidate @submit.prevent="submit">
    <div class="field">
      <label class="field__label" for="reg-username">用户名</label>
      <input
        id="reg-username"
        v-model="form.username"
        class="input"
        :class="{ 'input--invalid': errors.username }"
        type="text"
        placeholder="字母、数字或下划线，登录时自动转小写"
        autocomplete="off"
        spellcheck="false"
        :aria-invalid="!!errors.username || undefined"
      />
      <p v-if="errors.username" class="field__error">
        <AppIcon name="alert-triangle" :size="12" /><span>{{ errors.username }}</span>
      </p>
    </div>

    <div class="field">
      <label class="field__label" for="reg-email">邮箱</label>
      <div class="field__row">
        <input
          id="reg-email"
          v-model="form.email"
          class="input"
          :class="{ 'input--invalid': errors.email }"
          type="email"
          placeholder="用于接收验证码"
          autocomplete="off"
          spellcheck="false"
          :disabled="emailUnavailable"
          :aria-invalid="!!errors.email || undefined"
        />
        <button
          type="button"
          class="btn code-btn"
          :disabled="session.sendingCode || remain > 0 || emailUnavailable"
          @click="sendCode"
        >
          <Spinner v-if="session.sendingCode" :size="13" />
          <span v-else>{{ remain > 0 ? `${remain}s` : '获取验证码' }}</span>
        </button>
      </div>
      <p v-if="errors.email" class="field__error">
        <AppIcon name="alert-triangle" :size="12" /><span>{{ errors.email }}</span>
      </p>
      <p v-else-if="emailUnavailable" class="field__hint">邮件服务未启用，本次注册无需填写邮箱。</p>
    </div>

    <div v-if="!emailUnavailable" class="field">
      <label class="field__label" for="reg-code">邮箱验证码</label>
      <input
        id="reg-code"
        v-model="form.code"
        class="input"
        :class="{ 'input--invalid': errors.code }"
        type="text"
        inputmode="numeric"
        maxlength="6"
        placeholder="6 位数字"
        autocomplete="off"
        spellcheck="false"
        :aria-invalid="!!errors.code || undefined"
        @input="form.code = String(form.code).replace(/\D/g, '').slice(0, 6)"
      />
      <p v-if="errors.code" class="field__error">
        <AppIcon name="alert-triangle" :size="12" /><span>{{ errors.code }}</span>
      </p>
      <p v-else-if="code.hint" class="field__hint">{{ code.hint }}</p>
    </div>

    <PasswordField
      v-model="form.password"
      label="密码"
      placeholder="设置登录密码"
      autocomplete="new-password"
      :invalid="touched && !!errors.password"
      :error="touched ? errors.password : ''"
    />

    <PasswordRules :value="form.password" />

    <PasswordField
      v-model="form.confirm"
      label="确认密码"
      placeholder="再次输入密码"
      autocomplete="new-password"
      :invalid="touched && !!errors.confirm"
      :error="touched ? errors.confirm : ''"
      @enter="submit"
    />

    <button type="submit" class="btn btn--primary btn--block btn--lg" :disabled="session.submitting">
      <Spinner v-if="session.submitting" :size="14" />
      <AppIcon v-else name="user" :size="15" />
      <span>提交注册</span>
    </button>

    <p class="field__hint">注册后需管理员审核通过才能登录。</p>
  </form>
</template>

<style scoped src="../../styles/auth-form.css"></style>
