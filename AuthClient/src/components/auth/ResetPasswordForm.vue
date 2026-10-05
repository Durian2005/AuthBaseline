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
 * 找回密码表单（用户名 + 绑定邮箱 → 验证码 → 直接设置新密码）。
 *
 * 重置成功**不建立任何会话** —— 必须回到登录页用新口令重新登录，
 * 因此这里只 emit `done`，由父级切页预填，而不是自行登录。
 *
 * 与注册表单同样的取舍：复杂度交服务端裁决（失败会记 RESET_PASSWORD_FAILED），
 * 本地只拦"两次不一致"这类纯输入错误。
 */
const emit = defineEmits(['error', 'done'])

const session = useSessionStore()
const toast = useToastStore()

const form = ref({ username: '', email: '', code: '', password: '', confirm: '' })
const touched = ref(false)
const { state: code, remain, apply, reset: resetCode } = useEmailCode()

const errors = computed(() => {
  if (!touched.value) return { username: '', email: '', code: '', password: '', confirm: '' }
  const f = form.value
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

async function sendCode() {
  emit('error', { message: '' })
  const f = form.value
  if (!f.username.trim()) {
    emit('error', { message: '请先填写用户名' })
    return
  }
  if (!isEmail(f.email)) {
    emit('error', { message: '请输入注册时绑定的邮箱' })
    return
  }
  try {
    const res = await session.sendEmailCode('RESET', f.username.trim(), f.email.trim())
    apply(res)
    toast.success('验证码已发送')
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    emit('error', {
      message: e.message,
      emailDisabled: e.code === 'EMAIL_DISABLED',
      lockoutEnd: e.data?.lockoutEnd ?? null
    })
  }
}

async function submit() {
  touched.value = true
  emit('error', { message: '' })
  const f = form.value
  if (!f.username.trim() || !isEmail(f.email) || !f.code.trim() || f.confirm !== f.password) {
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
    const username = f.username.trim()
    form.value = { username: '', email: '', code: '', password: '', confirm: '' }
    resetCode()
    touched.value = false
    emit('done', { username })
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    emit('error', { message: e.message, lockoutEnd: e.data?.lockoutEnd ?? null })
  }
}
</script>

<template>
  <!-- 忘记密码 -->
  <form class="stack" novalidate @submit.prevent="submit">
    <div class="field">
      <label class="field__label" for="reset-username">用户名</label>
      <input
        id="reset-username"
        v-model="form.username"
        class="input"
        :class="{ 'input--invalid': errors.username }"
        type="text"
        placeholder="请输入用户名"
        autocomplete="off"
        spellcheck="false"
        :aria-invalid="!!errors.username || undefined"
        autofocus
      />
      <p v-if="errors.username" class="field__error">
        <AppIcon name="alert-triangle" :size="12" /><span>{{ errors.username }}</span>
      </p>
    </div>

    <div class="field">
      <label class="field__label" for="reset-email">绑定邮箱</label>
      <div class="field__row">
        <input
          id="reset-email"
          v-model="form.email"
          class="input"
          :class="{ 'input--invalid': errors.email }"
          type="email"
          placeholder="注册时绑定的邮箱"
          autocomplete="off"
          spellcheck="false"
          :aria-invalid="!!errors.email || undefined"
        />
        <button
          type="button"
          class="btn code-btn"
          :disabled="session.sendingCode || remain > 0"
          @click="sendCode"
        >
          <Spinner v-if="session.sendingCode" :size="13" />
          <span v-else>{{ remain > 0 ? `${remain}s` : '获取验证码' }}</span>
        </button>
      </div>
      <p v-if="errors.email" class="field__error">
        <AppIcon name="alert-triangle" :size="12" /><span>{{ errors.email }}</span>
      </p>
      <p v-else class="field__hint">需与账号绑定的邮箱完全一致。</p>
    </div>

    <div class="field">
      <label class="field__label" for="reset-code">邮箱验证码</label>
      <input
        id="reset-code"
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
      label="新密码"
      placeholder="设置新的登录密码"
      autocomplete="new-password"
      :invalid="touched && !!errors.password"
      :error="touched ? errors.password : ''"
    />

    <PasswordRules :value="form.password" />

    <PasswordField
      v-model="form.confirm"
      label="确认新密码"
      placeholder="再次输入新密码"
      autocomplete="new-password"
      :invalid="touched && !!errors.confirm"
      :error="touched ? errors.confirm : ''"
      @enter="submit"
    />

    <button type="submit" class="btn btn--primary btn--block btn--lg" :disabled="session.submitting">
      <Spinner v-if="session.submitting" :size="14" />
      <AppIcon v-else name="mail-check" :size="15" />
      <span>重置密码</span>
    </button>
  </form>
</template>

<style scoped src="../../styles/auth-form.css"></style>
