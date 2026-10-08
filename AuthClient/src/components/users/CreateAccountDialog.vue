<script setup>
import { ref, watch } from 'vue'
import AppIcon from '../AppIcon.vue'
import AppWindow from '../AppWindow.vue'
import PasswordField from '../PasswordField.vue'
import Spinner from '../Spinner.vue'
import { useSessionStore } from '../../stores/session'
import { useToastStore } from '../../stores/toast'

/**
 * 新建账号弹窗（普通用户 / 用户管理员 / 审计管理员）。
 *
 * 与自助注册不同：**不需要验证码、建号即可登录**。
 * 邮箱是**可选**的：留空则账号只凭口令登录（代价是用不了「忘记密码」）；
 * 填写则后端登记为已验证，该账号随后即可走找回密码。
 *
 * 但后端要求二次校验操作者本人的登录口令 —— 这是特权操作，
 * 仅凭会话票据不足以防冒用，所以这里必须再输一次自己的口令。
 *
 * 表单状态自持：调用方只需要 `v-model:open`，不再关心字段与提交过程。
 */
const props = defineProps({
  open: { type: Boolean, default: false }
})
const emit = defineEmits(['update:open'])

const session = useSessionStore()
const toast = useToastStore()

const form = ref({ username: '', email: '', password: '', role: 'UserAdmin', operatorPassword: '' })
const error = ref('')
const creating = ref(false)

// 每次打开都回到干净的初始状态（与拆分前 openCreate() 的行为一致）
watch(
  () => props.open,
  (v) => {
    if (!v) return
    form.value = { username: '', email: '', password: '', role: 'UserAdmin', operatorPassword: '' }
    error.value = ''
  }
)

function close() {
  emit('update:open', false)
}

async function confirm() {
  const f = form.value
  if (!f.username.trim() || !f.password || !f.operatorPassword) {
    error.value = '请填写账号、初始口令与您本人的登录口令'
    return
  }
  creating.value = true
  error.value = ''
  try {
    const res = await session.createAccount(
      f.username.trim(),
      f.password,
      f.role,
      f.operatorPassword,
      // 邮箱可选，留空即不绑定。格式由后端裁决 —— 与口令复杂度同一条原则：
      // 前端不做提交门禁，免得两边的校验规则各说各话。
      f.email.trim()
    )
    toast.success(res?.message || '账号已创建')
    close()
  } catch (err) {
    error.value = err?.message || '创建失败'
  } finally {
    creating.value = false
  }
}
</script>

<template>
  <AppWindow
    :open="open"
    title="新建账号"
    icon="user-plus"
    tone="primary"
    :width="460"
    :close-on-overlay="!creating"
    @close="!creating && close()"
  >
    <div class="form">
      <div class="form__notice">
        <AppIcon name="info" :size="15" :stroke-width="2" />
        <span>
          新建账号<strong>无需绑定邮箱</strong>，创建后即可用初始口令登录。
          邮箱是<strong>可选项</strong>：留空则只能凭口令登录、用不了「忘记密码」；
          填写则登记为已验证，该账号随后即可自助找回密码。请按职责选择角色。
        </span>
      </div>

      <div v-if="error" class="alert" role="alert">
        <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
        <span class="selectable">{{ error }}</span>
      </div>

      <label class="field">
        <span class="field__label">账号</span>
        <input
          v-model="form.username"
          class="input"
          type="text"
          placeholder="例如 auditor01"
          autocomplete="off"
          spellcheck="false"
        />
      </label>

      <label class="field">
        <span class="field__label">角色</span>
        <select v-model="form.role" class="input select">
          <option value="User">普通用户 —— 只能使用自己的账号与口令功能</option>
          <option value="UserAdmin">用户管理员 —— 可管理用户，不能查看审计日志</option>
          <option value="AuditAdmin">审计管理员 —— 只能查看审计日志，不能管理用户</option>
        </select>
      </label>

      <label class="field">
        <span class="field__label">邮箱（可选）</span>
        <input
          v-model="form.email"
          class="input"
          type="email"
          placeholder="留空即不绑定，该账号只能凭口令登录"
          autocomplete="off"
          spellcheck="false"
        />
      </label>

      <PasswordField
        v-model="form.password"
        label="初始口令"
        placeholder="至少 8 位，含大小写字母与数字"
        autocomplete="new-password"
      />

      <PasswordField
        v-model="form.operatorPassword"
        label="您的登录口令（二次确认）"
        placeholder="输入你自己的密码以确认身份"
        autocomplete="off"
        :invalid="!!error"
        :error="error"
        @enter="confirm"
      />
    </div>

    <template #footer>
      <button type="button" class="btn" :disabled="creating" @click="close">取消</button>
      <button type="button" class="btn btn--primary" :disabled="creating" @click="confirm">
        <Spinner v-if="creating" :size="13" />
        <span>创建账号</span>
      </button>
    </template>
  </AppWindow>
</template>

<style scoped src="../../styles/form-dialog.css"></style>
