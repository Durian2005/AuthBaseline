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
 * 初始口令**固定为 <see cref="INITIAL_PASSWORD"/>，不再让管理员填写**。
 * 这不是偷懒：表单里原本并排有两个口令框（"初始口令"与"您的登录口令"），
 * 很容易把**自己的口令**填进"初始口令"，于是新账号的密码就等于管理员密码 ——
 * 一次填反就把管理员凭据交给了别人。固定值从结构上消掉了这个失误，
 * 也让批量建测试账号（人脸样本需要很多账号）变成只填用户名。
 *
 * ⚠️ 代价必须写在界面上：初始口令是**公开的约定值**，任何知道用户名的人
 *    都能在本人改密之前登进来。所以提示语明确要求"创建后立刻让本人改密"。
 */
const props = defineProps({
  open: { type: Boolean, default: false }
})
const emit = defineEmits(['update:open'])

const session = useSessionStore()
const toast = useToastStore()

/**
 * 统一初始口令。
 *
 * 8 位、含大小写与数字 ⇒ 满足后端的复杂度裁决（IS_PASSWORD_COMPLEX），
 * 不需要为"固定口令"在后端开一个例外分支 —— 那条例外迟早会被别处复用。
 */
const INITIAL_PASSWORD = 'Abc12345'

const form = ref({ username: '', email: '', role: 'UserAdmin', operatorPassword: '' })
const error = ref('')
const creating = ref(false)

// 每次打开都回到干净的初始状态（与拆分前 openCreate() 的行为一致）
watch(
  () => props.open,
  (v) => {
    if (!v) return
    form.value = { username: '', email: '', role: 'UserAdmin', operatorPassword: '' }
    error.value = ''
  }
)

function close() {
  emit('update:open', false)
}

async function confirm() {
  const f = form.value
  if (!f.username.trim() || !f.operatorPassword) {
    error.value = '请填写账号与您本人的登录口令'
    return
  }
  creating.value = true
  error.value = ''
  try {
    const res = await session.createAccount(
      f.username.trim(),
      INITIAL_PASSWORD,
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
          新建账号<strong>无需绑定邮箱</strong>，创建后即可用初始口令 <strong>Abc12345</strong> 登录。
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

      <!-- 初始口令固定：只读展示，避免管理员把自己的口令填进来 -->
      <div class="field">
        <span class="field__label">初始口令（固定）</span>
        <input class="input mono" :value="INITIAL_PASSWORD" readonly tabindex="-1" />
        <p class="field__hint">
          所有新建账号统一为这个口令，创建后请让本人登录并立即修改。
          它只用于"第一次交接"，不是长期凭据。
        </p>
      </div>

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
