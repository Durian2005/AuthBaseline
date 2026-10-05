<script setup>
import { ref, watch } from 'vue'
import AppIcon from '../AppIcon.vue'
import AppWindow from '../AppWindow.vue'
import PasswordField from '../PasswordField.vue'
import Spinner from '../Spinner.vue'
import { useSessionStore } from '../../stores/session'
import { useToastStore } from '../../stores/toast'
import { roleLabelOf } from '../../utils/userDisplay'

/**
 * 变更账号角色弹窗 —— "指定某位管理员为审计管理员"就是走这里。
 *
 * 角色任免是系统内权限最高的操作，后端要求二次校验操作者本人口令。
 * 变更成功后**对方**需要重新登录（后端会吊销其票据），操作者自己的会话不受影响。
 *
 * 调用方只传 `target`（要变更的账号，null 表示不显示），表单状态由本组件自持。
 */
const props = defineProps({
  target: { type: Object, default: null }
})
const emit = defineEmits(['update:target'])

const session = useSessionStore()
const toast = useToastStore()

const form = ref({ role: 'UserAdmin', operatorPassword: '' })
const error = ref('')
const saving = ref(false)

// 每次换目标都重置表单（与拆分前 openRole() 的行为一致）
watch(
  () => props.target,
  (u) => {
    if (!u) return
    // 默认给一个"反直觉但最常用"的预设：从非审计岗切到审计岗
    form.value = {
      role: u.role === 'AuditAdmin' ? 'UserAdmin' : 'AuditAdmin',
      operatorPassword: ''
    }
    error.value = ''
  }
)

function close() {
  emit('update:target', null)
}

async function confirm() {
  if (!props.target) return
  if (!form.value.operatorPassword) {
    error.value = '请输入您本人的登录口令'
    return
  }
  saving.value = true
  error.value = ''
  try {
    const res = await session.setRole(
      props.target.username,
      form.value.role,
      form.value.operatorPassword
    )
    toast.success(res?.message || '角色已变更')
    close()
  } catch (err) {
    error.value = err?.message || '变更失败'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <AppWindow
    :open="!!target"
    title="变更账号角色"
    icon="swap"
    tone="warn"
    :width="460"
    :close-on-overlay="!saving"
    @close="!saving && close()"
  >
    <div v-if="target" class="form">
      <div class="form__notice">
        <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
        <span>
          正在变更「<strong>{{ target.username }}</strong>」的角色
          （当前：{{ roleLabelOf(target) }}）。变更后该账号的登录状态会被作废，
          需要重新登录才能生效。
        </span>
      </div>

      <div v-if="error" class="alert" role="alert">
        <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
        <span class="selectable">{{ error }}</span>
      </div>

      <label class="field">
        <span class="field__label">变更为</span>
        <select v-model="form.role" class="input select">
          <option value="AuditAdmin">审计管理员 —— 只能查看审计日志，不能管理用户</option>
          <option value="UserAdmin">用户管理员 —— 可管理用户，不能查看审计日志</option>
          <option value="User">普通用户 —— 撤销全部管理能力</option>
        </select>
      </label>

      <PasswordField
        v-model="form.operatorPassword"
        label="您的登录口令（二次确认）"
        placeholder="输入你自己的密码以确认身份"
        autocomplete="off"
        :invalid="!!error"
        :error="error"
        autofocus
        @enter="confirm"
      />
    </div>

    <template #footer>
      <button type="button" class="btn" :disabled="saving" @click="close">取消</button>
      <button type="button" class="btn btn--primary" :disabled="saving" @click="confirm">
        <Spinner v-if="saving" :size="13" />
        <span>确认变更</span>
      </button>
    </template>
  </AppWindow>
</template>

<style scoped src="../../styles/form-dialog.css"></style>
