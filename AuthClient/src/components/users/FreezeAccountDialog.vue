<script setup>
import { ref, watch } from 'vue'
import AppIcon from '../AppIcon.vue'
import AppWindow from '../AppWindow.vue'
import Spinner from '../Spinner.vue'
import { useSessionStore } from '../../stores/session'
import { useToastStore } from '../../stores/toast'
import { dormantText } from '../../utils/userDisplay'

/**
 * 冻结账号弹窗（沉睡账号治理）。
 *
 * 冻结是**可逆**操作，所以用 warn 色调而非 danger —— 与「注销」（永久、红色）
 * 在视觉上必须明确区分，否则容易把可恢复的处置看成不可恢复的删除。
 *
 * 后端会同时：置 Disabled + 吊销该账号全部票据 + 写审计 DORMANT_FREEZE。
 * 调用方只传 `target`，其余状态自持。
 */
const props = defineProps({
  target: { type: Object, default: null }
})
const emit = defineEmits(['update:target'])

const session = useSessionStore()
const toast = useToastStore()

const reason = ref('')
const freezing = ref(false)

// 打开时清空原因（与拆分前 openFreeze() 的行为一致）
watch(
  () => props.target,
  (u) => {
    if (u) reason.value = ''
  }
)

function close() {
  emit('update:target', null)
}

async function confirm() {
  if (!props.target) return
  freezing.value = true
  try {
    const res = await session.freezeUser(props.target.username, reason.value.trim())
    toast.success(res?.message || '账号已冻结')
    close()
  } catch (err) {
    toast.error(err?.message || '冻结失败')
  } finally {
    freezing.value = false
  }
}
</script>

<template>
  <AppWindow
    :open="!!target"
    title="冻结账号"
    icon="lock"
    tone="warn"
    :width="440"
    :close-on-overlay="!freezing"
    @close="!freezing && close()"
  >
    <div v-if="target" class="form">
      <div class="form__notice">
        <AppIcon name="info" :size="15" :stroke-width="2" />
        <span>
          将冻结「<strong>{{ target.username }}</strong>」
          （{{ dormantText(target) }}）。
          冻结后该账号<strong>无法登录</strong>，其已登录的会话会立即失效；
          但数据全部保留，随时可在此页面<strong>解除冻结</strong>。
        </span>
      </div>

      <label class="field">
        <span class="field__label">冻结原因（可选，会记入审计）</span>
        <input
          v-model="reason"
          class="input"
          type="text"
          placeholder="例如：超过 90 天未登录"
          maxlength="100"
          @keyup.enter="confirm"
        />
      </label>
    </div>

    <template #footer>
      <button type="button" class="btn" :disabled="freezing" @click="close">取消</button>
      <button type="button" class="btn btn--warn" :disabled="freezing" @click="confirm">
        <Spinner v-if="freezing" :size="13" />
        <span>确认冻结</span>
      </button>
    </template>
  </AppWindow>
</template>

<style scoped src="../../styles/form-dialog.css"></style>
