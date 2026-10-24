<script setup>
import { computed, ref, watch } from 'vue'
import AppIcon from '../AppIcon.vue'
import AppWindow from '../AppWindow.vue'
import Spinner from '../Spinner.vue'
import { useSessionStore } from '../../stores/session'
import { useToastStore } from '../../stores/toast'
import { roleLabelOf } from '../../utils/userDisplay'

/**
 * 批量处置弹窗：对已选中的多个账号执行**同一个**动作。
 *
 * 三段式（pick → confirm → result），刻意不拆成三个弹窗：
 * 批量处置的语境一旦中断（关掉再开），选中集合就丢了，
 * 而重选 20 个人正是这个功能最想省掉的那一步。
 *
 * 与单条弹窗的分工：
 *   · 单条弹窗（冻结 / 改角色）自带业务表单，一次处理一个人；
 *   · 本弹窗只管"选哪个动作 + 填该动作需要的参数 + 确认 + 看结果"，
 *     真正的执行全部交给后端批量接口 —— 后端逐条调用单条入口，
 *     所以这里的动作与单条**行为一致**，不存在第二套规则。
 *
 * 危险动作（注销 / 改角色）额外要求勾选确认：
 * 批量误点的代价是 N 倍的，而"列出名字"在 20 个目标时会变成一堵墙，
 * 勾一个明确的知晓项比逼人读完 20 行更有效。
 */
const props = defineProps({
  /** 已选中的用户名清单；空数组 ⇒ 弹窗关闭 */
  usernames: { type: Array, default: () => [] },
  /** 用户列表快照，用于在确认页显示角色（判断谁可能被拒） */
  users: { type: Array, default: () => [] }
})
const emit = defineEmits(['close', 'done'])

const session = useSessionStore()
const toast = useToastStore()

const open = computed(() => props.usernames.length > 0)
const step = ref('pick')
const actionKey = ref('')
const reason = ref('')
const role = ref('User')
const operatorPassword = ref('')
const acknowledged = ref(false)
const busy = ref(false)
const result = ref(null)

/** 动作清单 —— 与后端 BatchAction 的六个 key 一一对应，多一个都会 400。 */
const ACTIONS = [
  { key: 'approve', label: '审批通过', tone: '', desc: '把待审批的账号置为启用' },
  { key: 'unlock', label: '解锁 / 解冻', tone: '', desc: '解除口令锁定或沉睡冻结' },
  { key: 'freeze', label: '冻结', tone: 'warn', desc: '禁止登录并吊销票据，可随时解冻' },
  { key: 'reset-face', label: '重置人脸', tone: 'warn', desc: '清掉两套人脸模板，本人需重新录入' },
  { key: 'set-role', label: '变更角色', tone: 'danger', adminOnly: true, desc: '改角色会立即吊销对方票据' },
  { key: 'delete', label: '注销', tone: 'danger', desc: '永久删除，不可恢复' }
]

/** 只有 Admin 能改角色（后端该动作走 RequireAdminAsync）。 */
const actions = computed(() => ACTIONS.filter((a) => !a.adminOnly || session.isRoleAdmin))
const current = computed(() => ACTIONS.find((a) => a.key === actionKey.value) ?? null)
/** 危险动作：需要勾选知晓 */
const needAck = computed(() => actionKey.value === 'delete' || actionKey.value === 'set-role')

const targets = computed(() =>
  props.usernames.map((name) => props.users.find((u) => u.username === name) ?? { username: name, role: '' })
)

// 打开时重置到第一步（上次的残留不该带到新一次操作里）
watch(
  () => props.usernames,
  (list) => {
    if (list.length > 0) {
      step.value = 'pick'
      actionKey.value = ''
      reason.value = ''
      role.value = 'User'
      operatorPassword.value = ''
      acknowledged.value = false
      result.value = null
    }
  }
)

function close() {
  if (busy.value) return
  emit('close')
}

function pick(key) {
  actionKey.value = key
  step.value = 'confirm'
}

function back() {
  step.value = 'pick'
  acknowledged.value = false
}

async function confirm() {
  if (!current.value) return
  busy.value = true
  try {
    const params = { reason: reason.value.trim() }
    if (actionKey.value === 'set-role') {
      params.role = role.value
      params.operatorPassword = operatorPassword.value
    }
    const res = await session.batchAction(actionKey.value, props.usernames, params)
    result.value = res
    step.value = 'result'
    if (res?.allFailed) toast.error(res.message)
    else toast.success(res?.message || '批量处理完成')
    emit('done', res)
  } catch (err) {
    toast.error(err?.message || '批量处理失败')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AppWindow
    :open="open"
    :title="step === 'result' ? '批量处理结果' : `批量处理（已选 ${usernames.length} 个账号）`"
    icon="info"
    :tone="current?.tone || 'normal'"
    :width="560"
    :close-on-overlay="!busy"
    @close="close"
  >
    <!-- 第一步：选动作 -->
    <div v-if="step === 'pick'" class="form">
      <div class="form__notice">
        <AppIcon name="info" :size="15" :stroke-width="2" />
        <span>
          将对选中的 <strong>{{ usernames.length }}</strong> 个账号执行同一个动作。
          <strong>每个账号单独处理、单独留痕</strong>：无权处置的会被跳过，其余照常执行。
        </span>
      </div>
      <div class="batch-actions">
        <button
          v-for="a in actions"
          :key="a.key"
          type="button"
          class="batch-action"
          :class="a.tone ? `batch-action--${a.tone}` : ''"
          @click="pick(a.key)"
        >
          <span class="batch-action__label">{{ a.label }}</span>
          <span class="batch-action__desc">{{ a.desc }}</span>
        </button>
      </div>
    </div>

    <!-- 第二步：确认 + 参数 -->
    <div v-else-if="step === 'confirm'" class="form">
      <div class="form__notice" :class="{ 'form__notice--danger': current?.tone === 'danger' }">
        <AppIcon name="info" :size="15" :stroke-width="2" />
        <span>
          即将对以下 <strong>{{ usernames.length }}</strong> 个账号执行
          <strong>「{{ current?.label }}」</strong>。{{ current?.desc }}。
        </span>
      </div>

      <div class="batch-list">
        <span v-for="u in targets" :key="u.username" class="batch-chip">
          {{ u.username }}
          <em v-if="u.role">{{ roleLabelOf(u) }}</em>
        </span>
      </div>

      <label v-if="actionKey === 'freeze'" class="field">
        <span class="field__label">冻结原因（可选，会记入每个账号的审计）</span>
        <input v-model="reason" class="input" type="text" placeholder="例如：超过 90 天未登录" maxlength="100" />
      </label>

      <template v-if="actionKey === 'set-role'">
        <label class="field">
          <span class="field__label">目标角色</span>
          <select v-model="role" class="input">
            <option value="User">普通用户</option>
            <option value="UserAdmin">用户管理员</option>
            <option value="AuditAdmin">审计管理员</option>
          </select>
        </label>
        <label class="field">
          <span class="field__label">您的登录口令（二次确认，与单个改角色要求一致）</span>
          <input v-model="operatorPassword" class="input" type="password" autocomplete="current-password" />
        </label>
      </template>

      <label v-if="needAck" class="batch-ack">
        <input v-model="acknowledged" type="checkbox" />
        <span>
          {{ actionKey === 'delete' ? '我确认这些账号将被永久删除，且无法恢复。' : '我确认这些账号的角色将被变更，对方需重新登录。' }}
        </span>
      </label>
    </div>

    <!-- 第三步：结果 -->
    <div v-else class="form">
      <div class="form__notice" :class="{ 'form__notice--danger': result?.allFailed }">
        <AppIcon name="info" :size="15" :stroke-width="2" />
        <span>{{ result?.message }}</span>
      </div>
      <table class="batch-result">
        <thead>
          <tr>
            <th>账号</th>
            <th style="width: 76px">结果</th>
            <th>说明</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="it in result?.summary?.items ?? []" :key="it.username">
            <td class="table__mono">{{ it.username }}</td>
            <td>
              <span class="tag" :class="it.success ? 'tag--ok' : 'tag--danger'">
                {{ it.success ? '成功' : '未处理' }}
              </span>
            </td>
            <td class="muted">{{ it.message }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <template #footer>
      <template v-if="step === 'pick'">
        <button type="button" class="btn" @click="close">取消</button>
      </template>
      <template v-else-if="step === 'confirm'">
        <button type="button" class="btn" :disabled="busy" @click="back">返回</button>
        <button
          type="button"
          class="btn"
          :class="current?.tone === 'danger' ? 'btn--danger' : current?.tone === 'warn' ? 'btn--warn' : 'btn--primary'"
          :disabled="busy || (needAck && !acknowledged)"
          @click="confirm"
        >
          <Spinner v-if="busy" :size="13" />
          <span>确认执行（{{ usernames.length }} 个）</span>
        </button>
      </template>
      <template v-else>
        <button type="button" class="btn btn--primary" @click="close">完成</button>
      </template>
    </template>
  </AppWindow>
</template>

<style scoped src="../../styles/form-dialog.css"></style>

<style scoped>
.batch-actions {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}
.batch-action {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 12px 14px;
  text-align: left;
  border-radius: var(--radius-md, 8px);
  border: 0.5px solid var(--color-border-tertiary, rgba(255, 255, 255, 0.15));
  background: var(--color-background-secondary, transparent);
  cursor: pointer;
}
.batch-action:hover {
  border-color: var(--color-border-secondary, rgba(255, 255, 255, 0.3));
}
.batch-action__label {
  font-size: 13px;
  font-weight: 500;
}
.batch-action__desc {
  font-size: 11px;
  opacity: 0.7;
  line-height: 1.5;
}
.batch-action--warn .batch-action__label {
  color: var(--color-text-warning, #f0c46c);
}
.batch-action--danger .batch-action__label {
  color: var(--color-text-danger, #f09595);
}
.batch-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  max-height: 132px;
  overflow-y: auto;
  padding: 8px;
  border-radius: var(--radius-md, 8px);
  background: var(--color-background-tertiary, rgba(255, 255, 255, 0.04));
}
.batch-chip {
  font-size: 12px;
  font-family: var(--font-mono, monospace);
  padding: 2px 8px;
  border-radius: 4px;
  border: 0.5px solid var(--color-border-tertiary, rgba(255, 255, 255, 0.15));
}
.batch-chip em {
  font-style: normal;
  opacity: 0.6;
  margin-left: 4px;
}
.batch-ack {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 12px;
  line-height: 1.6;
}
.batch-result {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.batch-result th,
.batch-result td {
  text-align: left;
  padding: 6px 8px;
  border-bottom: 0.5px solid var(--color-border-tertiary, rgba(255, 255, 255, 0.12));
}
.batch-result th {
  font-weight: 500;
  opacity: 0.7;
}
</style>
