<script setup>
import { computed, onMounted, ref } from 'vue'
import AppIcon from '../AppIcon.vue'
import PasswordField from '../PasswordField.vue'
import Spinner from '../Spinner.vue'
import { useSessionStore } from '../../stores/session'
import { useToastStore } from '../../stores/toast'
import { ApiError } from '../../api/client'
import { formatDateTime } from '../../utils/format'

/**
 * 纯人脸登录（FaceId）卡片 —— 与「刷脸登录」（第二因子）**刻意分成两张卡**。
 *
 * 为什么必须分开显示，而不是合并成一个"人脸设置"：
 *   两者是**不同的登录方式**，安全含义完全不同：
 *     · 第二因子：口令对 + 人脸对，才签票；
 *     · 纯人脸登录：用户名 + 人脸就签票（没有口令参与）。
 *   合并会让用户以为"我录过一次脸，两条路都通了"，而实际上两条链路的模板
 *   各自独立（不同集合、不同特征模型），删掉一边不影响另一边。
 *
 * 交互刻意做成"单步"（输口令 → 点按钮 → 服务端采集约 1 秒）：
 *   本模块没有活体动作挑战，动作没有需要协商的内容。代价是用户点下按钮后
 *   要正对镜头一小会儿，所以文案必须明确说"正在采集"，而不是给一个转圈。
 *
 * 请求体里**只有口令**：画面与特征全部由服务端进程自己采集，
 * 前端既拿不到也传不了。这是"伪造一个向量直接提交"这条路在类型层面就不存在的前提。
 */
const session = useSessionStore()
const toast = useToastStore()

const status = computed(() => session.faceIdStatus)
const busy = computed(() => session.faceIdBusy)

/** idle | enroll | delete —— 输口令的两种用途。 */
const mode = ref('idle')
const password = ref('')
const error = ref('')
const notice = ref('')

const enrolling = computed(() => busy.value && mode.value === 'enroll')
const deleting = computed(() => busy.value && mode.value === 'delete')

/** 引擎不可用 / 模块关闭 / 模型作废，三种"看得见但不能用"的状态。 */
const engineBlocked = computed(() => status.value && (!status.value.enabled || !status.value.engineReady))
const modelMismatch = computed(
  () => !!status.value && status.value.templateCount > 0 && status.value.usableCount === 0
)

function errorText(err) {
  return err instanceof ApiError ? err.message : err?.message || '操作失败'
}

async function load() {
  error.value = ''
  try {
    await session.refreshFaceIdStatus()
  } catch (err) {
    error.value = errorText(err)
  }
}

onMounted(load)

function begin(next) {
  mode.value = next
  password.value = ''
  error.value = ''
  notice.value = ''
}

function cancel() {
  mode.value = 'idle'
  password.value = ''
  error.value = ''
}

async function submit() {
  error.value = ''
  notice.value = ''
  if (!password.value) {
    error.value = '请输入当前登录口令'
    return
  }

  try {
    if (mode.value === 'delete') {
      const res = await session.removeFaceId(password.value)
      notice.value = res?.message || '已删除人脸模板'
      toast.success('已删除纯人脸登录模板')
    } else {
      const res = await session.enrollFaceId(password.value)
      notice.value = res?.message || '已录入人脸模板'
      toast.success('已录入人脸模板，下次可只用用户名 + 人脸登录')
    }
    password.value = ''
    mode.value = 'idle'
  } catch (err) {
    // 口令错误会累计失败次数，所以这里必须把服务端原话显示出来，
    // 不能替换成"录入失败"这种把原因抹平的文案。
    error.value = errorText(err)
  }
}
</script>

<template>
  <section class="panel">
    <div class="panel__head">
      <h3 class="panel__title"><AppIcon name="face" :size="15" /><span>纯人脸登录</span></h3>
      <span class="pill">独立登录方式</span>
    </div>

    <div class="panel__body sec">
      <div v-if="error" class="alert" role="alert">
        <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
        <span class="selectable">{{ error }}</span>
      </div>
      <div v-else-if="notice" class="notice" role="status">
        <AppIcon name="check-circle" :size="15" />
        <span>{{ notice }}</span>
      </div>

      <!-- 模块关闭 / 引擎不可用：说清楚"为什么不能用"，不给一个看起来能点的按钮 -->
      <div v-if="engineBlocked" class="hint hint--warn">
        <AppIcon name="alert-triangle" :size="14" :stroke-width="2" />
        <span>
          {{ status?.enabled ? status?.engineMessage || '本机人脸引擎不可用' : '本系统的纯人脸登录当前未启用' }}
        </span>
      </div>

      <div class="sec__row">
        <span class="sec__label">录入状态</span>
        <span class="sec__value">
          <template v-if="status?.enrolled">
            已录入 {{ status.usableCount }} / {{ status.maxTemplates }} 张
          </template>
          <template v-else>未录入</template>
        </span>
      </div>
      <div class="sec__row">
        <span class="sec__label">最近录入</span>
        <span class="sec__value">{{ status?.enrolledAt ? formatDateTime(status.enrolledAt) : '—' }}</span>
      </div>
      <div class="sec__row">
        <span class="sec__label">判定阈值</span>
        <span class="sec__value">{{ status?.threshold != null ? status.threshold.toFixed(2) : '—' }}</span>
      </div>
      <div class="sec__row">
        <span class="sec__label">特征模型</span>
        <span class="sec__value mono">{{ status?.modelId || '—' }}</span>
      </div>

      <!-- 模板与模型绑定：换了权重，旧模板不能再比，必须明确告诉用户"重新录" -->
      <div v-if="modelMismatch" class="hint hint--warn">
        <AppIcon name="alert-triangle" :size="14" :stroke-width="2" />
        <span>已录入的 {{ status.templateCount }} 张模板录制于旧模型，已作废。请重新录入一张。</span>
      </div>

      <!-- 录入 / 删除：都要当前口令 -->
      <div v-if="mode !== 'idle'" class="form">
        <PasswordField
          v-model="password"
          :label="mode === 'delete' ? '当前登录口令（确认删除）' : '当前登录口令（确认是你本人）'"
          placeholder="请输入当前登录口令"
          autocomplete="off"
          :disabled="busy"
          @enter="submit"
        />

        <p v-if="mode === 'enroll'" class="hint">
          <AppIcon name="info" :size="13" />
          <span>点下按钮后请正对摄像头约 1 秒：画面由服务端采集，不落盘、不进审计。</span>
        </p>
        <p v-else class="hint hint--warn">
          <AppIcon name="alert-triangle" :size="13" :stroke-width="2" />
          <span>删除后该账号只能使用口令登录，人脸模板不可恢复。</span>
        </p>

        <div class="actions">
          <button type="button" class="btn" :class="mode === 'delete' ? 'btn--danger' : 'btn--primary'"
                  :disabled="busy" @click="submit">
            <Spinner v-if="busy" :size="14" />
            <AppIcon v-else :name="mode === 'delete' ? 'trash' : 'check-circle'" :size="15" />
            <span>
              {{ deleting ? '正在删除…' : enrolling ? '正在采集，请正对摄像头…'
                : mode === 'delete' ? '确认删除' : '开始采集' }}
            </span>
          </button>
          <button type="button" class="btn btn--ghost" :disabled="busy" @click="cancel">取消</button>
        </div>
      </div>

      <div v-else class="actions">
        <button type="button" class="btn btn--primary" :disabled="!!engineBlocked || busy"
                @click="begin('enroll')">
          <AppIcon name="face" :size="15" />
          <span>{{ status?.usableCount ? '追加一张人脸' : '录入人脸' }}</span>
        </button>
        <button v-if="status?.enrolled" type="button" class="btn btn--ghost" @click="begin('delete')">
          <AppIcon name="trash" :size="15" />
          <span>删除人脸</span>
        </button>
      </div>

      <ul class="tips">
        <li>
          <AppIcon name="check-circle" :size="13" />
          录入与删除都需要<strong>重新输入当前口令</strong>，输错会累计失败次数
        </li>
        <li>
          <AppIcon name="check-circle" :size="13" />
          模板以 AES-GCM 加密存储，只存特征、不存照片；换模型后旧模板自动作废
        </li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.sec {
  display: flex;
  flex-direction: column;
  gap: var(--sp-3);
}

.sec__row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-3);
  font-size: var(--fs-base);
}
.sec__label {
  color: var(--c-text-muted);
}
.sec__value {
  color: var(--c-text);
  text-align: right;
  word-break: break-all;
}
.mono {
  font-family: var(--font-mono);
  font-size: var(--fs-sm);
}

.pill {
  padding: 1px var(--sp-2);
  border: 1px solid var(--c-border-strong);
  border-radius: var(--r-full);
  background: var(--c-surface-2);
  color: var(--c-text-muted);
  font-size: var(--fs-xs);
  line-height: 1.6;
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

.notice {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  padding: var(--sp-2) var(--sp-3);
  border-radius: var(--r-md);
  border: 1px solid color-mix(in srgb, var(--c-accent) 30%, transparent);
  background: var(--c-accent-soft);
  font-size: var(--fs-sm);
  line-height: 1.5;
}
.notice > svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--st-enabled-fg);
}

.form {
  display: flex;
  flex-direction: column;
  gap: var(--sp-3);
}

.actions {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  flex-wrap: wrap;
}

.hint {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  margin: 0;
  padding: var(--sp-2) var(--sp-3);
  border-radius: var(--r-md);
  background: var(--c-surface-2);
  color: var(--c-text-muted);
  font-size: var(--fs-sm);
  line-height: 1.5;
}
.hint > svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--c-text-subtle);
}
.hint--warn {
  background: var(--c-warn-soft);
  color: var(--c-text);
}
.hint--warn > svg {
  color: var(--c-warn);
}

.tips {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
  margin: 0;
  padding: 0;
  list-style: none;
}
.tips li {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  font-size: var(--fs-sm);
  line-height: 1.5;
  color: var(--c-text-muted);
}
.tips svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--st-enabled-fg);
}
</style>
