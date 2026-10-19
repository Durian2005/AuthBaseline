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

/**
 * 活体判定的显示文案。
 *
 * 刻意把"模型不可用"单列，不并进上面的"引擎不可用"：
 * 引擎好、活体模型缺失时，录入会被 fail closed 拒绝 —— 这时如果界面只说
 * "引擎正常"，用户会一直怀疑是摄像头或光线的问题。
 */
const padText = computed(() => {
  const s = status.value
  if (!s) return '—'
  if (!s.padEnabled) return '已关闭（照片可通过）'
  if (!s.padReady) return '模型不可用 ⇒ 录入将被拒绝'
  return `已启用 · ${s.padMinLive != null ? s.padMinLive.toFixed(2) : '—'}`
})

/**
 * 多脸闸门状态：默认拒绝；给照片测试放开时，取画面里面积最大的那张。
 * 必须在界面上可见 —— 放开之后"存进去的是谁"就没有保证了。
 */
const multiFaceText = computed(() => {
  const s = status.value
  if (!s) return '—'
  return s.rejectMultipleFaces === false ? '已放行（取最大那张）' : '拒绝'
})

/**
 * 特征模型的**短名**。
 *
 * modelId 的完整形态是 `cv:face_recognition_arcface_w600k_r50.onnx:<sha16>:512`，
 * 直接摆进这一行会折成两行、还挤掉了真正的信息（维度）。这里只保留
 * 权重短名 + 维度，完整值留在 title 里按需悬停查看。
 */
const modelText = computed(() => {
  const raw = status.value?.modelId
  if (!raw) return '—'
  const p = raw.split(':')
  const dim = p[p.length - 1]
  if (p.length < 4) return `${p[0]} · ${dim} 维`
  const weight = p[1].replace(/\.onnx$/i, '').replace(/^face_recognition_/i, '')
  return `${weight} · ${dim} 维`
})

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
        <span class="sec__label">活体判定</span>
        <span class="sec__value">{{ padText }}</span>
      </div>
      <div class="sec__row">
        <span class="sec__label">特征模型</span>
        <span class="sec__value" :title="status?.modelId || ''">{{ modelText }}</span>
      </div>

      <div class="sec__row">
        <span class="sec__label">多脸画面</span>
        <span class="sec__value">{{ multiFaceText }}</span>
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
          <span>点下按钮后请正对摄像头约 1 秒。</span>
        </p>
        <p v-else class="hint hint--warn">
          <AppIcon name="alert-triangle" :size="13" :stroke-width="2" />
          <span>删除后只能口令登录，人脸模板不可恢复。</span>
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
</style>
