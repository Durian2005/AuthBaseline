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

/**
 * 阈值那一行的悬浮说明。
 * 为什么不把它塞进可见文本：卡片刻意只留三项基础状态，把 AND 的机制写进正文
 * 会把日常界面变成一份说明书；但"两个数是什么意思"必须能查到，否则那两个数
 * 看起来像是范围（0.30–0.46），恰好把语义说反了。
 */
const thresholdTitle = computed(() =>
  status.value?.sfaceThreshold != null
    ? '主模型（ArcFace）/ 第二模型（SFace）：两个都达到才通过（AND）'
    : '判定阈值'
)

function errorText(err) {
  return err instanceof ApiError ? err.message : err?.message || '操作失败'
}

/**
 * 卡片只展示三项基础状态：录入状态 / 最近录入 / 判定阈值。
 *
 * 活体判定、多脸闸门、特征模型这三项**刻意不在这里显示**（10-19 用户要求收敛）。
 * 它们不是没了：活体与多脸开关仍然写在**后端启动日志**里（`[FaceId] 活体判定已关闭…`
 * `多脸 拒绝/已放行`），`GET /api/faceid/status` 也照旧下发；只是卡片不再摆一行行参数。
 * 代价要清楚：界面上不再主动声明"活体是关的"，回答"有没有反欺骗"只能靠日志与环境变量。
 */

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
        <!-- 阶段 2 起判定是两个模型相与（AND）：只显示一个数会让用户以为"过一个就行"。
             主模型（ArcFace）/ 第二模型（SFace）并排给出，第二个数缺失时退回单值。 -->
        <span class="sec__value" :title="thresholdTitle">
          {{ status?.threshold != null ? status.threshold.toFixed(2) : '—' }}
          <template v-if="status?.sfaceThreshold != null">
            / {{ status.sfaceThreshold.toFixed(2) }}
          </template>
        </span>
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
