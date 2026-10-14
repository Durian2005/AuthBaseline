<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import AppIcon from '../AppIcon.vue'
import { api } from '../../api/client'
import { createPoller } from '../../composables/poller'

/**
 * 人脸识别画面 —— 登录第二因子与"录入人脸"共用的**取景框**。
 *
 * ── 画面从哪来（这一条决定它是不是安全的）────────────────────────
 * 画面**不是**前端自己开摄像头拿的，而是后端把它采集、检测、画好框之后
 * 逐帧下发的 JPEG。前端从头到尾不碰摄像头设备，也不上送任何画面或特征。
 *
 * 两个必须这么做的理由（都不是洁癖）：
 *   ① 采集端留在服务端，是这条功能的立身之本 —— 否则攻击者可以不碰摄像头、
 *      直接 POST 一个特征向量（见 docs/design/FACE-AUTH-DESIGN.md §四）；
 *   ② 前端自己去开一路摄像头会**与后端抢同一个设备**：Windows DSHOW 下
 *      第二次打开通常直接失败，会把真正的采集挤掉 —— 也就是说，
 *      "让前端开摄像头做预览"这条看起来更省事的路，实际会让功能直接坏掉。
 *
 * ── 为什么不把框的坐标下发、让前端自己画 ────────────────────────
 * 5 个关键点属于生物特征。服务端画成框再下发，出去的只是**可视化结果**，
 * 前端手里没有坐标、没有关键点、没有特征。
 *
 * ── 为什么用 fetch + canvas 而不是 <img src="…"> ─────────────────
 * 桌面壳有 CSP，`img-src` 只放行 'self' / asset: / data:，既不含后端源
 * （http://127.0.0.1:*）也不含 blob:。而 `connect-src` 是放行后端的，
 * 所以走 fetch 拿字节、再用 canvas 画出来 —— **不需要给 CSP 开任何新的口子**，
 * 顺带还能读到响应头里的检测状态。
 */
const props = defineProps({
  /** 一次性挑战 token（不是会话票据）。为空时整个组件不工作。 */
  token: { type: String, default: '' },
  /** 动作指令（服务端下发），叠加在画面左下角 */
  actionText: { type: String, default: '' },
  /** 本机判定阈值，仅用于显示，不参与任何判定 */
  threshold: { type: Number, default: null },
  /** 采集进行中：叠加提示用 */
  busy: { type: Boolean, default: false }
})

const canvasRef = ref(null)
/** 服务端随帧下发的粗粒度状态：'' | down | no-face | detected | action | returned */
const state = ref('')
const score = ref(null)
/** 首帧之前的"还在取画面"状态 */
const warming = ref(true)

let lastBitmap = null
let inFlight = false

/** 拉一帧。整条链路都不抛错：预览是锦上添花，失败不该打断认证流程。 */
async function pull() {
  if (inFlight || !props.token) return
  inFlight = true
  try {
    const res = await fetch(api.facePreviewUrl(props.token), { cache: 'no-store' })
    if (!res.ok) {
      // 503 = 窗口开着但还没攒出第一帧（或引擎不可用）
      if (res.status === 503) warming.value = true
      else if (res.status === 404) state.value = ''
      return
    }

    const nextState = res.headers.get('X-Face-State') || ''
    const nextScore = res.headers.get('X-Face-Score') || ''
    const blob = await res.blob()
    const bitmap = await createImageBitmap(blob)

    const canvas = canvasRef.value
    if (canvas) {
      if (canvas.width !== bitmap.width || canvas.height !== bitmap.height) {
        canvas.width = bitmap.width
        canvas.height = bitmap.height
      }
      const ctx = canvas.getContext('2d')
      ctx.drawImage(bitmap, 0, 0)
      state.value = nextState
      score.value = nextScore ? Number(nextScore) : null
      warming.value = false
    }
    // 上一张解码结果要显式关掉，否则每帧漏一张位图，几十秒就能把内存顶起来
    if (lastBitmap) lastBitmap.close()
    lastBitmap = bitmap
  } catch {
    /* 网络抖一下不弹错误：下一拍自然会补上 */
  } finally {
    inFlight = false
  }
}

const poller = createPoller({
  name: 'face-preview',
  guard: () => !!props.token,
  task: pull,
  intervalMs: 130,
  immediate: true,
  swallowError: true
})

onMounted(() => poller.start())
onBeforeUnmount(() => {
  poller.stop()
  if (lastBitmap) lastBitmap.close()
  lastBitmap = null
})

// 换了一张挑战（例如重试）就立刻重启取帧，不要等下一拍
watch(
  () => props.token,
  () => {
    state.value = ''
    score.value = null
    warming.value = true
    poller.start()
  }
)

const badge = computed(() => {
  if (warming.value) return { text: '正在取画面…', tone: 'off' }
  switch (state.value) {
    case 'detected':
      return { text: '已检测到人脸', tone: 'ok' }
    case 'no-face':
      return { text: '未检测到人脸', tone: 'warn' }
    case 'action':
      return { text: '请按提示完成动作', tone: 'warn' }
    case 'returned':
      return { text: '动作已识别 · 请转回正对摄像头', tone: 'ok' }
    case 'down':
      return { text: '画面不可用', tone: 'off' }
    default:
      return { text: '正在取画面…', tone: 'off' }
  }
})

const detectedText = computed(() => {
  if (warming.value) return '—'
  if (state.value === 'no-face') return '0 张'
  if (state.value === 'down') return '—'
  if (score.value == null) return '已检测到'
  return `1 张 · ${score.value.toFixed(4)}`
})

const thresholdText = computed(() =>
  props.threshold != null ? `≥ ${props.threshold.toFixed(2)}` : '—'
)
</script>

<template>
  <div class="fpv">
    <div class="fpv__stage" :class="{ 'is-busy': busy }">
      <!-- 初值就按后端采集尺寸给，避免首帧到达时取景框高度跳一下 -->
      <canvas ref="canvasRef" class="fpv__canvas" width="640" height="480" />

      <span class="fpv__badge" :class="`fpv__badge--${badge.tone}`">
        <span class="fpv__dot" />
        {{ badge.text }}
      </span>

      <span v-if="actionText" class="fpv__hint">
        <AppIcon name="face" :size="12" />
        <span>{{ actionText }}</span>
      </span>

      <span v-if="busy" class="fpv__rec">
        <span class="fpv__dot" /> 正在采集
      </span>
    </div>

    <div class="fpv__stats">
      <div class="fpv__stat">
        <span class="fpv__stat-k">检测结果</span>
        <span class="fpv__stat-v">{{ detectedText }}</span>
      </div>
      <div class="fpv__stat">
        <span class="fpv__stat-k">判定阈值</span>
        <span class="fpv__stat-v">{{ thresholdText }}</span>
      </div>
      <div class="fpv__stat">
        <span class="fpv__stat-k">活体检测</span>
        <span class="fpv__stat-v">动作挑战</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.fpv {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
  width: 100%;
}

.fpv__stage {
  position: relative;
  border: 1px solid var(--c-border);
  border-radius: var(--r-lg);
  overflow: hidden;
  background: #0b0a12;
  line-height: 0;
  transition: border-color var(--t-base) var(--ease);
}
.fpv__stage.is-busy {
  border-color: var(--c-accent);
}

.fpv__canvas {
  display: block;
  width: 100%;
  height: auto;
}

.fpv__badge {
  position: absolute;
  top: var(--sp-2);
  left: var(--sp-2);
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 9px;
  border-radius: 999px;
  font-size: var(--fs-xs);
  line-height: 1.5;
  color: #fff;
  background: rgba(12, 10, 20, 0.62);
  backdrop-filter: blur(3px);
  border: 1px solid rgba(255, 255, 255, 0.12);
}
.fpv__badge--ok {
  color: #b6f5c6;
  border-color: rgba(96, 220, 96, 0.45);
}
.fpv__badge--warn {
  color: #ffd79a;
  border-color: rgba(255, 190, 0, 0.45);
}

.fpv__dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px currentColor;
  flex-shrink: 0;
}

.fpv__hint {
  position: absolute;
  left: var(--sp-2);
  bottom: var(--sp-2);
  max-width: calc(100% - var(--sp-4));
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: var(--fs-xs);
  line-height: 1.5;
  color: #fff;
  background: rgba(12, 10, 20, 0.68);
  border: 1px solid rgba(255, 255, 255, 0.12);
}

.fpv__rec {
  position: absolute;
  top: var(--sp-2);
  right: var(--sp-2);
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 9px;
  border-radius: 999px;
  font-size: var(--fs-xs);
  line-height: 1.5;
  color: var(--c-accent);
  background: rgba(12, 10, 20, 0.62);
  border: 1px solid color-mix(in srgb, var(--c-accent) 45%, transparent);
}

.fpv__stats {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--sp-2);
}
.fpv__stat {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: var(--sp-2) var(--sp-3);
  border: 1px solid var(--c-border);
  border-radius: var(--r-md);
  background: var(--c-surface-2);
}
.fpv__stat-k {
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
}
.fpv__stat-v {
  font-size: var(--fs-sm);
  font-weight: 600;
  color: var(--c-text);
  font-variant-numeric: tabular-nums;
}
</style>
