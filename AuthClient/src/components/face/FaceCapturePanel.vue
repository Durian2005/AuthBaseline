<script setup>
import { computed } from 'vue'
import AppIcon from '../AppIcon.vue'
import Spinner from '../Spinner.vue'

/**
 * 活体动作挑战面板 —— 登录第二因子与"录入人脸"两步共用的中间态。
 *
 * 为什么两个场景共用一个组件：它们在**用户视角下是同一件事**
 * （"后端让我做个动作，我做完它去采一帧"），差别只有措辞。
 * 各写一份必然分叉，而"动作提示的判定口径"一旦分叉，
 * 用户照着一个版本的提示做动作、却被另一个版本的口径拒绝，就非常难解释。
 *
 * ⚠️ 这里**刻意没有摄像头取景框画面**，不是没做，是做不了也不该做：
 *   · 采集发生在**服务端进程**内（见设计文档 §四：采集端必须留在服务端，
 *     否则攻击者可以不碰摄像头直接提交一个特征向量）；
 *   · 前端若自己去开一路摄像头做预览，就会与后端抢同一个设备
 *     （Windows DSHOW 下第二次打开通常直接失败），把真正的采集挤掉；
 *   · 后端若把画面推给前端，就等于开了一个**未鉴权**的摄像头画面流 ——
 *     本机任何页面都能来拉。
 *   所以取景框只作为"摄像头语境"的符号，并明确写出画面为何不显示。
 */
const props = defineProps({
  /** 'left' | 'right' | 'up' | 'down' */
  action: { type: String, default: '' },
  actionText: { type: String, default: '' },
  actionHint: { type: String, default: '' },
  /** 采集进行中：按钮进入 loading 且不可重复点 */
  busy: { type: Boolean, default: false },
  /** 主按钮文案 */
  confirmText: { type: String, default: '开始采集' },
  /** 紧凑模式：嵌在既有面板里时用（去掉外边框与阴影） */
  compact: { type: Boolean, default: false }
})

defineEmits(['capture', 'cancel'])

/** 箭头朝向：以"指右"为基准旋转 */
const arrowAngle = computed(
  () => ({ right: 0, down: 90, left: 180, up: 270 })[props.action] ?? 0
)
</script>

<template>
  <div class="fcp" :class="{ 'fcp--compact': compact }">
    <!-- 取景框：四角 + 方向箭头。画面不显示（原因见组件说明） -->
    <div class="fcp__frame" :class="{ 'is-busy': busy }">
      <svg class="fcp__brackets" viewBox="0 0 120 120" aria-hidden="true">
        <path d="M12 38V22a10 10 0 0 1 10-10h16" />
        <path d="M82 12h16a10 10 0 0 1 10 10v16" />
        <path d="M108 82v16a10 10 0 0 1-10 10H82" />
        <path d="M38 108H22a10 10 0 0 1-10-10V82" />
      </svg>

      <svg
        v-if="action"
        class="fcp__arrow"
        viewBox="0 0 48 48"
        :style="{ transform: `rotate(${arrowAngle}deg)` }"
        aria-hidden="true"
      >
        <path d="M8 24h28" />
        <path d="M28 16l8 8-8 8" />
      </svg>
      <AppIcon v-else name="face" :size="30" class="fcp__glyph" />
    </div>

    <p v-if="actionText" class="fcp__action">{{ actionText }}</p>
    <p v-if="actionHint" class="fcp__hint">{{ actionHint }}</p>

    <p class="fcp__note">
      <AppIcon name="info" :size="12" />
      <span>画面由本机后端直接采集，界面不显示取景画面</span>
    </p>

    <div class="fcp__actions">
      <button
        type="button"
        class="btn btn--primary"
        :disabled="busy"
        data-autofocus
        @click="$emit('capture')"
      >
        <Spinner v-if="busy" :size="14" />
        <AppIcon v-else name="face" :size="15" />
        <span>{{ busy ? '正在采集…' : confirmText }}</span>
      </button>
      <button type="button" class="btn btn--ghost" :disabled="busy" @click="$emit('cancel')">
        取消
      </button>
    </div>
  </div>
</template>

<style scoped>
.fcp {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--sp-3);
  padding: var(--sp-5) var(--sp-4);
  border: 1px solid var(--c-border);
  border-radius: var(--r-lg);
  background: var(--c-surface-2);
  text-align: center;
}
.fcp--compact {
  padding: var(--sp-4);
  border: 0;
  background: transparent;
  border-radius: 0;
}

.fcp__frame {
  position: relative;
  width: 108px;
  height: 108px;
  display: grid;
  place-items: center;
  color: var(--c-primary);
  transition: color var(--t-base) var(--ease);
}
.fcp__frame.is-busy {
  color: var(--c-accent);
}

.fcp__brackets {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  fill: none;
  stroke: currentColor;
  stroke-width: 3;
  stroke-linecap: round;
  stroke-opacity: 0.55;
}
.fcp__frame.is-busy .fcp__brackets {
  animation: fcp-pulse 1.1s var(--ease) infinite;
}

.fcp__arrow {
  width: 46px;
  height: 46px;
  fill: none;
  stroke: currentColor;
  stroke-width: 3.4;
  stroke-linecap: round;
  stroke-linejoin: round;
  transition: transform var(--t-slow) var(--ease-out);
}
.fcp__glyph {
  color: currentColor;
}

@keyframes fcp-pulse {
  0%,
  100% {
    stroke-opacity: 0.28;
  }
  50% {
    stroke-opacity: 0.85;
  }
}

.fcp__action {
  font-size: var(--fs-md);
  font-weight: 600;
  color: var(--c-text);
  line-height: 1.4;
}
.fcp__hint {
  font-size: var(--fs-sm);
  color: var(--c-text-muted);
  line-height: 1.5;
}

.fcp__note {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--sp-1);
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
  line-height: 1.4;
}
.fcp__note svg {
  flex-shrink: 0;
}

.fcp__actions {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  margin-top: var(--sp-1);
}
</style>
