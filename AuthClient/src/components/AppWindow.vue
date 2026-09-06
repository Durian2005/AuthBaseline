<script setup>
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'
import AppIcon from './AppIcon.vue'

/**
 * 可拖拽的模态子窗口 —— 桌面软件的对话框隐喻。
 * 标题栏按住可拖动，Esc 关闭，点击遮罩关闭。
 */
const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: '' },
  icon: { type: String, default: 'info' },
  width: { type: Number, default: 420 },
  closeOnOverlay: { type: Boolean, default: true },
  tone: { type: String, default: 'primary' } // primary | danger | warn
})

const emit = defineEmits(['close'])

const winRef = ref(null)
const pos = ref({ x: 0, y: 0 })
const dragging = ref(false)
let origin = { px: 0, py: 0, x: 0, y: 0 }

function place() {
  const el = winRef.value
  const w = el?.offsetWidth || props.width
  const h = el?.offsetHeight || 240
  pos.value = {
    x: Math.max(12, Math.round((window.innerWidth - w) / 2)),
    y: Math.max(12, Math.round((window.innerHeight - h) / 2.7))
  }
}

watch(
  () => props.open,
  async (open) => {
    if (open) {
      await nextTick()
      place()
      document.addEventListener('keydown', onKeydown)
      nextTick(() => {
        const target = winRef.value?.querySelector('[data-autofocus]')
        if (target) target.focus()
        else winRef.value?.focus()
      })
    } else {
      document.removeEventListener('keydown', onKeydown)
      stopDrag()
    }
  }
)

function onKeydown(e) {
  if (e.key === 'Escape') {
    e.stopPropagation()
    emit('close')
  }
}

function startDrag(e) {
  if (e.button !== 0) return
  dragging.value = true
  origin = { px: e.clientX, py: e.clientY, x: pos.value.x, y: pos.value.y }
  document.addEventListener('mousemove', onDrag)
  document.addEventListener('mouseup', stopDrag)
}

function onDrag(e) {
  const el = winRef.value
  const w = el?.offsetWidth || props.width
  const h = el?.offsetHeight || 240
  const maxX = Math.max(12, window.innerWidth - w - 12)
  const maxY = Math.max(12, window.innerHeight - h - 12)
  pos.value = {
    x: Math.min(Math.max(12, origin.x + e.clientX - origin.px), maxX),
    y: Math.min(Math.max(12, origin.y + e.clientY - origin.py), maxY)
  }
}

function stopDrag() {
  dragging.value = false
  document.removeEventListener('mousemove', onDrag)
  document.removeEventListener('mouseup', stopDrag)
}

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown)
  stopDrag()
})
</script>

<template>
  <Teleport to="body">
    <Transition name="win">
      <div v-if="open" class="overlay" @click.self="closeOnOverlay && emit('close')">
        <div
          ref="winRef"
          class="win"
          :class="{ 'is-dragging': dragging }"
          :style="{ left: pos.x + 'px', top: pos.y + 'px', width: width + 'px' }"
          role="dialog"
          aria-modal="true"
          :aria-label="title"
          tabindex="-1"
        >
          <header class="win__bar" @mousedown="startDrag">
            <div class="win__title">
              <AppIcon :name="icon" :size="14" :stroke-width="2" />
              <span>{{ title }}</span>
            </div>
            <button type="button" class="win__close" aria-label="关闭对话框" @click="emit('close')">
              <AppIcon name="x" :size="13" :stroke-width="2" />
            </button>
          </header>

          <div class="win__body" :class="`win__body--${tone}`">
            <slot />
          </div>

          <footer v-if="$slots.footer" class="win__footer">
            <slot name="footer" />
          </footer>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.overlay {
  position: fixed;
  inset: 0;
  z-index: 200;
  background: rgba(8, 15, 28, 0.42);
  backdrop-filter: blur(2px);
}

.win {
  position: fixed;
  border-radius: var(--r-lg);
  background: var(--c-window);
  border: 1px solid var(--c-border-strong);
  box-shadow: var(--sh-dialog);
  overflow: hidden;
  transition: box-shadow var(--t-base) var(--ease);
}
.win.is-dragging {
  box-shadow: var(--sh-dialog), 0 0 0 1px var(--c-primary);
}

.win__bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 32px;
  padding-left: var(--sp-3);
  background: var(--c-titlebar);
  border-bottom: 1px solid var(--c-border);
  cursor: grab;
  user-select: none;
}
.win.is-dragging .win__bar {
  cursor: grabbing;
}

.win__title {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  font-size: var(--fs-base);
  font-weight: 600;
  color: var(--c-text);
}

.win__close {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 31px;
  border: 0;
  background: transparent;
  color: var(--c-text-muted);
  cursor: pointer;
  transition: background var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
}
.win__close:hover {
  background: var(--c-danger);
  color: #fff;
}

.win__body {
  padding: var(--sp-4);
  font-size: var(--fs-base);
  color: var(--c-text);
}
.win__body--danger {
  border-top: 2px solid var(--c-danger);
}
.win__body--warn {
  border-top: 2px solid var(--st-pending-fg);
}

.win__footer {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--sp-2);
  padding: var(--sp-3) var(--sp-4);
  background: var(--c-panel);
  border-top: 1px solid var(--c-border);
}

/* 进场动画 */
.win-enter-active,
.win-leave-active {
  transition: opacity var(--t-base) var(--ease);
}
.win-enter-active .win {
  transition: transform var(--t-slow) var(--ease-out), opacity var(--t-slow) var(--ease-out);
}
.win-leave-active .win {
  transition: transform var(--t-base) var(--ease), opacity var(--t-base) var(--ease);
}
.win-enter-from,
.win-leave-to {
  opacity: 0;
}
.win-enter-from .win,
.win-leave-to .win {
  opacity: 0;
  transform: scale(0.96) translateY(-6px);
}
</style>
