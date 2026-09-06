<script setup>
import { storeToRefs } from 'pinia'
import { useToastStore } from '../stores/toast'
import AppIcon from './AppIcon.vue'

const toastStore = useToastStore()
const { toasts } = storeToRefs(toastStore)

const ICONS = {
  success: 'check-circle',
  error: 'alert-triangle',
  warning: 'alert-triangle',
  info: 'info'
}
</script>

<template>
  <!-- 应用内通知：位于窗口右上角，模拟桌面软件的通知气泡 -->
  <div class="toasts" role="region" aria-label="通知">
    <TransitionGroup name="toast">
      <div
        v-for="t in toasts"
        :key="t.id"
        class="toast"
        :class="`toast--${t.type}`"
        role="status"
        aria-live="polite"
      >
        <AppIcon :name="ICONS[t.type] || 'info'" :size="16" :stroke-width="2" />
        <span class="toast__msg selectable">{{ t.message }}</span>
        <button
          type="button"
          class="toast__close"
          aria-label="关闭通知"
          @click="toastStore.dismiss(t.id)"
        >
          <AppIcon name="x" :size="13" :stroke-width="2" />
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toasts {
  position: absolute;
  top: calc(var(--titlebar-h) + 10px);
  right: var(--sp-4);
  z-index: 60;
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
  pointer-events: none;
  max-width: 380px;
}

.toast {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  padding: 9px var(--sp-3);
  border-radius: var(--r-md);
  border: 1px solid var(--c-border-strong);
  background: var(--c-surface);
  box-shadow: var(--sh-popover);
  font-size: var(--fs-base);
  color: var(--c-text);
  pointer-events: auto;
}

.toast__msg {
  flex: 1;
  line-height: 1.45;
  word-break: break-word;
}

.toast__close {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  margin-top: 1px;
  border: 0;
  border-radius: var(--r-xs);
  background: transparent;
  color: var(--c-text-subtle);
  cursor: pointer;
  transition: background var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
}
.toast__close:hover {
  background: var(--c-surface-hover);
  color: var(--c-text);
}

.toast--success {
  border-left: 3px solid var(--st-enabled-fg);
}
.toast--success > :first-child {
  color: var(--st-enabled-fg);
}
.toast--error {
  border-left: 3px solid var(--st-locked-fg);
}
.toast--error > :first-child {
  color: var(--st-locked-fg);
}
.toast--warning {
  border-left: 3px solid var(--st-pending-fg);
}
.toast--warning > :first-child {
  color: var(--st-pending-fg);
}
.toast--info {
  border-left: 3px solid var(--c-info);
}
.toast--info > :first-child {
  color: var(--c-info);
}

/* 进场/退场动画 */
.toast-enter-active {
  transition: opacity var(--t-slow) var(--ease-out), transform var(--t-slow) var(--ease-out);
}
.toast-leave-active {
  transition: opacity var(--t-base) var(--ease), transform var(--t-base) var(--ease);
}
.toast-enter-from {
  opacity: 0;
  transform: translateX(16px) scale(0.97);
}
.toast-leave-to {
  opacity: 0;
  transform: translateX(16px) scale(0.97);
}
.toast-move {
  transition: transform var(--t-base) var(--ease);
}
</style>
