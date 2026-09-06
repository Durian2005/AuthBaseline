<script setup>
import AppIcon from './AppIcon.vue'

defineProps({
  icon: { type: String, required: true },
  label: { type: String, required: true },
  value: { type: [Number, String], required: true },
  hint: { type: String, default: '' },
  tone: { type: String, default: 'primary' }
})
</script>

<template>
  <div class="stat" :class="`stat--${tone}`">
    <div class="stat__icon">
      <AppIcon :name="icon" :size="16" />
    </div>
    <div class="stat__body">
      <div class="stat__label">{{ label }}</div>
      <div class="stat__value">{{ value }}</div>
      <div v-if="hint" class="stat__hint">{{ hint }}</div>
    </div>
  </div>
</template>

<style scoped>
.stat {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-3);
  padding: var(--sp-3) var(--sp-4);
  background: var(--c-surface);
  border: 1px solid var(--c-border);
  border-radius: var(--r-lg);
  box-shadow: var(--sh-card);
  transition: border-color var(--t-base) var(--ease),
    transform var(--t-base) var(--ease);
}
.stat:hover {
  border-color: var(--c-border-strong);
  transform: translateY(-1px);
}

.stat__icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  border-radius: var(--r-md);
  flex-shrink: 0;
}

.stat__body {
  min-width: 0;
}

.stat__label {
  font-size: var(--fs-xs);
  font-weight: 600;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  color: var(--c-text-muted);
}

.stat__value {
  font-size: var(--fs-xl);
  font-weight: 650;
  line-height: 1.25;
  color: var(--c-text);
  font-variant-numeric: tabular-nums;
}

.stat__hint {
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
}

/* 语义色（图文双通道，不依赖单一颜色传达信息） */
.stat--primary .stat__icon {
  background: var(--c-primary-soft);
  color: var(--c-primary);
}
.stat--pending .stat__icon {
  background: var(--st-pending-bg);
  color: var(--st-pending-fg);
}
.stat--locked .stat__icon {
  background: var(--st-locked-bg);
  color: var(--st-locked-fg);
}
.stat--enabled .stat__icon {
  background: var(--st-enabled-bg);
  color: var(--st-enabled-fg);
}
.stat--info .stat__icon {
  background: var(--c-info-soft);
  color: var(--c-info);
}
</style>
