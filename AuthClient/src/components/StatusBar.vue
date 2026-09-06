<script setup>
import { computed } from 'vue'
import AppIcon from './AppIcon.vue'
import { now } from '../composables/clock'
import { formatClock, formatDate, formatDuration, formatRelative } from '../utils/format'

const props = defineProps({
  connection: { type: String, default: 'unknown' },
  lastSyncAt: { type: String, default: null },
  lockRemaining: { type: Number, default: 0 },
  username: { type: String, default: '' }
})

const CONN = {
  online: { label: '后端已连接', icon: 'wifi', tone: 'ok' },
  offline: { label: '后端未连接', icon: 'cloud-off', tone: 'bad' },
  unknown: { label: '等待连接', icon: 'question', tone: 'idle' }
}

const conn = computed(() => CONN[props.connection] || CONN.unknown)
const clock = computed(() => formatClock(now.value))
const today = computed(() => formatDate(now.value))
const syncText = computed(() =>
  props.lastSyncAt ? `上次同步 ${formatRelative(props.lastSyncAt, now.value)}` : '尚未同步'
)
</script>

<template>
  <footer class="status">
    <div class="status__left">
      <span class="conn" :class="`conn--${conn.tone}`" :title="`API 基址 http://localhost:5007`">
        <AppIcon :name="conn.icon" :size="12" :stroke-width="2" />
        <span>{{ conn.label }}</span>
      </span>

      <span class="status__item status__item--mono">{{ syncText }}</span>
    </div>

    <div class="status__right">
      <span v-if="lockRemaining > 0" class="lock">
        <AppIcon name="lock" :size="12" :stroke-width="2" />
        <span>锁定剩余 {{ formatDuration(lockRemaining) }}</span>
      </span>

      <span v-if="username" class="status__item">
        <AppIcon name="user" :size="12" :stroke-width="2" />
        <span class="selectable">{{ username }}</span>
      </span>

      <span class="status__item status__item--mono" :title="today">{{ clock }}</span>
    </div>
  </footer>
</template>

<style scoped>
.status {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-3);
  height: var(--statusbar-h);
  flex-shrink: 0;
  padding: 0 var(--sp-3);
  background: var(--c-titlebar);
  border-top: 1px solid var(--c-border);
  font-size: var(--fs-xs);
  color: var(--c-text-muted);
  user-select: none;
}

.status__left,
.status__right {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  min-width: 0;
}

.status__item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}

.status__item--mono {
  font-variant-numeric: tabular-nums;
}

.conn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 0 6px 0 4px;
  border-radius: var(--r-sm);
  font-weight: 600;
  white-space: nowrap;
  cursor: default;
}
.conn--ok {
  color: var(--st-enabled-fg);
  background: var(--st-enabled-bg);
}
.conn--bad {
  color: var(--st-locked-fg);
  background: var(--st-locked-bg);
}
.conn--idle {
  color: var(--st-disabled-fg);
  background: var(--st-disabled-bg);
}

.lock {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 0 6px 0 4px;
  border-radius: var(--r-sm);
  background: var(--st-locked-bg);
  color: var(--st-locked-fg);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
</style>
