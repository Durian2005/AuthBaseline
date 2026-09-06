<script setup>
import { computed } from 'vue'
import AppIcon from './AppIcon.vue'
import { statusMeta } from '../utils/format'

const props = defineProps({
  status: { type: String, required: true }
})

const meta = computed(() => statusMeta(props.status))
</script>

<template>
  <span class="badge" :class="`badge--${meta.tone}`">
    <AppIcon :name="meta.icon" :size="12" :stroke-width="2" />
    <span>{{ meta.label }}</span>
  </span>
</template>

<style scoped>
.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  height: 20px;
  padding: 0 8px 0 6px;
  border-radius: var(--r-full);
  border: 1px solid transparent;
  font-size: var(--fs-xs);
  font-weight: 600;
  white-space: nowrap;
  line-height: 1;
}

.badge--enabled {
  color: var(--st-enabled-fg);
  background: var(--st-enabled-bg);
  border-color: color-mix(in srgb, var(--st-enabled-fg) 24%, transparent);
}
.badge--pending {
  color: var(--st-pending-fg);
  background: var(--st-pending-bg);
  border-color: color-mix(in srgb, var(--st-pending-fg) 26%, transparent);
}
.badge--locked {
  color: var(--st-locked-fg);
  background: var(--st-locked-bg);
  border-color: color-mix(in srgb, var(--st-locked-fg) 26%, transparent);
}
.badge--disabled {
  color: var(--st-disabled-fg);
  background: var(--st-disabled-bg);
  border-color: color-mix(in srgb, var(--st-disabled-fg) 22%, transparent);
}
</style>
