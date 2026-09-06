<script setup>
import { computed } from 'vue'
import AppIcon from './AppIcon.vue'
import { STRENGTH_META, evaluatePassword, passwordScore } from '../utils/password'

const props = defineProps({
  value: { type: String, default: '' }
})

const rules = computed(() => evaluatePassword(props.value))
const score = computed(() => passwordScore(props.value))
const strength = computed(() => STRENGTH_META[score.value])
const allPassed = computed(() => rules.value.every((r) => r.passed))
</script>

<template>
  <div class="rules">
    <div class="rules__bar" role="img" :aria-label="`密码强度：${strength.label}`">
      <span
        v-for="i in 4"
        :key="i"
        class="rules__seg"
        :class="[`rules__seg--${strength.tone}`, { 'is-on': i <= score }]"
      />
    </div>

    <ul class="rules__list">
      <li v-for="rule in rules" :key="rule.id" class="rules__item" :class="{ 'is-passed': rule.passed }">
        <AppIcon :name="rule.passed ? 'check-circle' : 'minus-circle'" :size="13" />
        <span>{{ rule.label }}</span>
      </li>
    </ul>

    <p class="rules__summary" :class="{ 'is-ok': allPassed }">
      {{ allPassed ? '口令复杂度符合要求' : '需满足以上全部条件' }}
    </p>
  </div>
</template>

<style scoped>
.rules {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
}

.rules__bar {
  display: flex;
  gap: 4px;
}

.rules__seg {
  flex: 1;
  height: 3px;
  border-radius: var(--r-full);
  background: var(--c-surface-2);
  transition: background var(--t-base) var(--ease);
}

.rules__seg.is-on.rules__seg--locked {
  background: var(--st-locked-fg);
}
.rules__seg.is-on.rules__seg--pending {
  background: var(--st-pending-fg);
}
.rules__seg.is-on.rules__seg--info {
  background: var(--c-info);
}
.rules__seg.is-on.rules__seg--enabled {
  background: var(--st-enabled-fg);
}

.rules__list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 4px var(--sp-3);
  margin: 0;
  padding: 0;
  list-style: none;
}

.rules__item {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
  transition: color var(--t-base) var(--ease);
}

.rules__item.is-passed {
  color: var(--st-enabled-fg);
}

.rules__summary {
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
}
.rules__summary.is-ok {
  color: var(--st-enabled-fg);
  font-weight: 500;
}
</style>
