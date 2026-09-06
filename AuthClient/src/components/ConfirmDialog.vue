<script setup>
import AppWindow from './AppWindow.vue'
import AppIcon from './AppIcon.vue'
import Spinner from './Spinner.vue'

defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: '请确认' },
  icon: { type: String, default: 'alert-triangle' },
  tone: { type: String, default: 'warn' },
  message: { type: String, default: '' },
  detail: { type: String, default: '' },
  confirmText: { type: String, default: '确定' },
  cancelText: { type: String, default: '取消' },
  loading: { type: Boolean, default: false }
})

const emit = defineEmits(['confirm', 'cancel'])
</script>

<template>
  <AppWindow
    :open="open"
    :title="title"
    :icon="icon"
    :tone="tone"
    :width="400"
    :close-on-overlay="!loading"
    @close="!loading && emit('cancel')"
  >
    <div class="confirm">
      <div class="confirm__icon" :class="`confirm__icon--${tone}`">
        <AppIcon :name="icon" :size="20" :stroke-width="1.75" />
      </div>
      <div class="confirm__text">
        <p class="confirm__msg">{{ message }}</p>
        <p v-if="detail" class="confirm__detail">{{ detail }}</p>
      </div>
    </div>

    <template #footer>
      <button type="button" class="btn" :disabled="loading" @click="emit('cancel')">
        {{ cancelText }}
      </button>
      <button
        type="button"
        class="btn"
        :class="tone === 'danger' ? 'btn--danger' : 'btn--primary'"
        :disabled="loading"
        data-autofocus
        @click="emit('confirm')"
      >
        <Spinner v-if="loading" :size="13" />
        {{ confirmText }}
      </button>
    </template>
  </AppWindow>
</template>

<style scoped>
.confirm {
  display: flex;
  gap: var(--sp-3);
}

.confirm__icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  border-radius: var(--r-md);
  flex-shrink: 0;
}
.confirm__icon--danger {
  background: var(--c-danger-soft);
  color: var(--c-danger);
}
.confirm__icon--warn {
  background: var(--st-pending-bg);
  color: var(--st-pending-fg);
}
.confirm__icon--primary {
  background: var(--c-primary-soft);
  color: var(--c-primary);
}

.confirm__text {
  min-width: 0;
  padding-top: 2px;
}

.confirm__msg {
  font-size: var(--fs-md);
  line-height: 1.55;
  color: var(--c-text);
}

.confirm__detail {
  margin-top: var(--sp-2);
  font-size: var(--fs-sm);
  line-height: 1.5;
  color: var(--c-text-muted);
  word-break: break-word;
}
</style>
