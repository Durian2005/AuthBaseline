<script setup>
import { computed, ref, useId } from 'vue'
import AppIcon from './AppIcon.vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  label: { type: String, default: '' },
  placeholder: { type: String, default: '' },
  autocomplete: { type: String, default: 'off' },
  invalid: { type: Boolean, default: false },
  error: { type: String, default: '' },
  hint: { type: String, default: '' },
  disabled: { type: Boolean, default: false },
  autofocus: { type: Boolean, default: false }
})

const emit = defineEmits(['update:modelValue', 'enter'])

const uid = useId()
const inputId = computed(() => `pw-${uid}`)
const revealed = ref(false)

function onInput(e) {
  emit('update:modelValue', e.target.value)
}

function toggle() {
  revealed.value = !revealed.value
}
</script>

<template>
  <div class="field">
    <label v-if="label" class="field__label" :for="inputId">{{ label }}</label>

    <div class="pw">
      <input
        :id="inputId"
        class="input pw__input"
        :class="{ 'input--invalid': invalid }"
        :type="revealed ? 'text' : 'password'"
        :value="modelValue"
        :placeholder="placeholder"
        :autocomplete="autocomplete"
        :disabled="disabled"
        :aria-invalid="invalid || undefined"
        :aria-describedby="error ? `${inputId}-err` : hint ? `${inputId}-hint` : undefined"
        :autofocus="autofocus"
        spellcheck="false"
        @input="onInput"
        @keyup.enter="emit('enter')"
      />
      <button
        type="button"
        class="pw__toggle"
        :aria-label="revealed ? '隐藏密码' : '显示密码'"
        :aria-pressed="revealed"
        :disabled="disabled"
        @click="toggle"
      >
        <AppIcon :name="revealed ? 'eye-off' : 'eye'" :size="15" />
      </button>
    </div>

    <p v-if="error" :id="`${inputId}-err`" class="field__error" role="alert">
      <AppIcon name="alert-triangle" :size="12" />
      <span>{{ error }}</span>
    </p>
    <p v-else-if="hint" :id="`${inputId}-hint`" class="field__hint">{{ hint }}</p>
  </div>
</template>

<style scoped>
.pw {
  position: relative;
  display: flex;
  align-items: center;
}

.pw__input {
  padding-right: 36px;
}

.pw__toggle {
  position: absolute;
  right: 3px;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border: 0;
  border-radius: var(--r-sm);
  background: transparent;
  color: var(--c-text-subtle);
  cursor: pointer;
  transition: background var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
}
.pw__toggle:hover:not(:disabled) {
  background: var(--c-surface-hover);
  color: var(--c-text);
}
.pw__toggle:focus-visible {
  outline: none;
  box-shadow: var(--sh-focus);
}
.pw__toggle:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
</style>
