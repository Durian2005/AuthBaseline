import { defineStore } from 'pinia'
import { ref } from 'vue'

let seq = 0

export const useToastStore = defineStore('toast', () => {
  const toasts = ref([])
  const MAX = 4

  function dismiss(id) {
    toasts.value = toasts.value.filter((t) => t.id !== id)
  }

  function push(message, type = 'info', timeout = 3400) {
    const id = ++seq
    toasts.value = [...toasts.value, { id, message, type }].slice(-MAX)
    if (timeout > 0) setTimeout(() => dismiss(id), timeout)
    return id
  }

  return {
    toasts,
    push,
    dismiss,
    success: (m, t) => push(m, 'success', t),
    error: (m, t) => push(m, 'error', t ?? 5200),
    warning: (m, t) => push(m, 'warning', t),
    info: (m, t) => push(m, 'info', t)
  }
})
