<script setup>
defineProps({
  size: { type: Number, default: 14 }
})
</script>

<template>
  <span
    class="spinner"
    :style="{ width: size + 'px', height: size + 'px' }"
    role="status"
    aria-label="加载中"
  />
</template>

<style scoped>
.spinner {
  display: inline-block;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  opacity: 0.85;
  animation: spin 0.65s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .spinner {
    animation-duration: 1.6s;
  }
}
</style>
