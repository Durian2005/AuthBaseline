<script setup>
import AppIcon from './AppIcon.vue'
import { getCurrentWindow } from '@tauri-apps/api/window'

defineProps({
  title: { type: String, required: true }
})

const emit = defineEmits(['toggle-theme'])

// 浏览器开发模式（无 Tauri）下，窗口控制按钮无效 —— 用 toast 提示。
const isTauri =
  typeof window !== 'undefined' &&
  ('__TAURI_INTERNALS__' in window || '__TAURI__' in window)

async function doMinimize() {
  if (!isTauri) return
  try {
    await getCurrentWindow().minimize()
  } catch (e) {
    console.warn('minimize failed:', e)
  }
}

async function doMaximize() {
  if (!isTauri) return
  try {
    await getCurrentWindow().toggleMaximize()
  } catch (e) {
    console.warn('toggleMaximize failed:', e)
  }
}

// 点 X → 调 Tauri 的 close() → 触发 WindowEvent::Destroyed → Rust 侧 kill_backend → 退出。
// 不再弹确认框、不再"关闭到桌面图标"，就是要直接退出整个程序。
async function doClose() {
  if (!isTauri) return
  try {
    await getCurrentWindow().close()
  } catch (e) {
    console.warn('close failed:', e)
  }
}
</script>

<template>
  <header class="bar" @dblclick="doMaximize">
    <div class="bar__left">
      <div class="bar__logo">
        <AppIcon name="shield-check" :size="15" :stroke-width="2" />
      </div>
      <span class="bar__title">{{ title }}</span>
    </div>

    <div class="bar__center">
      <slot name="center" />
    </div>

    <div class="bar__right">
      <button
        type="button"
        class="bar__tool"
        aria-label="切换深色/浅色主题"
        title="切换主题"
        @click="emit('toggle-theme')"
      >
        <AppIcon name="sun" :size="14" class="icon-light" />
        <AppIcon name="moon" :size="14" class="icon-dark" />
      </button>

      <div class="bar__sep" aria-hidden="true" />

      <div class="bar__controls">
        <button
          type="button"
          class="ctl"
          aria-label="最小化"
          title="最小化"
          @click="doMinimize"
        >
          <AppIcon name="minus" :size="13" :stroke-width="2" />
        </button>
        <button
          type="button"
          class="ctl"
          aria-label="最大化/还原"
          title="最大化/还原"
          @click="doMaximize"
        >
          <AppIcon name="maximize" :size="12" :stroke-width="2" />
        </button>
        <button
          type="button"
          class="ctl ctl--close"
          aria-label="关闭应用"
          title="关闭"
          @click="doClose"
        >
          <AppIcon name="x" :size="13" :stroke-width="2" />
        </button>
      </div>
    </div>
  </header>
</template>

<style scoped>
.bar {
  display: flex;
  align-items: center;
  height: var(--titlebar-h);
  flex-shrink: 0;
  padding-left: var(--sp-3);
  background: var(--c-titlebar);
  border-bottom: 1px solid var(--c-border);
  box-shadow: var(--sh-inset-top);
  user-select: none;
}

.bar__left {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  min-width: 0;
}

.bar__logo {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border-radius: var(--r-sm);
  background: linear-gradient(160deg, var(--c-primary), var(--c-secondary));
  color: #fff;
  flex-shrink: 0;
}

.bar__title {
  font-size: var(--fs-base);
  font-weight: 600;
  color: var(--c-text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.bar__center {
  flex: 1;
  display: flex;
  justify-content: center;
  min-width: 0;
  padding: 0 var(--sp-3);
}

.bar__right {
  display: flex;
  align-items: center;
  height: 100%;
}

.bar__tool {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 26px;
  border: 0;
  border-radius: var(--r-sm);
  background: transparent;
  color: var(--c-text-muted);
  cursor: pointer;
  transition: background var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
}
.bar__tool:hover {
  background: var(--c-surface-hover);
  color: var(--c-text);
}
.bar__tool:focus-visible {
  outline: none;
  box-shadow: var(--sh-focus);
}

/* 主题图标：只在对应主题下显示，避免语义混淆 */
[data-theme='light'] .icon-dark {
  display: none;
}
[data-theme='dark'] .icon-light {
  display: none;
}

.bar__sep {
  width: 1px;
  height: 16px;
  margin: 0 var(--sp-2);
  background: var(--c-border);
}

.bar__controls {
  display: flex;
  align-items: stretch;
  height: 100%;
}

.ctl {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 42px;
  border: 0;
  background: transparent;
  color: var(--c-text-muted);
  cursor: pointer;
  transition: background var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
}
.ctl:hover {
  background: var(--c-surface-hover);
  color: var(--c-text);
}
.ctl:focus-visible {
  outline: none;
  box-shadow: inset var(--sh-focus);
}
.ctl--close:hover {
  background: #e81123;
  color: #fff;
}
</style>
