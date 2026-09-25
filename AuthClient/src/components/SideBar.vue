<script setup>
import AppIcon from './AppIcon.vue'
import StatusBadge from './StatusBadge.vue'

defineProps({
  items: { type: Array, required: true },
  activeKey: { type: String, default: '' },
  username: { type: String, default: '' },
  status: { type: String, default: '' },
  /** 角色中文显示名（管理员 / 用户管理员 / 审计管理员），空串表示普通用户不显示 */
  roleLabel: { type: String, default: '' }
})

const emit = defineEmits(['select', 'logout'])

const initial = (name) => (name ? name.trim().charAt(0).toUpperCase() : '?')
</script>

<template>
  <aside class="side">
    <nav class="side__nav" aria-label="主导航">
      <p class="side__group">功能导航</p>
      <button
        v-for="item in items"
        :key="item.key"
        type="button"
        class="nav"
        :class="{ 'is-active': item.key === activeKey }"
        :aria-current="item.key === activeKey ? 'page' : undefined"
        @click="emit('select', item.key)"
      >
        <AppIcon :name="item.icon" :size="16" />
        <span class="nav__label">{{ item.label }}</span>
        <span v-if="item.badge" class="nav__badge">{{ item.badge }}</span>
      </button>
    </nav>

    <div class="side__foot">
      <hr class="divider" />
      <div class="me">
        <div class="me__avatar" aria-hidden="true">{{ initial(username) }}</div>
        <div class="me__info">
          <div class="me__name selectable" :title="username">{{ username }}</div>
          <div class="me__meta">
            <StatusBadge :status="status" />
            <!-- 角色徽章：让用户一眼看清"我现在是谁"，
                 尤其在角色被变更、重新登录之后 -->
            <span v-if="roleLabel && roleLabel !== '普通用户'" class="me__role">{{ roleLabel }}</span>
          </div>
        </div>
        <button
          type="button"
          class="me__logout"
          aria-label="退出登录"
          title="退出登录"
          @click="emit('logout')"
        >
          <AppIcon name="log-out" :size="15" />
        </button>
      </div>
    </div>
  </aside>
</template>

<style scoped>
.side {
  display: flex;
  flex-direction: column;
  width: var(--sidebar-w);
  flex-shrink: 0;
  background: var(--c-panel);
  border-right: 1px solid var(--c-border);
}

.side__nav {
  flex: 1;
  padding: var(--sp-3) var(--sp-2);
  overflow-y: auto;
}

.side__group {
  padding: 0 var(--sp-2) var(--sp-2);
  font-size: var(--fs-xs);
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--c-text-subtle);
}

.nav {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  width: 100%;
  height: 32px;
  padding: 0 var(--sp-2);
  margin-bottom: 2px;
  border: 0;
  border-radius: var(--r-md);
  background: transparent;
  color: var(--c-text-muted);
  font-size: var(--fs-base);
  font-weight: 500;
  text-align: left;
  cursor: pointer;
  transition: background var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
}
.nav:hover {
  background: var(--c-surface-hover);
  color: var(--c-text);
}
.nav:focus-visible {
  outline: none;
  box-shadow: var(--sh-focus);
}
.nav.is-active {
  background: var(--c-primary);
  color: var(--c-on-primary);
}
.nav.is-active:hover {
  background: var(--c-primary-hover);
  color: var(--c-on-primary);
}

.nav__label {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.nav__badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: var(--r-full);
  background: var(--st-pending-bg);
  color: var(--st-pending-fg);
  font-size: var(--fs-xs);
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}
.nav.is-active .nav__badge {
  background: rgba(255, 255, 255, 0.22);
  color: var(--c-on-primary);
}

.side__foot {
  flex-shrink: 0;
}

.me {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  padding: var(--sp-3);
}

.me__avatar {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  flex-shrink: 0;
  border-radius: var(--r-md);
  background: var(--c-primary-soft);
  color: var(--c-primary);
  font-size: var(--fs-md);
  font-weight: 700;
}

.me__info {
  flex: 1;
  min-width: 0;
}

.me__name {
  font-size: var(--fs-base);
  font-weight: 600;
  color: var(--c-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.me__meta {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  margin-top: 3px;
}

.me__role {
  padding: 0 6px;
  border-radius: var(--r-sm);
  background: var(--c-primary-soft);
  color: var(--c-primary);
  font-size: var(--fs-xs);
  font-weight: 600;
  line-height: 16px;
  white-space: nowrap;
}

.me__logout {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  flex-shrink: 0;
  border: 0;
  border-radius: var(--r-sm);
  background: transparent;
  color: var(--c-text-subtle);
  cursor: pointer;
  transition: background var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
}
.me__logout:hover {
  background: var(--c-danger-soft);
  color: var(--c-danger);
}
.me__logout:focus-visible {
  outline: none;
  box-shadow: var(--sh-focus);
}
</style>
