<script setup>
import { computed, onMounted, onBeforeUnmount, ref, watch } from 'vue'
import TitleBar from './components/TitleBar.vue'
import SideBar from './components/SideBar.vue'
import StatusBar from './components/StatusBar.vue'
import ToastHost from './components/ToastHost.vue'
import TamperAlertDialog from './components/TamperAlertDialog.vue'
import IntrusionAlertDialog from './components/IntrusionAlertDialog.vue'
import LoginView from './views/LoginView.vue'
import DashboardView from './views/DashboardView.vue'
import AccountView from './views/AccountView.vue'
import UsersView from './views/UsersView.vue'
import AuditView from './views/AuditView.vue'
import { useSessionStore } from './stores/session'
import { useToastStore } from './stores/toast'
import { probe } from './api/client'

const session = useSessionStore()
const toast = useToastStore()

/* ---------------- 主题 ---------------- */
const THEME_KEY = 'auth.theme'
const theme = ref(
  localStorage.getItem(THEME_KEY) ||
    (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
)

watch(
  theme,
  (v) => {
    document.documentElement.dataset.theme = v
    localStorage.setItem(THEME_KEY, v)
  },
  { immediate: true }
)

function toggleTheme() {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
}

/* ---------------- 导航 ----------------
 * 菜单按角色拆分，这是职责分离在界面上的直接体现：
 *   · 「用户管理」= 管账号的人（Admin / UserAdmin）
 *   · 「审计日志」= 看日志的人（仅 AuditAdmin）
 * 两组条件互不重叠，所以任何一个角色都不可能同时看到两个入口。
 * 隐藏入口只是体验层，真正的边界在后端：即使手敲地址调接口，
 * 也会被以 NOT_AUDIT_ADMIN / NOT_ADMIN 拒绝并写入审计链。
 */
const view = ref('dashboard')

const navItems = computed(() => {
  const items = [
    { key: 'dashboard', label: '仪表盘', icon: 'house' },
    { key: 'account', label: '账号与口令', icon: 'key' }
  ]
  if (session.isAdmin) {
    items.push({
      key: 'users',
      label: '用户管理',
      icon: 'users',
      badge: session.pendingUsers.length || 0
    })
  }
  if (session.isAuditAdmin) {
    items.push({ key: 'audit', label: '审计日志', icon: 'file-text' })
  }
  return items
})

// 角色变化（被降级 / 变更角色后重新登录）时，避免停在已无权限的页面
watch(
  () => [session.isAdmin, session.isAuditAdmin],
  ([canManageUsers, canReadAudit]) => {
    if (!canManageUsers && view.value === 'users') view.value = 'dashboard'
    if (!canReadAudit && view.value === 'audit') view.value = 'dashboard'
  }
)

function onLogout() {
  session.logout()
  view.value = 'dashboard'
}

/* ---------------- 后端连通性探测 ----------------
 * 浏览器环境：页面与 API 同源，探测相对路径即可。
 * 桌面端：探测 Rust 侧通过 IPC 下发的 sidecar 后端地址。
 */
let probeTimer = null

async function probeBackend() {
  session.connection = (await probe()) ? 'online' : 'offline'
}

/**
 * 首次启动的快速就绪等待。
 * 桌面端的 sidecar（.NET）需要几秒预热，若只按 15s 间隔轮询，
 * 用户一进界面就会看到"后端离线"。这里以 400ms 间隔快速探活。
 */
async function waitForBackendReady(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await probe()) {
      session.connection = 'online'
      return true
    }
    await new Promise((r) => setTimeout(r, 400))
  }
  return false
}

onMounted(async () => {
  await waitForBackendReady()
  probeTimer = setInterval(() => {
    // 有后台轮询的角色（管理员 / 审计管理员）不需要额外探活：
    // 他们的轮询本身就会刷新 lastSyncAt，再探一次属于重复请求。
    if (document.visibilityState === 'visible' && !session.isAdmin && !session.isAuditAdmin) {
      probeBackend()
    }
  }, 15000)
})

onBeforeUnmount(() => {
  clearInterval(probeTimer)
  session.stopAdminPolling()
  session.stopAuditPolling()
  session.stopIntegrityPolling()
  session.stopIntrusionPolling()
})
</script>

<template>
  <div class="app">
    <TitleBar title="基线系统" @toggle-theme="toggleTheme">
      <template #center>
        <span v-if="session.isLocked && session.lockRemaining > 0" class="lockchip">
          <AppIcon name="lock" :size="12" :stroke-width="2" />
          <span>账号锁定中</span>
        </span>
      </template>
    </TitleBar>

    <div class="app__body">
      <SideBar
        v-if="session.isLoggedIn"
        :items="navItems"
        :active-key="view"
        :username="session.currentUser?.username"
        :status="session.status"
        :role-label="session.roleLabel"
        @select="view = $event"
        @logout="onLogout"
      />

      <main class="content" :class="{ 'content--auth': !session.isLoggedIn }">
        <LoginView v-if="!session.isLoggedIn" />
        <DashboardView v-else-if="view === 'dashboard'" @navigate="view = $event" />
        <AccountView v-else-if="view === 'account'" />
        <UsersView v-else-if="view === 'users'" />
        <AuditView v-else-if="view === 'audit'" />
      </main>
    </div>

    <StatusBar
      :connection="session.connection"
      :last-sync-at="session.lastSyncAt"
      :lock-remaining="session.lockRemaining"
      :username="session.currentUser?.username || ''"
    />

    <ToastHost />
    <TamperAlertDialog />
    <IntrusionAlertDialog />
  </div>
</template>

<style scoped>
.app {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--c-window);
  overflow: hidden;
}

.app__body {
  flex: 1;
  display: flex;
  min-height: 0;
}

.content {
  position: relative;
  flex: 1;
  min-width: 0;
  min-height: 0;
  overflow-y: auto;
  padding: var(--sp-5);
  background: var(--c-window);
}

.content--auth {
  padding: 0;
  overflow: hidden;
}

.lockchip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 1px 9px 1px 6px;
  border-radius: var(--r-full);
  background: var(--st-locked-bg);
  color: var(--st-locked-fg);
  font-size: var(--fs-xs);
  font-weight: 600;
  white-space: nowrap;
}
</style>
