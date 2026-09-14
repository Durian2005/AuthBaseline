<script setup>
import { computed, onMounted, ref } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import StatusBadge from '../components/StatusBadge.vue'
import Spinner from '../components/Spinner.vue'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import AppWindow from '../components/AppWindow.vue'
import PasswordField from '../components/PasswordField.vue'
import { useSessionStore } from '../stores/session'
import { useToastStore } from '../stores/toast'
import { formatDateTime, formatDuration } from '../utils/format'
import { now } from '../composables/clock'

const session = useSessionStore()
const toast = useToastStore()

const keyword = ref('')
const filter = ref('all')
const busyUser = ref('')

/* ---------------- 待审核：查找与排序 ---------------- */
const pendingKeyword = ref('')
/** 'newest' 最新注册在前，'oldest' 最早注册在前（先来先审） */
const pendingSort = ref('newest')

const filteredPending = computed(() => {
  const kw = pendingKeyword.value.trim().toLowerCase()
  const matched = session.pendingUsers.filter(
    (u) => !kw || u.username.toLowerCase().includes(kw)
  )
  // 复制一份再排序，避免打乱 store 中原始列表的顺序
  return matched.sort((a, b) => {
    const ta = new Date(a.createdAt).getTime() || 0
    const tb = new Date(b.createdAt).getTime() || 0
    return pendingSort.value === 'newest' ? tb - ta : ta - tb
  })
})

const FILTERS = [
  { key: 'all', label: '全部' },
  { key: 'Pending', label: '待审核' },
  { key: 'Enabled', label: '启用' },
  { key: 'Locked', label: '锁定' }
]

const filteredUsers = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return session.users.filter((u) => {
    const okStatus = filter.value === 'all' || u.status === filter.value
    const okKw = !kw || u.username.toLowerCase().includes(kw)
    return okStatus && okKw
  })
})

const pendingCount = computed(() => session.pendingUsers.length)

function countOf(status) {
  return session.users.filter((u) => u.status === status).length
}

/** 锁定剩余时间（后端存的是 UTC 截止时刻） */
function lockLeft(lockoutEnd) {
  if (!lockoutEnd) return 0
  const end = new Date(lockoutEnd).getTime()
  if (Number.isNaN(end)) return 0
  return Math.max(0, Math.ceil((end - now.value) / 1000))
}

async function run(action, username) {
  busyUser.value = username
  try {
    const res = await session[action](username)
    toast.success(res?.message || '操作成功')
  } catch (err) {
    toast.error(err?.message || '操作失败')
  } finally {
    busyUser.value = ''
  }
}

/* ---------------- 注销确认 ---------------- */
const target = ref(null)
const deleting = ref(false)

async function confirmDelete() {
  if (!target.value) return
  deleting.value = true
  try {
    const res = await session.deleteUser(target.value.username)
    toast.success(res?.message || '用户已注销')
    target.value = null
  } catch (err) {
    toast.error(err?.message || '注销失败')
  } finally {
    deleting.value = false
  }
}

/* ---------------- 管理员权限转让 ----------------
 * 转让属于特权变更，后端要求二次校验现任管理员口令，
 * 因此这里不能复用 ConfirmDialog（它没有输入项），单独用一个子窗口承载。
 */
const transferTarget = ref(null)
const transferPassword = ref('')
const transferError = ref('')
const transferring = ref(false)

function openTransfer(user) {
  transferTarget.value = user
  transferPassword.value = ''
  transferError.value = ''
}

async function confirmTransfer() {
  if (!transferTarget.value || !transferPassword.value) return
  transferring.value = true
  transferError.value = ''
  try {
    const res = await session.transferAdmin(transferTarget.value.username, transferPassword.value)
    toast.success(res?.message || '管理员权限已转让')
    transferTarget.value = null
    transferPassword.value = ''
    // 转让后本人降为普通用户，界面会自动离开管理员页面
    toast.info('您已变为普通用户，管理员功能已不可用')
  } catch (err) {
    transferError.value = err?.message || '转让失败'
  } finally {
    transferring.value = false
  }
}

async function refresh() {
  try {
    await session.refreshUsers()
    toast.success('用户列表已刷新')
  } catch (err) {
    toast.error(err?.message || '刷新失败')
  }
}

onMounted(() => {
  if (session.isAdmin && !session.users.length) session.refreshUsers()
})
</script>

<template>
  <div class="page">
    <header class="head">
      <div>
        <h2 class="head__title">用户管理</h2>
        <p class="head__sub">
          共 {{ session.users.length }} 个账号 · 待审核 {{ pendingCount }} · 已锁定
          {{ countOf('Locked') }}
        </p>
      </div>
      <button type="button" class="btn" :disabled="session.loadingUsers" @click="refresh">
        <Spinner v-if="session.loadingUsers" :size="14" />
        <AppIcon v-else name="refresh" :size="14" />
        <span>刷新</span>
      </button>
    </header>

    <!-- 待审核 -->
    <section class="panel">
      <div class="panel__head">
        <h3 class="panel__title">
          <AppIcon name="clipboard-check" :size="15" />
          <span>待审核用户</span>
          <span v-if="pendingCount" class="chip">{{ pendingCount }}</span>
        </h3>

        <div v-if="session.pendingUsers.length" class="toolbar">
          <div class="search">
            <span class="search__icon"><AppIcon name="search" :size="14" /></span>
            <input
              v-model="pendingKeyword"
              class="input"
              type="search"
              placeholder="查找待审核账号"
              aria-label="查找待审核账号"
            />
          </div>

          <select v-model="pendingSort" class="input select" aria-label="按注册时间排序">
            <option value="newest">最新注册在前</option>
            <option value="oldest">最早注册在前</option>
          </select>
        </div>
      </div>

      <p v-if="session.pendingUsers.length" class="panel__meta">
        共 {{ pendingCount }} 条待审核<span v-if="pendingKeyword.trim()">
          · 匹配 {{ filteredPending.length }} 条</span
        >
      </p>

      <div v-if="filteredPending.length" class="table-wrap">
        <table class="table table--dense">
          <thead>
            <tr>
              <th style="width: 40%">用户名</th>
              <th>注册时间</th>
              <th style="width: 120px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in filteredPending" :key="u.id">
              <td class="cell-name selectable">{{ u.username }}</td>
              <td class="table__mono">{{ formatDateTime(u.createdAt) }}</td>
              <td>
                <button
                  type="button"
                  class="btn btn--sm btn--accent"
                  :disabled="busyUser === u.username"
                  @click="run('approve', u.username)"
                >
                  <Spinner v-if="busyUser === u.username" :size="12" />
                  <AppIcon v-else name="check-circle" :size="13" />
                  <span>通过审核</span>
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else-if="pendingKeyword.trim()" class="empty">
        <AppIcon name="search" :size="22" />
        <p class="empty__title">没有匹配的待审核账号</p>
        <p class="empty__desc">换个关键词试试，或清空查找条件查看全部</p>
      </div>

      <div v-else class="empty">
        <AppIcon name="check-circle" :size="22" />
        <p class="empty__title">没有待审核账号</p>
        <p class="empty__desc">新用户注册后会在此排队等待放行</p>
      </div>
    </section>

    <!-- 全部用户 -->
    <section class="panel">
      <div class="panel__head">
        <h3 class="panel__title"><AppIcon name="users" :size="15" /><span>全部用户</span></h3>

        <div class="toolbar">
          <div class="search">
            <span class="search__icon"><AppIcon name="search" :size="14" /></span>
            <input
              v-model="keyword"
              class="input"
              type="search"
              placeholder="搜索用户名"
              aria-label="搜索用户名"
            />
          </div>

          <div class="segmented" role="group" aria-label="按状态筛选">
            <button
              v-for="f in FILTERS"
              :key="f.key"
              type="button"
              class="seg"
              :class="{ 'is-active': filter === f.key }"
              :aria-pressed="filter === f.key"
              @click="filter = f.key"
            >
              {{ f.label }}
            </button>
          </div>
        </div>
      </div>

      <div class="table-wrap">
        <table class="table table--dense">
          <thead>
            <tr>
              <th style="width: 22%">用户名</th>
              <th style="width: 160px">邮箱</th>
              <th style="width: 100px">状态</th>
              <th style="width: 84px">失败次数</th>
              <th style="width: 160px">锁定截止</th>
              <th>注册时间</th>
              <th style="width: 230px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in filteredUsers" :key="u.id">
              <td>
                <div class="name">
                  <span class="selectable">{{ u.username }}</span>
                  <span v-if="u.isAdmin" class="tag">管理员</span>
                </div>
              </td>
              <!-- 后端只返回脱敏邮箱：管理员能看到"绑没绑、验没验"，但拿不到完整地址 -->
              <td class="table__mono">
                <template v-if="u.email">
                  <span :title="u.emailVerified ? '邮箱已验证' : '邮箱未验证'">{{ u.email }}</span>
                  <AppIcon
                    v-if="u.emailVerified"
                    name="check-circle"
                    :size="12"
                    class="mail-ok"
                    aria-label="邮箱已验证"
                  />
                </template>
                <span v-else class="muted">未绑定</span>
              </td>
              <td><StatusBadge :status="u.status" /></td>
              <td class="num">{{ u.failedLoginAttempts }}</td>
              <td class="table__mono">
                <span v-if="u.status === 'Locked' && lockLeft(u.lockoutEnd) > 0" class="count">
                  剩 {{ formatDuration(lockLeft(u.lockoutEnd)) }}
                </span>
                <span v-else>{{ u.lockoutEnd ? formatDateTime(u.lockoutEnd) : '—' }}</span>
              </td>
              <td class="table__mono">{{ formatDateTime(u.createdAt) }}</td>
              <td>
                <div v-if="u.isAdmin" class="muted">受保护，不可操作</div>
                <div v-else class="row-actions">
                  <button
                    v-if="u.status === 'Locked'"
                    type="button"
                    class="btn btn--sm"
                    :disabled="busyUser === u.username"
                    @click="run('unlock', u.username)"
                  >
                    <Spinner v-if="busyUser === u.username" :size="12" />
                    <AppIcon v-else name="unlock" :size="13" />
                    <span>解锁</span>
                  </button>
                  <!-- 只有处于启用状态的账号才是"合法用户"，才有资格接管管理员权限 -->
                  <button
                    v-if="u.status === 'Enabled'"
                    type="button"
                    class="btn btn--sm"
                    :title="`把管理员权限转让给 ${u.username}`"
                    @click="openTransfer(u)"
                  >
                    <AppIcon name="swap" :size="13" />
                    <span>转让权限</span>
                  </button>
                  <button
                    type="button"
                    class="btn btn--sm btn--danger"
                    @click="target = u"
                  >
                    <AppIcon name="trash" :size="13" />
                    <span>注销</span>
                  </button>
                </div>
              </td>
            </tr>

            <tr v-if="!filteredUsers.length">
              <td colspan="7">
                <div class="empty">
                  <AppIcon name="search" :size="22" />
                  <p class="empty__title">没有匹配的用户</p>
                  <p class="empty__desc">换个关键词或切换筛选条件试试</p>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 注销确认 -->
    <ConfirmDialog
      :open="!!target"
      title="注销用户"
      icon="trash"
      tone="danger"
      :message="`确定要注销用户「${target?.username}」吗？`"
      detail="该账号将从数据库中永久删除，且无法恢复。此操作会写入审计日志。"
      confirm-text="永久注销"
      :loading="deleting"
      @cancel="target = null"
      @confirm="confirmDelete"
    />

    <!-- 管理员权限转让：需二次校验现任管理员口令 -->
    <AppWindow
      :open="!!transferTarget"
      title="转让管理员权限"
      icon="swap"
      tone="warn"
      :width="430"
      :close-on-overlay="!transferring"
      @close="!transferring && (transferTarget = null)"
    >
      <div v-if="transferTarget" class="transfer">
        <div class="transfer__notice">
          <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
          <span>
            转让后「{{ transferTarget.username }}」成为管理员，你将变为普通用户且无法撤销，
            需由新管理员再次转让。操作会写入审计日志。
          </span>
        </div>

        <div v-if="transferError" class="alert" role="alert">
          <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
          <span class="selectable">{{ transferError }}</span>
        </div>

        <PasswordField
          v-model="transferPassword"
          label="当前管理员口令"
          placeholder="输入你的登录密码以确认身份"
          autocomplete="off"
          :invalid="!!transferError"
          :error="transferError"
          autofocus
          @enter="confirmTransfer"
        />
      </div>

      <template #footer>
        <button type="button" class="btn" :disabled="transferring" @click="transferTarget = null">
          取消
        </button>
        <button
          type="button"
          class="btn btn--primary"
          :disabled="transferring || !transferPassword"
          @click="confirmTransfer"
        >
          <Spinner v-if="transferring" :size="13" />
          <span>确认转让</span>
        </button>
      </template>
    </AppWindow>
  </div>
</template>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: var(--sp-4);
}

.head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--sp-4);
}

.head__title {
  font-size: var(--fs-xl);
  font-weight: 650;
  color: var(--c-text);
}
.head__sub {
  margin-top: var(--sp-2);
  font-size: var(--fs-sm);
  color: var(--c-text-muted);
}

.chip {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 6px;
  border-radius: var(--r-full);
  background: var(--st-pending-bg);
  color: var(--st-pending-fg);
  font-size: var(--fs-xs);
  font-weight: 700;
}

.segmented {
  display: flex;
  padding: 2px;
  background: var(--c-surface-2);
  border-radius: var(--r-md);
}

.seg {
  height: 24px;
  padding: 0 var(--sp-3);
  border: 0;
  border-radius: var(--r-sm);
  background: transparent;
  color: var(--c-text-muted);
  font-size: var(--fs-sm);
  font-weight: 500;
  cursor: pointer;
  transition: background var(--t-fast) var(--ease), color var(--t-fast) var(--ease);
}
.seg:hover {
  color: var(--c-text);
}
.seg.is-active {
  background: var(--c-surface);
  color: var(--c-text);
  box-shadow: var(--sh-card);
}
.seg:focus-visible {
  outline: none;
  box-shadow: var(--sh-focus);
}

.cell-name {
  font-weight: 600;
}

.name {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  min-width: 0;
}

.tag {
  padding: 0 6px;
  border-radius: var(--r-sm);
  background: var(--c-primary-soft);
  color: var(--c-primary);
  font-size: var(--fs-xs);
  font-weight: 600;
  white-space: nowrap;
}

.num {
  font-variant-numeric: tabular-nums;
  font-weight: 600;
}

/* 邮箱已验证标记：颜色弱化，只作为可信状态的辅助提示 */
.mail-ok {
  margin-left: var(--sp-1);
  vertical-align: -1px;
  color: var(--st-enabled-fg, var(--c-primary));
}

.count {
  color: var(--st-locked-fg);
  font-weight: 600;
}

.muted {
  font-size: var(--fs-sm);
  color: var(--c-text-subtle);
}

.row-actions {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
}

.panel__meta {
  padding: 0 var(--sp-4) var(--sp-3);
  font-size: var(--fs-sm);
  color: var(--c-text-muted);
}

.select {
  height: 28px;
  width: auto;
  padding-right: var(--sp-2);
  cursor: pointer;
}

/* ---------- 权限转让 ---------- */
.transfer {
  display: flex;
  flex-direction: column;
  gap: var(--sp-3);
}

.transfer__notice {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  padding: var(--sp-2) var(--sp-3);
  border: 1px solid color-mix(in srgb, var(--st-pending-fg) 34%, transparent);
  border-radius: var(--r-md);
  background: var(--st-pending-bg);
  color: var(--c-text);
  font-size: var(--fs-sm);
  line-height: 1.55;
}
.transfer__notice > svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--st-pending-fg);
}

.alert {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  padding: var(--sp-2) var(--sp-3);
  border-radius: var(--r-md);
  border: 1px solid color-mix(in srgb, var(--c-danger) 30%, transparent);
  background: var(--c-danger-soft);
  color: var(--c-text);
  font-size: var(--fs-sm);
  line-height: 1.5;
}
.alert > svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--c-danger);
}
</style>
