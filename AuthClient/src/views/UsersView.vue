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

/**
 * 注销确认里的风险提示。
 * 注销管理员 / 审计管理员现在是被允许的，但后果比删普通用户大得多
 * （前者带走角色任免能力，后者带走审计独立性），必须在确认框里说清楚。
 */
const deleteDetail = computed(() => {
  const u = target.value
  if (!u) return ''
  const base = '该账号将从数据库中永久删除，且无法恢复。此操作会写入审计日志。'
  if (u.role === 'Admin') return base + '注销后系统将少一个能任命角色的账号。'
  if (u.role === 'AuditAdmin') return base + '注销后其审计查看能力需由其他审计管理员承担。'
  return base
})

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

/* ---------------- 角色显示与处置权限 ---------------- */

const ROLE_TAGS = {
  Admin: '管理员',
  UserAdmin: '用户管理员',
  AuditAdmin: '审计管理员',
  User: '普通用户'
}

function roleTag(user) {
  return ROLE_TAGS[user?.role] ?? '普通用户'
}

/** 这一行是不是操作者自己 —— 自己永远是"受保护"的那一行。 */
function isSelf(user) {
  return !!user && user.username === session.currentUser?.username
}

/**
 * 能否变更该账号的角色。
 *
 * 只有「管理员」有这个入口（用户管理员无权任免角色）；
 * 管理员可变更**除自己以外**任意账号的角色，含审计管理员与其它管理员。
 * 后端同样以 FORBIDDEN_TARGET 兜底，这里只是提前隐藏按钮。
 */
function canChangeRole(user) {
  return session.isRoleAdmin && !isSelf(user)
}

/**
 * 能否注销该账号。
 *
 * 分两级，与后端 UserRoles.CanBeManagedBy 保持一致：
 *   · 管理员 —— 除自己以外任意账号都能注销，含审计管理员；
 *   · 用户管理员 —— 只能注销普通用户与用户管理员，够不到审计管理员与管理员。
 * 自己永远不能注销：否则可能删掉系统里最后一个能任命角色的账号。
 */
function canDelete(user) {
  if (isSelf(user)) return false
  if (session.isRoleAdmin) return true
  return user.role === 'User' || user.role === 'UserAdmin'
}

/* ---------------- 新建账号（用户管理员 / 审计管理员） ----------------
 * 与自助注册不同：**不需要邮箱与验证码**，建号即可登录。
 * 但后端要求二次校验操作者本人的登录口令 —— 这是特权操作，
 * 仅凭会话票据不足以防冒用，所以这里必须再输一次自己的口令。
 */
const showCreate = ref(false)
const createForm = ref({ username: '', password: '', role: 'UserAdmin', operatorPassword: '' })
const createError = ref('')
const creating = ref(false)

function openCreate() {
  createForm.value = { username: '', password: '', role: 'UserAdmin', operatorPassword: '' }
  createError.value = ''
  showCreate.value = true
}

async function confirmCreate() {
  const f = createForm.value
  if (!f.username.trim() || !f.password || !f.operatorPassword) {
    createError.value = '请填写账号、初始口令与您本人的登录口令'
    return
  }
  creating.value = true
  createError.value = ''
  try {
    const res = await session.createAccount(
      f.username.trim(),
      f.password,
      f.role,
      f.operatorPassword
    )
    toast.success(res?.message || '账号已创建')
    showCreate.value = false
  } catch (err) {
    createError.value = err?.message || '创建失败'
  } finally {
    creating.value = false
  }
}

/* ---------------- 变更角色 ----------------
 * "指定某位管理员为审计管理员"就是走这里。
 * 变更成功后**对方**需要重新登录（后端会吊销其票据），操作者自己的会话不受影响。
 */
const roleTarget = ref(null)
const roleForm = ref({ role: 'UserAdmin', operatorPassword: '' })
const roleError = ref('')
const savingRole = ref(false)

function openRole(user) {
  roleTarget.value = user
  // 默认给一个"反直觉但最常用"的预设：从非审计岗切到审计岗
  roleForm.value = {
    role: user.role === 'AuditAdmin' ? 'UserAdmin' : 'AuditAdmin',
    operatorPassword: ''
  }
  roleError.value = ''
}

async function confirmRole() {
  if (!roleTarget.value) return
  if (!roleForm.value.operatorPassword) {
    roleError.value = '请输入您本人的登录口令'
    return
  }
  savingRole.value = true
  roleError.value = ''
  try {
    const res = await session.setRole(
      roleTarget.value.username,
      roleForm.value.role,
      roleForm.value.operatorPassword
    )
    toast.success(res?.message || '角色已变更')
    roleTarget.value = null
  } catch (err) {
    roleError.value = err?.message || '变更失败'
  } finally {
    savingRole.value = false
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
      <div class="head__actions">
        <!-- 新建账号入口只有「管理员」能看到：用户管理员能管用户但不能造账号 -->
        <button v-if="session.isRoleAdmin" type="button" class="btn btn--primary" @click="openCreate">
          <AppIcon name="user-plus" :size="14" />
          <span>新建账号</span>
        </button>
        <button type="button" class="btn" :disabled="session.loadingUsers" @click="refresh">
          <Spinner v-if="session.loadingUsers" :size="14" />
          <AppIcon v-else name="refresh" :size="14" />
          <span>刷新</span>
        </button>
      </div>
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
              <th style="width: 20%">用户名</th>
              <th style="width: 110px">角色</th>
              <th style="width: 150px">邮箱</th>
              <th style="width: 90px">状态</th>
              <th style="width: 76px">失败次数</th>
              <th style="width: 140px">锁定截止</th>
              <th>注册时间</th>
              <th style="width: 230px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in filteredUsers" :key="u.id">
              <td>
                <div class="name">
                  <span class="selectable">{{ u.username }}</span>
                  <span v-if="u.username === session.currentUser?.username" class="tag tag--me">本人</span>
                </div>
              </td>
              <td>
                <span class="tag" :class="{ 'tag--audit': u.role === 'AuditAdmin' }">
                  {{ roleTag(u) }}
                </span>
              </td>
              <!-- 后端只返回脱敏邮箱：管理员能看到"绑没绑、验没验"，但拿不到完整地址。
                   由管理员创建的账号一律不绑邮箱，这里会显示"未绑定" -->
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
                <div class="row-actions">
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
                  <!-- 变更角色：把某位账号指定为审计管理员（或撤销）走这里 -->
                  <button
                    v-if="canChangeRole(u)"
                    type="button"
                    class="btn btn--sm"
                    :title="`变更「${u.username}」的角色`"
                    @click="openRole(u)"
                  >
                    <AppIcon name="swap" :size="13" />
                    <span>变更角色</span>
                  </button>
                  <button
                    v-if="canDelete(u)"
                    type="button"
                    class="btn btn--sm btn--danger"
                    @click="target = u"
                  >
                    <AppIcon name="trash" :size="13" />
                    <span>注销</span>
                  </button>
                  <span v-if="!canDelete(u) && !canChangeRole(u)" class="muted">
                  {{ isSelf(u) ? '受保护' : '无操作权限' }}
                </span>
                </div>
              </td>
            </tr>

            <tr v-if="!filteredUsers.length">
              <td colspan="8">
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
      :detail="deleteDetail"
      confirm-text="永久注销"
      :loading="deleting"
      @cancel="target = null"
      @confirm="confirmDelete"
    />

    <!-- 新建账号：用户管理员 / 审计管理员。
         这两类账号不需要邮箱，建号即可登录；但需二次校验操作者本人口令。 -->
    <AppWindow
      :open="showCreate"
      title="新建账号"
      icon="user-plus"
      tone="primary"
      :width="460"
      :close-on-overlay="!creating"
      @close="!creating && (showCreate = false)"
    >
      <div class="form">
        <div class="form__notice">
          <AppIcon name="info" :size="15" :stroke-width="2" />
          <span>
            新建账号<strong>无需绑定邮箱</strong>，创建后即可用初始口令登录。
            这两类账号与管理员账号权限不同，请按职责选择角色。
          </span>
        </div>

        <div v-if="createError" class="alert" role="alert">
          <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
          <span class="selectable">{{ createError }}</span>
        </div>

        <label class="field">
          <span class="field__label">账号</span>
          <input
            v-model="createForm.username"
            class="input"
            type="text"
            placeholder="例如 auditor01"
            autocomplete="off"
            spellcheck="false"
          />
        </label>

        <label class="field">
          <span class="field__label">角色</span>
          <select v-model="createForm.role" class="input select">
            <option value="UserAdmin">用户管理员 —— 可管理用户，不能查看审计日志</option>
            <option value="AuditAdmin">审计管理员 —— 只能查看审计日志，不能管理用户</option>
          </select>
        </label>

        <PasswordField
          v-model="createForm.password"
          label="初始口令"
          placeholder="至少 8 位，含大小写字母与数字"
          autocomplete="new-password"
        />

        <PasswordField
          v-model="createForm.operatorPassword"
          label="您的登录口令（二次确认）"
          placeholder="输入你自己的密码以确认身份"
          autocomplete="off"
          :invalid="!!createError"
          :error="createError"
          @enter="confirmCreate"
        />
      </div>

      <template #footer>
        <button type="button" class="btn" :disabled="creating" @click="showCreate = false">
          取消
        </button>
        <button type="button" class="btn btn--primary" :disabled="creating" @click="confirmCreate">
          <Spinner v-if="creating" :size="13" />
          <span>创建账号</span>
        </button>
      </template>
    </AppWindow>

    <!-- 变更角色：把某位账号指定为审计管理员（或撤销审计权限）。
         角色任免是系统内权限最高的操作，需二次校验操作者本人口令。 -->
    <AppWindow
      :open="!!roleTarget"
      title="变更账号角色"
      icon="swap"
      tone="warn"
      :width="460"
      :close-on-overlay="!savingRole"
      @close="!savingRole && (roleTarget = null)"
    >
      <div v-if="roleTarget" class="form">
        <div class="form__notice">
          <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
          <span>
            正在变更「<strong>{{ roleTarget.username }}</strong>」的角色
            （当前：{{ roleTag(roleTarget) }}）。变更后该账号的登录状态会被作废，
            需要重新登录才能生效。
          </span>
        </div>

        <div v-if="roleError" class="alert" role="alert">
          <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
          <span class="selectable">{{ roleError }}</span>
        </div>

        <label class="field">
          <span class="field__label">变更为</span>
          <select v-model="roleForm.role" class="input select">
            <option value="AuditAdmin">审计管理员 —— 只能查看审计日志，不能管理用户</option>
            <option value="UserAdmin">用户管理员 —— 可管理用户，不能查看审计日志</option>
            <option value="User">普通用户 —— 撤销全部管理能力</option>
          </select>
        </label>

        <PasswordField
          v-model="roleForm.operatorPassword"
          label="您的登录口令（二次确认）"
          placeholder="输入你自己的密码以确认身份"
          autocomplete="off"
          :invalid="!!roleError"
          :error="roleError"
          autofocus
          @enter="confirmRole"
        />
      </div>

      <template #footer>
        <button type="button" class="btn" :disabled="savingRole" @click="roleTarget = null">
          取消
        </button>
        <button type="button" class="btn btn--primary" :disabled="savingRole" @click="confirmRole">
          <Spinner v-if="savingRole" :size="13" />
          <span>确认变更</span>
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

/* 审计管理员：用不同色调区分，一眼能看出"看日志的人"和"管账号的人" */
.tag--audit {
  background: var(--st-locked-bg);
  color: var(--st-locked-fg);
}

/* "本人"标记：提醒操作者这一行是自己，避免误操作 */
.tag--me {
  background: var(--c-surface-2);
  color: var(--c-text-subtle);
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

/* ---------- 新建账号 / 变更角色弹窗 ---------- */
.form {
  display: flex;
  flex-direction: column;
  gap: var(--sp-3);
}

.form__notice {
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
.form__notice > svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--st-pending-fg);
}

.field {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
}

.field__label {
  font-size: var(--fs-sm);
  font-weight: 600;
  color: var(--c-text-muted);
}

/* ---------- 页头操作区 ---------- */
.head__actions {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  flex-shrink: 0;
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
