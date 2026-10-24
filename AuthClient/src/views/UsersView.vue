<script setup>
import { computed, onMounted, ref } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import StatusBadge from '../components/StatusBadge.vue'
import Spinner from '../components/Spinner.vue'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import { useSessionStore } from '../stores/session'
import { useToastStore } from '../stores/toast'
import { formatDateTime, formatDuration } from '../utils/format'
import CreateAccountDialog from '../components/users/CreateAccountDialog.vue'
import SetRoleDialog from '../components/users/SetRoleDialog.vue'
import FreezeAccountDialog from '../components/users/FreezeAccountDialog.vue'
import BatchDialog from '../components/users/BatchDialog.vue'
import { dormantText, roleLabelOf } from '../utils/userDisplay'
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
  { key: 'Locked', label: '锁定' },
  { key: 'Disabled', label: '已冻结' }
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

/* ---------------- 批量多选 ----------------
 * 选择集合只存**用户名**、不存对象：用户列表每 20 秒轮询一次，
 * 存对象的话刷新后引用就失效了，而"勾选状态跨刷新保留"恰恰是批量操作的基本要求 ——
 * 谁也不想勾到一半被轮询清空。
 *
 * canBatch 是后端 CanBeManagedBy 的**前端镜像**，只用于把不可处置的行置灰。
 * 真正的边界在后端（批量接口逐条鉴权），两者不一致时以后端为准 ——
 * 所以这里宁可宽松，也不要在前端替用户决定"哪些能选"。
 */
/* 多选模式：默认关闭。
 * 常驻复选框会让"看一眼用户列表"这件最常做的事多一层视觉噪声，
 * 而批量处置是低频操作 —— 所以把它的成本挪到"显式开启"这一步。
 * 关闭时必须清空已选：否则隐藏的选择会在下次开启时"复活"，
 * 用户看到的勾是上次的、以为是自己刚勾的。 */
const multiSelect = ref(false)

const selected = ref(new Set())
const selectedNames = computed(() => [...selected.value])

function canBatch(u) {
  if (!u) return false
  if (isSelf(u)) return false
  if (session.isRoleAdmin) return true
  return u.role === 'User' || u.role === 'UserAdmin'
}

const selectableUsers = computed(() => filteredUsers.value.filter(canBatch))
const allSelected = computed(
  () => selectableUsers.value.length > 0 && selectableUsers.value.every((u) => selected.value.has(u.username))
)

function toggleOne(username) {
  const next = new Set(selected.value)
  if (next.has(username)) next.delete(username)
  else next.add(username)
  selected.value = next
}

function toggleAll() {
  if (allSelected.value) {
    selected.value = new Set()
    return
  }
  selected.value = new Set(selectableUsers.value.map((u) => u.username))
}

function clearSelection() {
  selected.value = new Set()
}

/** 进出多选模式。退出时连带关掉批量弹窗并清空已选，回到"纯浏览"状态。 */
function toggleMultiSelect() {
  multiSelect.value = !multiSelect.value
  if (!multiSelect.value) {
    batchOpen.value = false
    clearSelection()
  }
}

/** 批量弹窗开关。关闭时清空选择 —— 留着会让人以为还选中着。 */
const batchOpen = ref(false)

function openBatch() {
  if (selected.value.size === 0) return
  batchOpen.value = true
}

function closeBatch() {
  batchOpen.value = false
  clearSelection()
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

/* ---------------- 沉睡账号治理（冻结 / 解除冻结） ----------------
 * 判定阈值与基准时间全部由后端下发（session.dormant），
 * 前端只负责展示与发起处置 —— 不自己算"差多少天"，
 * 否则会出现"后端判沉睡、前端按另一套阈值显示"的口径分歧。
 */

/** 是否被冻结（后端 Status=Disabled 的语义化别名） */
function isFrozen(user) {
  return user?.status === 'Disabled'
}

/**
 * 能否冻结该账号。
 *
 * 三个条件缺一不可，与后端 DormantFreeze 的校验一一对应：
 *   · 确实处于沉睡候选（后端已在 candidates 里做过筛选，这里是二次确认）；
 *   · 角色不受保护（管理账号永不参与冻结）；
 *   · 不是操作者自己。
 * 前端隐藏按钮只是提前告知，真正的把关在后端 —— 手敲请求一样会被拒并留痕。
 */
function canFreeze(user) {
  if (!user) return false
  if (user.dormantProtected) return false
  if (isSelf(user)) return false
  return user.dormant === true && user.status === 'Enabled'
}

/** 能否解除冻结：被冻结 + 有处置权限（与注销共用同一套范围判定） */
function canUnfreeze(user) {
  if (!user || !isFrozen(user)) return false
  if (isSelf(user)) return false
  if (session.isRoleAdmin) return true
  return user.role === 'User' || user.role === 'UserAdmin'
}


const freezeTarget = ref(null)

/** 打开冻结确认弹窗（表单与提交由 FreezeAccountDialog 自持） */
function openFreeze(user) {
  freezeTarget.value = user
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

/* ---------------- 重置他人人脸 ----------------
 * 与注销共用同一套范围判定（后端也是同一个出口 CanBeManagedBy）。
 * 它是一次**降级**：把对方的第二因子直接拿掉，因此走二次确认，
 * 并且在确认框里说清后果 —— 而不是做成一个点一下就生效的行内按钮。
 */
const faceTarget = ref(null)
const resettingFace = ref(false)

/** 与注销同权限梯度；自己那一行不给入口（本人删除走账号页，需要自己的口令） */
function canResetFace(user) {
  return canDelete(user)
}

const resetFaceDetail = computed(() => {
  const u = faceTarget.value
  if (!u) return ''
  return (
    `重置后「${u.username}」的两套人脸都会被删除：第二因子模板（口令 + 人脸）与` +
    '刷脸登录（用户名 + 人脸），该账号退回纯口令登录。' +
    '本操作会记入审计日志（谁重置了谁，两条记录）。另一种用法：' +
    '当本人摄像头损坏、无法完成第二因子时，这是唯一的恢复路径。'
  )
})

async function confirmResetFace() {
  if (!faceTarget.value) return
  resettingFace.value = true
  try {
    const res = await session.resetFace(faceTarget.value.username)
    toast.success(res?.message || '已重置人脸')
    faceTarget.value = null
  } catch (err) {
    toast.error(err?.message || '重置人脸失败')
  } finally {
    resettingFace.value = false
  }
}

/* ---------------- 新建账号（用户管理员 / 审计管理员） ----------------
 * 与自助注册不同：**不需要邮箱与验证码**，建号即可登录。
 * 但后端要求二次校验操作者本人的登录口令 —— 这是特权操作，
 * 仅凭会话票据不足以防冒用，所以这里必须再输一次自己的口令。
 */
const showCreate = ref(false)

/** 打开新建账号弹窗（表单与提交由 CreateAccountDialog 自持） */
function openCreate() {
  showCreate.value = true
}

/* ---------------- 变更角色 ----------------
 * "指定某位管理员为审计管理员"就是走这里。
 * 变更成功后**对方**需要重新登录（后端会吊销其票据），操作者自己的会话不受影响。
 */
const roleTarget = ref(null)

/** 打开变更角色弹窗（表单与提交由 SetRoleDialog 自持） */
function openRole(user) {
  roleTarget.value = user
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

          <!-- 多选开关：与上面的状态筛选是两类东西（那是单选筛选、这是模式开关），
               所以刻意不放进同一组 segmented，避免被读成"选了多选就不能选锁定" -->
          <button
            type="button"
            class="btn btn--sm multi-toggle"
            :class="{ 'is-on': multiSelect }"
            :aria-pressed="multiSelect"
            :title="multiSelect ? '退出多选：清空已选并隐藏勾选框' : '进入多选：批量审批、冻结、注销等'"
            @click="toggleMultiSelect"
          >
            {{ multiSelect ? '退出多选' : '多选' }}
          </button>
        </div>
      </div>

      <!-- 批量操作条：只在有选中时出现，不常驻占用版面 -->
      <div v-if="multiSelect && selected.size > 0" class="batch-bar">
        <span class="batch-bar__count">
          已选 <strong>{{ selected.size }}</strong> 个账号
        </span>
        <div class="batch-bar__actions">
          <button type="button" class="btn btn--sm btn--primary" @click="openBatch">
            批量处理
          </button>
          <button type="button" class="btn btn--sm" @click="clearSelection">取消选择</button>
        </div>
      </div>

      <div class="table-wrap">
        <table class="table table--dense">
          <thead>
            <tr>
              <th v-if="multiSelect" style="width: 34px">
                <input
                  type="checkbox"
                  :checked="allSelected"
                  :disabled="selectableUsers.length === 0"
                  :title="allSelected ? '取消全选' : '全选可处置账号'"
                  @change="toggleAll"
                />
              </th>
              <th style="width: 20%">用户名</th>
              <th style="width: 110px">角色</th>
              <th style="width: 150px">邮箱</th>
              <th style="width: 90px">状态</th>
              <th style="width: 76px">失败次数</th>
              <th style="width: 140px">锁定截止</th>
              <th style="width: 106px">注册时间</th>
              <th style="width: 230px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in filteredUsers" :key="u.id">
              <td v-if="multiSelect" class="pick">
                <input
                  type="checkbox"
                  :checked="selected.has(u.username)"
                  :disabled="!canBatch(u)"
                  :title="canBatch(u) ? `选择「${u.username}」` : '当前身份不能处置该账号'"
                  @change="toggleOne(u.username)"
                />
              </td>
              <td>
                <div class="name">
                  <span class="selectable">{{ u.username }}</span>
                  <span v-if="u.username === session.currentUser?.username" class="tag tag--me">本人</span>
                </div>
              </td>
              <td>
                <span class="tag" :class="{ 'tag--audit': u.role === 'AuditAdmin' }">
                  {{ roleLabelOf(u) }}
                </span>
              </td>
              <!-- 后端只返回脱敏邮箱：管理员能看到"绑没绑、验没验"，但拿不到完整地址。
                   管理员创建账号时邮箱是可选项：留空这里显示"未绑定"，
                   填写则显示脱敏地址并带"已验证"标记（代填即视为已验证） -->
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
              <td class="table__mono nowrap">{{ formatDateTime(u.createdAt) }}</td>
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
                  <!-- 重置人脸：把对方的**两套**人脸（第二因子 + 刷脸登录）一起拿掉，
                       是一次降级动作，因此与"注销"一样走二次确认，不用行内直接生效。
                       只清其中一套会留下一条更宽松的登录路径，恢复就成了半截。 -->
                  <button
                    v-if="canResetFace(u)"
                    type="button"
                    class="btn btn--sm"
                    :title="`重置「${u.username}」的人脸（第二因子 + 刷脸登录）`"
                    @click="faceTarget = u"
                  >
                    <AppIcon name="face" :size="13" />
                    <span>重置人脸</span>
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

    <!-- 沉睡账号治理 -->
    <section class="panel">
      <div class="panel__head">
        <h3 class="panel__title">
          <AppIcon name="clock" :size="15" />
          <span>长期未登录账号</span>
          <span v-if="session.dormantCandidates.length" class="chip">
            {{ session.dormantCandidates.length }}
          </span>
        </h3>
        <p class="panel__hint">
          超过 <strong>{{ session.dormantThresholdDays ?? '—' }}</strong> 天未登录即为沉睡。
          冻结后该账号无法登录，但随时可解除，<strong>不会删除任何数据</strong>。
        </p>
      </div>

      <!-- 可冻结的普通账号 -->
      <p class="panel__meta">
        沉睡候选 {{ session.dormantCandidates.length }} 个
        <span v-if="session.frozenAccounts.length"> · 已冻结 {{ session.frozenAccounts.length }} 个</span>
      </p>

      <div v-if="session.dormantCandidates.length" class="table-wrap">
        <table class="table table--dense">
          <thead>
            <tr>
              <th style="width: 26%">用户名</th>
              <th style="width: 110px">角色</th>
              <th>上次登录</th>
              <th style="width: 120px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in session.dormantCandidates" :key="u.id">
              <td class="cell-name selectable">{{ u.username }}</td>
              <td><span class="tag">{{ roleLabelOf(u) }}</span></td>
              <td class="table__mono">
                <span class="stale">{{ dormantText(u) }}</span>
                <span v-if="u.lastLoginAt" class="muted"> · {{ formatDateTime(u.lastLoginAt) }}</span>
              </td>
              <td>
                <button
                  v-if="canFreeze(u)"
                  type="button"
                  class="btn btn--sm btn--warn"
                  :disabled="busyUser === u.username"
                  @click="openFreeze(u)"
                >
                  <AppIcon name="lock" :size="13" />
                  <span>冻结</span>
                </button>
                <!-- 不可冻结的行也要说清原因，别只留一个空单元格 -->
                <span v-else class="muted">{{ isSelf(u) ? '受保护' : '不参与自动判定' }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else class="empty">
        <AppIcon name="check-circle" :size="22" />
        <p class="empty__title">没有需要处置的沉睡账号</p>
        <p class="empty__desc">所有普通账号近期都有活动记录</p>
      </div>

      <!-- 已冻结账号：可解除 -->
      <template v-if="session.frozenAccounts.length">
        <p class="panel__meta panel__meta--divider">已冻结账号（可解除）</p>
        <div class="table-wrap">
          <table class="table table--dense">
            <thead>
              <tr>
                <th style="width: 26%">用户名</th>
                <th style="width: 110px">角色</th>
                <th>上次登录</th>
                <th style="width: 120px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="u in session.frozenAccounts" :key="u.id">
                <td class="cell-name selectable">{{ u.username }}</td>
                <td><span class="tag">{{ roleLabelOf(u) }}</span></td>
                <td class="table__mono">
                  <span>{{ dormantText(u) }}</span>
                </td>
                <td>
                  <button
                    v-if="canUnfreeze(u)"
                    type="button"
                    class="btn btn--sm"
                    :disabled="busyUser === u.username"
                    @click="run('unlock', u.username)"
                  >
                    <Spinner v-if="busyUser === u.username" :size="12" />
                    <AppIcon v-else name="unlock" :size="13" />
                    <span>解除冻结</span>
                  </button>
                  <span v-else class="muted">无权限</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>

      <!-- 管理账号：达到阈值也只提示，不参与冻结 -->
      <template v-if="session.dormantProtected.length">
        <p class="panel__meta panel__meta--divider">
          管理账号（不参与冻结）
        </p>
        <div class="table-wrap">
          <table class="table table--dense">
            <thead>
              <tr>
                <th style="width: 26%">用户名</th>
                <th style="width: 110px">角色</th>
                <th>上次登录</th>
                <th style="width: 200px">说明</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="u in session.dormantProtected" :key="u.id">
                <td class="cell-name selectable">{{ u.username }}</td>
                <td>
                  <span class="tag" :class="{ 'tag--audit': u.role === 'AuditAdmin' }">
                    {{ roleLabelOf(u) }}
                  </span>
                </td>
                <td class="table__mono">{{ dormantText(u) }}</td>
                <td class="muted">管理角色，冻结会影响系统职责，故不参与自动治理</td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
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

    <!-- 重置人脸的确认框：可逆性上是"可恢复的"（对方可重新录入），
         但方向上是**降级**，所以用 warn 色调 + 把后果写在 detail 里，
         而不是像注销那样用 danger —— 避免两者在视觉上被当成同一档操作。 -->
    <ConfirmDialog
      :open="!!faceTarget"
      title="重置人脸（两套）"
      icon="face"
      tone="warn"
      :message="`确定要重置「${faceTarget?.username}」的人脸吗？`"
      :detail="resetFaceDetail"
      confirm-text="重置人脸"
      :loading="resettingFace"
      @cancel="faceTarget = null"
      @confirm="confirmResetFace"
    />

    <!-- 冻结确认：可逆操作，用 warn 色调而非 danger，
         与"注销"（永久、红色）在视觉上明确区分 -->
    <FreezeAccountDialog v-model:target="freezeTarget" />

    <!-- 新建账号：用户管理员 / 审计管理员。
         这两类账号不需要邮箱，建号即可登录；但需二次校验操作者本人口令。 -->
    <CreateAccountDialog v-model:open="showCreate" />

    <!-- 变更角色：把某位账号指定为审计管理员（或撤销审计权限）。
         角色任免是系统内权限最高的操作，需二次校验操作者本人口令。 -->
    <SetRoleDialog v-model:target="roleTarget" />
  </div>
  <BatchDialog
    :usernames="batchOpen ? selectedNames : []"
    :users="session.users"
    @close="closeBatch"
  />
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

/* 分组之间的分隔标题：让"候选 / 已冻结 / 管理账号"三段看得出一段一段 */
.panel__meta--divider {
  padding-top: var(--sp-2);
  border-top: 1px solid var(--c-border);
  margin-top: var(--sp-2);
  font-weight: 600;
  color: var(--c-text-subtle);
}

/* 沉睡时长用警示色：这是管理员需要立刻注意到的信号 */
.stale {
  color: var(--st-locked-fg);
  font-weight: 600;
}

/* 页头下方的口径说明（阈值 + 可逆性），措辞必须让"不会删数据"一眼可见 */
.panel__hint {
  flex: 1;
  max-width: 560px;
  font-size: var(--fs-sm);
  color: var(--c-text-muted);
  line-height: 1.5;
}
.panel__hint strong {
  color: var(--c-text);
}

.select {
  height: 28px;
  width: auto;
  padding-right: var(--sp-2);
  cursor: pointer;
}


/* ---------- 页头操作区 ---------- */
.head__actions {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  flex-shrink: 0;
}

/* ---------- 批量多选 ---------- */
/* 时间类单元格不折行：折起来会把日期劈成 "2026-10-" 和 "05" 两段，比溢出更难读 */
.nowrap {
  white-space: nowrap;
}

/* 多选开关：关闭时是普通次级按钮，开启时填主色 —— 模式状态要一眼可辨，
   不能靠"复选框列有没有出现"这种间接线索让人猜 */
.multi-toggle {
  border-color: var(--c-border);
}
.multi-toggle.is-on {
  background: var(--c-primary);
  border-color: var(--c-primary);
  color: var(--c-on-primary);
}
.multi-toggle.is-on:hover:not(:disabled) {
  background: var(--c-primary-hover);
  border-color: var(--c-primary-hover);
}

.pick {
  width: 34px;
  text-align: center;
}
.pick input {
  cursor: pointer;
}
.pick input:disabled {
  cursor: not-allowed;
  opacity: 0.35;
}
.batch-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-2);
  padding: 8px 12px;
  margin-bottom: var(--sp-2);
  border-radius: var(--radius-md, 8px);
  border: 0.5px solid var(--color-border-info, rgba(133, 183, 235, 0.4));
  background: var(--color-background-info, rgba(133, 183, 235, 0.08));
}
.batch-bar__count {
  font-size: 13px;
}
.batch-bar__actions {
  display: flex;
  gap: 8px;
}
</style>
