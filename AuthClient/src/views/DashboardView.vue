<script setup>
import { computed, ref } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import StatCard from '../components/StatCard.vue'
import StatusBadge from '../components/StatusBadge.vue'
import Spinner from '../components/Spinner.vue'
import { useSessionStore } from '../stores/session'
import { useToastStore } from '../stores/toast'
import { actionMeta, formatRelative, formatDateTime } from '../utils/format'
import { now } from '../composables/clock'

const session = useSessionStore()
const toast = useToastStore()

const busyUser = ref('')

const recentLogs = computed(() => session.logs.slice(0, 8))

/** 完整性校验的结论文案：审计管理员最关心的一格 */
const integrityLabel = computed(() => {
  if (!session.integrity) return '未校验'
  return session.integrity.intact ? '完整' : '已断裂'
})

const greeting = computed(() => {
  const h = new Date(now.value).getHours()
  if (h < 6) return '夜深了'
  if (h < 11) return '早上好'
  if (h < 14) return '中午好'
  if (h < 18) return '下午好'
  return '晚上好'
})

/**
 * 按当前角色刷新本页数据。
 *
 * 两类角色的数据来自完全不同的接口，**不能混着调**：
 * 管理员没有审计权限，顺手刷新日志只会撞 403，
 * 还会在审计链里留下自己制造的 AUDIT_ACCESS_DENIED 记录。
 */
async function refreshCurrent() {
  try {
    if (session.isAuditAdmin) {
      await session.refreshAuditData()
    } else if (session.isAdmin) {
      await session.refreshAdminData()
    } else {
      await session.refreshUsers()
    }
    toast.success('数据已刷新')
  } catch (err) {
    toast.error(err?.message || '刷新失败')
  }
}

async function quickApprove(username) {
  busyUser.value = username
  try {
    const res = await session.approve(username)
    toast.success(res?.message || `已通过「${username}」的审核`)
  } catch (err) {
    toast.error(err?.message || '审核失败')
  } finally {
    busyUser.value = ''
  }
}

defineEmits(['navigate'])
</script>

<template>
  <div class="page">
    <!-- 页头 -->
    <header class="head">
      <div>
        <h2 class="head__title">
          {{ greeting }}，<span class="selectable">{{ session.currentUser?.username }}</span>
        </h2>
        <p class="head__sub">
          当前账号状态
          <StatusBadge :status="session.status" />
          <span v-if="session.role !== 'User'" class="head__role">{{ session.roleLabel }}</span>
        </p>
      </div>
      <button
        v-if="session.isAdmin || session.isAuditAdmin"
        type="button"
        class="btn"
        @click="refreshCurrent"
      >
        <AppIcon name="refresh" :size="14" />
        <span>刷新数据</span>
      </button>
    </header>

    <!-- 锁定横幅 -->
    <div v-if="session.isLocked && session.lockRemaining > 0" class="banner banner--locked">
      <AppIcon name="lock" :size="18" :stroke-width="2" />
      <div class="banner__text">
        <strong>账号已被锁定</strong>
        <span>连续 3 次口令错误触发保护，锁定到期后自动解锁并需重新登录。</span>
      </div>
    </div>

    <!-- 管理员：用户视角。
         这里刻意**不出现任何审计数据** —— 管理员没有审计权限，
         拿不到日志条数，也不该在这一页看到"最近有哪些操作"。
         需要看日志的是审计管理员，入口在他们自己的视图里。 -->
    <template v-if="session.isAdmin">
      <section class="stats">
        <StatCard icon="users" label="用户总数" :value="session.stats.total" tone="primary" hint="全部账号" />
        <StatCard icon="clock" label="待审核" :value="session.stats.pending" tone="pending" hint="等待放行" />
        <StatCard icon="lock" label="已锁定" :value="session.stats.locked" tone="locked" hint="口令错误保护" />
        <StatCard
          icon="user-check"
          label="管理类账号"
          :value="session.adminUsers.length"
          tone="info"
          hint="管理员 + 用户管理员"
        />
      </section>
      <p class="hint">
        <AppIcon name="info" :size="13" />
        <span>审计日志仅审计管理员可见，管理员与用户管理员均无权查看。</span>
      </p>

      <div class="cols">
        <!-- 待审核队列 -->
        <section class="panel">
          <div class="panel__head">
            <h3 class="panel__title">
              <AppIcon name="clipboard-check" :size="15" />
              <span>待审核队列</span>
            </h3>
            <button type="button" class="btn btn--sm btn--ghost" @click="$emit('navigate', 'users')">
              <span>全部用户</span>
              <AppIcon name="chevron-right" :size="13" />
            </button>
          </div>

          <div v-if="session.pendingUsers.length" class="queue">
            <div v-for="u in session.pendingUsers" :key="u.id" class="queue__row">
              <div class="queue__avatar" aria-hidden="true">
                {{ u.username.charAt(0).toUpperCase() }}
              </div>
              <div class="queue__info">
                <div class="queue__name selectable">{{ u.username }}</div>
                <div class="queue__meta">{{ formatRelative(u.createdAt, now) }}注册</div>
              </div>
              <button
                type="button"
                class="btn btn--sm btn--accent"
                :disabled="busyUser === u.username"
                @click="quickApprove(u.username)"
              >
                <Spinner v-if="busyUser === u.username" :size="12" />
                <AppIcon v-else name="check-circle" :size="13" />
                <span>通过</span>
              </button>
            </div>
          </div>

          <div v-else class="empty">
            <AppIcon name="check-circle" :size="22" />
            <p class="empty__title">没有待审核账号</p>
            <p class="empty__desc">新用户注册后会出现在这里</p>
          </div>
        </section>

      </div>
    </template>

    <!-- 审计管理员：审计视角。
         与管理员视图严格对称 —— 这里**不出现任何用户管理数据**
         （没有待审核队列、没有用户总数）。审计管理员管不了账号，
         也不该从这一页看到"系统里有多少人待放行"。 -->
    <template v-else-if="session.isAuditAdmin">
      <section class="stats">
        <StatCard
          icon="file-text"
          label="审计记录"
          :value="session.auditTotal"
          tone="primary"
          hint="全部分片累计"
        />
        <StatCard
          icon="minus-circle"
          label="失败事件"
          :value="session.auditFailed"
          tone="locked"
          hint="结果为失败"
        />
        <StatCard
          icon="shield-check"
          label="链完整性"
          :value="integrityLabel"
          :tone="session.integrity && !session.integrity.intact ? 'pending' : 'enabled'"
          hint="最近一次校验"
        />
        <StatCard
          icon="database"
          label="分片数量"
          :value="session.shards.length"
          tone="info"
          hint="轮转归档"
        />
      </section>

      <section class="panel">
        <div class="panel__head">
          <h3 class="panel__title">
            <AppIcon name="activity" :size="15" />
            <span>最近操作</span>
          </h3>
          <button type="button" class="btn btn--sm btn--ghost" @click="$emit('navigate', 'audit')">
            <span>全部日志</span>
            <AppIcon name="chevron-right" :size="13" />
          </button>
        </div>

        <ul v-if="recentLogs.length" class="feed">
          <li v-for="log in recentLogs" :key="log.id" class="feed__item">
            <span class="feed__dot" :class="`feed__dot--${actionMeta(log.action).tone}`" />
            <div class="feed__body">
              <div class="feed__line">
                <strong class="selectable">{{ log.operatorName || 'anonymous' }}</strong>
                <span>{{ actionMeta(log.action).label }}</span>
              </div>
              <div class="feed__time">{{ formatRelative(log.timestamp, now) }}</div>
            </div>
            <span class="feed__state" :title="`${log.statusBefore} → ${log.statusAfter}`">
              {{ log.statusAfter }}
            </span>
          </li>
        </ul>

        <div v-else class="empty">
          <AppIcon name="file-text" :size="22" />
          <p class="empty__title">暂无审计记录</p>
        </div>
      </section>
    </template>

    <!-- 普通用户：安全概览 -->
    <template v-else>
      <section class="stats">
        <StatCard icon="key" label="口令哈希" value="BCrypt" tone="enabled" hint="服务端加盐存储" />
        <StatCard icon="shield" label="账号状态" :value="session.status === 'Enabled' ? '正常' : '受限'" tone="primary" />
        <StatCard icon="lock" label="失败锁定阈值" value="3 次" tone="locked" hint="锁定 3 分钟" />
      </section>

      <section class="panel">
        <div class="panel__head">
          <h3 class="panel__title"><AppIcon name="info" :size="15" /><span>账号信息</span></h3>
        </div>
        <dl class="kv">
          <div class="kv__row">
            <dt>用户名</dt>
            <dd class="selectable">{{ session.currentUser?.username }}</dd>
          </div>
          <div class="kv__row">
            <dt>账号状态</dt>
            <dd><StatusBadge :status="session.status" /></dd>
          </div>
          <div class="kv__row">
            <dt>角色</dt>
            <dd>{{ session.roleLabel }}</dd>
          </div>
          <div class="kv__row">
            <dt>最后同步</dt>
            <dd>{{ session.lastSyncAt ? formatDateTime(session.lastSyncAt) : '—' }}</dd>
          </div>
        </dl>
      </section>
    </template>
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
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  margin-top: var(--sp-2);
  font-size: var(--fs-sm);
  color: var(--c-text-muted);
}

.head__role {
  padding: 0 6px;
  border-radius: var(--r-sm);
  background: var(--c-primary-soft);
  color: var(--c-primary);
  font-size: var(--fs-xs);
  font-weight: 600;
}

.banner {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  padding: var(--sp-3) var(--sp-4);
  border-radius: var(--r-lg);
  border: 1px solid color-mix(in srgb, var(--st-locked-fg) 32%, transparent);
  background: var(--st-locked-bg);
}
.banner--locked > svg {
  color: var(--st-locked-fg);
}
.banner__text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: var(--fs-sm);
  color: var(--c-text);
}
.banner__text span {
  color: var(--c-text-muted);
}

.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: var(--sp-3);
}

.cols {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: var(--sp-3);
  align-items: start;
}

/* 权限提示条：向管理员说明"为什么这一页看不到审计数据"，
   避免被误当成功能缺失 */
.hint {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  padding: 0 var(--sp-1);
  font-size: var(--fs-sm);
  color: var(--c-text-subtle);
}
.hint > svg {
  flex-shrink: 0;
}

/* 待审核队列 */
.queue {
  display: flex;
  flex-direction: column;
}

.queue__row {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  padding: var(--sp-2) var(--sp-4);
  border-bottom: 1px solid var(--c-border);
  transition: background var(--t-fast) var(--ease);
}
.queue__row:last-child {
  border-bottom: none;
}
.queue__row:hover {
  background: var(--c-surface-hover);
}

.queue__avatar {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  flex-shrink: 0;
  border-radius: var(--r-md);
  background: var(--st-pending-bg);
  color: var(--st-pending-fg);
  font-size: var(--fs-base);
  font-weight: 700;
}

.queue__info {
  flex: 1;
  min-width: 0;
}

.queue__name {
  font-size: var(--fs-base);
  font-weight: 600;
  color: var(--c-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.queue__meta {
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
}

/* 操作流 */
.feed {
  margin: 0;
  padding: 0;
  list-style: none;
}

.feed__item {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  padding: var(--sp-2) var(--sp-4);
  border-bottom: 1px solid var(--c-border);
}
.feed__item:last-child {
  border-bottom: none;
}

.feed__dot {
  width: 7px;
  height: 7px;
  flex-shrink: 0;
  border-radius: 50%;
  background: var(--c-text-subtle);
}
.feed__dot--enabled {
  background: var(--st-enabled-fg);
}
.feed__dot--locked {
  background: var(--st-locked-fg);
}
.feed__dot--pending {
  background: var(--st-pending-fg);
}
.feed__dot--primary {
  background: var(--c-primary);
}
.feed__dot--info {
  background: var(--c-info);
}

.feed__body {
  flex: 1;
  min-width: 0;
}

.feed__line {
  display: flex;
  align-items: baseline;
  gap: 6px;
  font-size: var(--fs-base);
  color: var(--c-text-muted);
}
.feed__line strong {
  color: var(--c-text);
  font-weight: 600;
}

.feed__time {
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
}

.feed__state {
  flex-shrink: 0;
  padding: 1px 6px;
  border-radius: var(--r-sm);
  background: var(--c-surface-2);
  color: var(--c-text-muted);
  font-size: var(--fs-xs);
  font-weight: 600;
}

/* 键值表 */
.kv {
  margin: 0;
}
.kv__row {
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: var(--sp-3);
  padding: var(--sp-2) var(--sp-4);
  border-bottom: 1px solid var(--c-border);
}
.kv__row:last-child {
  border-bottom: none;
}
.kv__row dt {
  font-size: var(--fs-base);
  color: var(--c-text-muted);
}
.kv__row dd {
  margin: 0;
  font-size: var(--fs-base);
  color: var(--c-text);
}
</style>
