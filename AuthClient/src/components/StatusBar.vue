<script setup>
import { computed } from 'vue'
import AppIcon from './AppIcon.vue'
import { now } from '../composables/clock'
import { formatClock, formatDate, formatDuration, formatRelative } from '../utils/format'

const props = defineProps({
  connection: { type: String, default: 'unknown' },
  /** 后端 `GET /api/auth/transport` 的 data；null 表示未知（老后端 / 尚未连上） */
  transport: { type: Object, default: null },
  lastSyncAt: { type: String, default: null },
  lockRemaining: { type: Number, default: 0 },
  username: { type: String, default: '' }
})

const CONN = {
  online: { label: '后端已连接', icon: 'wifi', tone: 'ok' },
  offline: { label: '后端未连接', icon: 'cloud-off', tone: 'bad' },
  unknown: { label: '等待连接', icon: 'question', tone: 'idle' }
}

const conn = computed(() => CONN[props.connection] || CONN.unknown)

/**
 * 传输层指示灯 —— 验收时"讲得出加密了"靠的就是这一处。
 *
 * 判据取后端返回的 `tls`（其后端依据是 Request.IsHttps，是**实际链路**的事实），
 * 而不是"地址开头是不是 https"：后者只说明我们**打算**加密。
 * `tls` 不是布尔值时一律返回 null —— 不显示，胜过显示一个可能错的结论。
 */
const tls = computed(() => {
  const t = props.transport
  if (!t || typeof t.tls !== 'boolean') return null

  const notAfter = typeof t.notAfter === 'string' ? t.notAfter.slice(0, 10) : '-'
  return {
    on: t.tls,
    label: t.tls ? '加密' : '明文',
    icon: t.tls ? 'shield-check' : 'alert-triangle',
    tone: t.tls ? 'ok' : 'bad',
    title: t.tls
      ? `链路已加密（TLS）\n证书：${t.subject || '-'}\n到期：${notAfter}\n信任存储：${t.trustStore || '系统'}`
      : `⚠️ 当前为明文 HTTP：口令与票据在链路上可被本机其他进程读取`
        + (t.downgraded ? '\n（后端配置要求加密，但实际未生效）' : '')
  }
})

/** 后端地址提示。原来是硬编码的 `http://localhost:5007`，加密之后那句话会误导人。 */
const backendTitle = computed(() => {
  const scheme = props.transport?.scheme
  return scheme ? `API 基址 ${scheme}://127.0.0.1` : 'API 基址'
})

const clock = computed(() => formatClock(now.value))
const today = computed(() => formatDate(now.value))
const syncText = computed(() =>
  props.lastSyncAt ? `上次同步 ${formatRelative(props.lastSyncAt, now.value)}` : '尚未同步'
)
</script>

<template>
  <footer class="status">
    <div class="status__left">
      <span class="conn" :class="`conn--${conn.tone}`" :title="backendTitle">
        <AppIcon :name="conn.icon" :size="12" :stroke-width="2" />
        <span>{{ conn.label }}</span>
      </span>

      <span v-if="tls" class="conn" :class="`conn--${tls.tone}`" :title="tls.title">
        <AppIcon :name="tls.icon" :size="12" :stroke-width="2" />
        <span>{{ tls.label }}</span>
      </span>

      <span class="status__item status__item--mono">{{ syncText }}</span>
    </div>

    <div class="status__right">
      <span v-if="lockRemaining > 0" class="lock">
        <AppIcon name="lock" :size="12" :stroke-width="2" />
        <span>锁定剩余 {{ formatDuration(lockRemaining) }}</span>
      </span>

      <span v-if="username" class="status__item">
        <AppIcon name="user" :size="12" :stroke-width="2" />
        <span class="selectable">{{ username }}</span>
      </span>

      <span class="status__item status__item--mono" :title="today">{{ clock }}</span>
    </div>
  </footer>
</template>

<style scoped>
.status {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-3);
  height: var(--statusbar-h);
  flex-shrink: 0;
  padding: 0 var(--sp-3);
  background: var(--c-titlebar);
  border-top: 1px solid var(--c-border);
  font-size: var(--fs-xs);
  color: var(--c-text-muted);
  user-select: none;
}

.status__left,
.status__right {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  min-width: 0;
}

.status__item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}

.status__item--mono {
  font-variant-numeric: tabular-nums;
}

.conn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 0 6px 0 4px;
  border-radius: var(--r-sm);
  font-weight: 600;
  white-space: nowrap;
  cursor: default;
}
.conn--ok {
  color: var(--st-enabled-fg);
  background: var(--st-enabled-bg);
}
.conn--bad {
  color: var(--st-locked-fg);
  background: var(--st-locked-bg);
}
.conn--idle {
  color: var(--st-disabled-fg);
  background: var(--st-disabled-bg);
}

.lock {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 0 6px 0 4px;
  border-radius: var(--r-sm);
  background: var(--st-locked-bg);
  color: var(--st-locked-fg);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
</style>
