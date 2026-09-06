<script setup>
import { computed, onMounted, ref } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import AppWindow from '../components/AppWindow.vue'
import Spinner from '../components/Spinner.vue'
import { useSessionStore } from '../stores/session'
import { useToastStore } from '../stores/toast'
import {
  ACTION_META,
  actionMeta,
  formatDateTime,
  formatRelative,
  prettyJson,
  resultMeta,
  truncate
} from '../utils/format'
import { now } from '../composables/clock'

const session = useSessionStore()
const toast = useToastStore()

const keyword = ref('')
const action = ref('all')
const result = ref('all')
const detail = ref(null)

const RESULT_FILTERS = [
  { key: 'all', label: '全部结果' },
  { key: '成功', label: '仅成功' },
  { key: '失败', label: '仅失败' }
]

const actionOptions = computed(() => {
  const used = new Set(session.logs.map((l) => l.action))
  return Object.keys(ACTION_META).filter((a) => used.has(a))
})

const filteredLogs = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return session.logs.filter((l) => {
    const okAction = action.value === 'all' || l.action === action.value
    // 历史日志没有 result 字段，统一视为"成功"，避免筛选时莫名消失
    const actualResult = l.result || '成功'
    const okResult = result.value === 'all' || actualResult === result.value
    const okKw =
      !kw ||
      (l.operatorName || '').toLowerCase().includes(kw) ||
      (l.target || '').toLowerCase().includes(kw) ||
      (l.action || '').toLowerCase().includes(kw) ||
      (l.request || '').toLowerCase().includes(kw) ||
      (l.response || '').toLowerCase().includes(kw)
    return okAction && okResult && okKw
  })
})

const failedCount = computed(
  () => session.logs.filter((l) => (l.result || '成功') === '失败').length
)

async function refresh() {
  try {
    await session.refreshLogs()
    toast.success('审计日志已刷新')
  } catch (err) {
    toast.error(err?.message || '刷新失败')
  }
}

onMounted(() => {
  if (session.isAdmin && !session.logs.length) session.refreshLogs()
})
</script>

<template>
  <div class="page">
    <header class="head">
      <div>
        <h2 class="head__title">审计日志</h2>
        <p class="head__sub">
          保留最近 200 条记录 · 其中失败 {{ failedCount }} 条 · 当前展示
          {{ filteredLogs.length }} 条 ·
          {{ session.lastSyncAt ? `同步于 ${formatRelative(session.lastSyncAt, now)}` : '尚未同步' }}
        </p>
      </div>
      <button type="button" class="btn" :disabled="session.loadingLogs" @click="refresh">
        <Spinner v-if="session.loadingLogs" :size="14" />
        <AppIcon v-else name="refresh" :size="14" />
        <span>刷新</span>
      </button>
    </header>

    <section class="panel">
      <div class="panel__head">
        <h3 class="panel__title">
          <AppIcon name="file-text" :size="15" />
          <span>操作记录</span>
        </h3>

        <div class="toolbar">
          <div class="search">
            <span class="search__icon"><AppIcon name="search" :size="14" /></span>
            <input
              v-model="keyword"
              class="input"
              type="search"
              placeholder="搜索操作者 / 操作对象 / 请求 / 响应"
              aria-label="搜索审计日志"
            />
          </div>

          <select v-model="action" class="input select" aria-label="按操作类型筛选">
            <option value="all">全部操作</option>
            <option v-for="a in actionOptions" :key="a" :value="a">
              {{ actionMeta(a).label }}
            </option>
          </select>

          <select v-model="result" class="input select" aria-label="按操作结果筛选">
            <option v-for="r in RESULT_FILTERS" :key="r.key" :value="r.key">
              {{ r.label }}
            </option>
          </select>
        </div>
      </div>

      <div class="table-wrap">
        <table class="table table--dense">
          <thead>
            <tr>
              <th style="width: 150px">时间</th>
              <th style="width: 140px">操作者</th>
              <th style="width: 110px">动作</th>
              <th style="width: 80px">结果</th>
              <th style="width: 90px">前状态</th>
              <th style="width: 90px">后状态</th>
              <th>请求 / 响应摘要</th>
              <th style="width: 70px">详情</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="log in filteredLogs" :key="log.id">
              <td class="table__mono">
                <div>{{ formatDateTime(log.timestamp) }}</div>
                <div class="ago">{{ formatRelative(log.timestamp, now) }}</div>
              </td>
              <td class="cell-op selectable">
                <div>{{ log.operatorName || 'anonymous' }}</div>
                <div v-if="log.target && log.target !== log.operatorName" class="target">
                  → {{ log.target }}
                </div>
              </td>
              <td>
                <span class="act" :class="`act--${actionMeta(log.action).tone}`">
                  {{ actionMeta(log.action).label }}
                </span>
              </td>
              <td>
                <span class="act" :class="`act--${resultMeta(log.result || '成功').tone}`">
                  {{ resultMeta(log.result || '成功').label }}
                </span>
              </td>
              <td class="table__mono state">{{ log.statusBefore }}</td>
              <td class="table__mono state">{{ log.statusAfter }}</td>
              <td class="summary">
                <div class="summary__line" :title="log.request">
                  <span class="summary__tag">请求</span>
                  <span class="selectable">{{ truncate(prettyJson(log.request).replace(/\s+/g, ' '), 70) }}</span>
                </div>
                <div class="summary__line" :title="log.response">
                  <span class="summary__tag summary__tag--resp">响应</span>
                  <span class="selectable">{{ truncate(prettyJson(log.response).replace(/\s+/g, ' '), 70) }}</span>
                </div>
              </td>
              <td>
                <button
                  type="button"
                  class="btn btn--sm btn--ghost"
                  :aria-label="`查看 ${log.id} 的详细信息`"
                  @click="detail = log"
                >
                  <AppIcon name="external-link" :size="13" />
                  <span>详情</span>
                </button>
              </td>
            </tr>

            <tr v-if="!filteredLogs.length">
              <td colspan="8">
                <div class="empty">
                  <AppIcon name="file-text" :size="22" />
                  <p class="empty__title">没有匹配的日志记录</p>
                  <p class="empty__desc">调整搜索关键词、操作类型或结果筛选</p>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 日志详情（可拖拽子窗口） -->
    <AppWindow
      :open="!!detail"
      title="审计日志详情"
      icon="file-text"
      :width="560"
      @close="detail = null"
    >
      <div v-if="detail" class="detail">
        <dl class="detail__kv">
          <div><dt>时间</dt><dd class="selectable">{{ formatDateTime(detail.timestamp) }}</dd></div>
          <div><dt>操作者</dt><dd class="selectable">{{ detail.operatorName || 'anonymous' }}</dd></div>
          <div><dt>动作</dt><dd>{{ actionMeta(detail.action).label }}</dd></div>
          <div>
            <dt>结果</dt>
            <dd>{{ resultMeta(detail.result || '成功').label }}</dd>
          </div>
          <div v-if="detail.target">
            <dt>操作对象</dt>
            <dd class="selectable">{{ detail.target }}</dd>
          </div>
          <div><dt>状态变化</dt><dd class="selectable">{{ detail.statusBefore }} → {{ detail.statusAfter }}</dd></div>
        </dl>

        <div class="detail__block">
          <div class="detail__label">请求报文</div>
          <pre class="code selectable">{{ prettyJson(detail.request) || '—' }}</pre>
        </div>

        <div class="detail__block">
          <div class="detail__label">响应报文</div>
          <pre class="code selectable">{{ prettyJson(detail.response) || '—' }}</pre>
        </div>
      </div>

      <template #footer>
        <button type="button" class="btn" data-autofocus @click="detail = null">关闭</button>
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

.select {
  height: 28px;
  width: auto;
  padding-right: var(--sp-2);
  cursor: pointer;
}

.ago {
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
}

.cell-op {
  font-weight: 600;
}

.target {
  margin-top: 1px;
  font-size: var(--fs-xs);
  font-weight: 500;
  color: var(--c-text-subtle);
}

.state {
  color: var(--c-text-muted);
}

.act {
  display: inline-flex;
  align-items: center;
  padding: 1px 7px;
  border-radius: var(--r-sm);
  font-size: var(--fs-xs);
  font-weight: 600;
  white-space: nowrap;
}
.act--enabled {
  background: var(--st-enabled-bg);
  color: var(--st-enabled-fg);
}
.act--locked {
  background: var(--st-locked-bg);
  color: var(--st-locked-fg);
}
.act--pending {
  background: var(--st-pending-bg);
  color: var(--st-pending-fg);
}
.act--primary {
  background: var(--c-primary-soft);
  color: var(--c-primary);
}
.act--info {
  background: var(--c-info-soft);
  color: var(--c-info);
}
.act--disabled {
  background: var(--st-disabled-bg);
  color: var(--st-disabled-fg);
}

.summary {
  max-width: 420px;
}

.summary__line {
  display: flex;
  align-items: baseline;
  gap: 6px;
  font-size: var(--fs-xs);
  line-height: 1.6;
  color: var(--c-text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.summary__tag {
  flex-shrink: 0;
  padding: 0 4px;
  border-radius: var(--r-xs);
  background: var(--c-surface-2);
  color: var(--c-text-subtle);
  font-weight: 600;
}
.summary__tag--resp {
  background: var(--c-primary-soft);
  color: var(--c-primary);
}

/* 详情窗 */
.detail {
  display: flex;
  flex-direction: column;
  gap: var(--sp-3);
}

.detail__kv {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--sp-2) var(--sp-4);
  margin: 0;
}
.detail__kv div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.detail__kv dt {
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
}
.detail__kv dd {
  margin: 0;
  font-size: var(--fs-base);
  color: var(--c-text);
  word-break: break-all;
}

.detail__label {
  margin-bottom: 4px;
  font-size: var(--fs-xs);
  font-weight: 600;
  color: var(--c-text-muted);
}

.code {
  max-height: 190px;
  margin: 0;
  padding: var(--sp-3);
  overflow: auto;
  border: 1px solid var(--c-border);
  border-radius: var(--r-md);
  background: var(--c-surface-2);
  color: var(--c-text);
  font-family: var(--font-mono);
  font-size: var(--fs-sm);
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
