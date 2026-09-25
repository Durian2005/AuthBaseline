<script setup>
import { computed, onMounted, ref } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import AppWindow from '../components/AppWindow.vue'
import Spinner from '../components/Spinner.vue'
import { useSessionStore } from '../stores/session'
import { useToastStore } from '../stores/toast'
import {
  actionMeta,
  formatDateTime,
  formatRelative,
  prettyJson,
  reasonLabel,
  resultMeta,
  truncate
} from '../utils/format'
import { now } from '../composables/clock'

const session = useSessionStore()
const toast = useToastStore()

const keyword = ref('')
const action = ref('all')
const result = ref('all')
const shard = ref('')
const detail = ref(null)

const RESULT_FILTERS = [
  { key: 'all', label: '全部结果' },
  { key: '成功', label: '仅成功' },
  { key: '失败', label: '仅失败' }
]

/** 操作类型下拉：固定清单（含实验二新增的审计事件），避免只列出当前页出现过的动作 */
const ACTION_OPTIONS = [
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'LOGOUT',
  'REGISTER',
  'APPROVE',
  'UNLOCK',
  'DELETE_USER',
  'CHANGE_PASSWORD',
  'CHANGE_PASSWORD_FAILED',
  'TRANSFER_ADMIN',
  'SEND_EMAIL_CODE',
  'SEND_EMAIL_CODE_FAILED',
  'RESET_PASSWORD',
  'RESET_PASSWORD_FAILED',
  'AUDIT_QUERY',
  'AUDIT_VERIFY',
  'AUDIT_ACCESS_DENIED',
  'AUDIT_TAMPERED',
  // 时钟异常（墙钟与运行时长两条时间线背离）。
  // 它记录的是"系统保障被动过"，而不是某个人的一次操作失败 ——
  // 单列一项，审计员才能把"有人拨钟"和"有人输错口令"分开看。
  'CLOCK_ANOMALY'
]

/**
 * 说明：这里曾经有一个「安全事件」一键筛选按钮（把失败/拒绝类动作整类拉出来）。
 * 已按需求移除 —— 筛选入口收敛为「操作类型」下拉这一个，不再为同类需求开第二个口子。
 *
 * 失败类事件仍然可以查，而且查法更直接：动作下拉里就有
 * 「改密失败 / 重置密码失败 / 发码被拒 / 登录失败」等独立动作
 * （失败在写入时就已经和成功分开命名，不需要叠加结果条件），
 * 配合「结果 = 仅失败」可做全局失败筛查，配合「原因」列看具体原因码。
 */

/** 分片下拉选项：空串代表"当前活动分片"，其余为归档分片 */
const shardOptions = computed(() => {
  const list = [{ key: '', label: '当前分片（最近写入）' }]
  for (const s of session.shards) {
    list.push({ key: s.shard ?? s.name ?? s, label: String(s.shard ?? s.name ?? s) })
  }
  return list
})

/** 把筛选条件打包成后端查询参数（筛选交给服务端，避免只过滤当前页） */
function currentQuery(page = session.auditPage.page) {
  const q = { page, pageSize: session.auditPage.pageSize }
  if (shard.value) q.shard = shard.value
  if (keyword.value.trim()) q.keyword = keyword.value.trim()
  if (action.value !== 'all') q.action = action.value
  if (result.value !== 'all') q.result = result.value
  return q
}

const totalPages = computed(() =>
  Math.max(1, Math.ceil((session.auditTotal || 0) / (session.auditPage.pageSize || 50)))
)

const failedCount = computed(() =>
  session.logs.filter((l) => (l.result || '成功') === '失败').length
)

const integrity = computed(() => session.integrity)

async function refresh() {
  try {
    await session.refreshLogs(currentQuery(1))
    await session.refreshShards()
    // 顺带跑一次越权巡检：管理员在审计页主动刷新时，
    // 刚发生的越权尝试应当立刻冒泡，不必再等下一个巡检周期。
    await session.checkIntrusion()
    toast.success('审计日志已刷新')
  } catch (err) {
    toast.error(err?.message || '刷新失败')
  }
}

async function applyFilters() {
  try {
    await session.refreshLogs(currentQuery(1))
  } catch (err) {
    toast.error(err?.message || '筛选失败')
  }
}

async function goPage(page) {
  const target = Math.min(Math.max(1, page), totalPages.value)
  if (target === session.auditPage.page) return
  try {
    await session.refreshLogs(currentQuery(target))
  } catch (err) {
    toast.error(err?.message || '翻页失败')
  }
}

/**
 * 重置筛选。
 *
 * 名字从 clearFilters 改成 resetFilters 是有意的 —— 这个动作唯一的作用对象
 * 是**查询条件**，而旧名字与界面上的「清空」按钮连在一起，看起来像是
 * "把日志清空"。审计日志必须做到谁都改不了，界面上任何可能被读成
 * "可以删日志"的措辞都是要清掉的：一旦审计员自己以为日志能被清空，
 * 整条哈希链的可信度就跟着打折。
 *
 * 重置用 refresh 图标而不是 x：x 在窗口里是"关闭"，在这里会读成"删除"。
 */
async function resetFilters() {
  keyword.value = ''
  action.value = 'all'
  result.value = 'all'
  shard.value = ''
  await applyFilters()
}

/** 手动触发一次全链校验；断裂时 session 会自动弹出阻断式告警 */
async function runVerify() {
  try {
    const res = await session.verifyIntegrity({ auto: false })
    if (res?.intact) toast.success('完整性校验通过：全链哈希一致')
  } catch (err) {
    toast.error(err?.message || '校验失败')
  }
}

onMounted(async () => {
  // 本页只对审计管理员开放。管理员即使被导航到这里（正常路径下不会），
  // 这几个请求也会被后端以 NOT_AUDIT_ADMIN 拒绝，不如直接不发。
  if (!session.isAuditAdmin) return
  if (!session.logs.length) session.refreshLogs(currentQuery(1)).catch(() => {})
  if (!session.shards.length) session.refreshShards().catch(() => {})
})
</script>

<template>
  <div class="page">
    <header class="head">
      <div>
        <h2 class="head__title">审计日志</h2>
        <p class="head__sub">
          共 {{ session.auditTotal }} 条 · 本页失败 {{ failedCount }} 条 ·
          第 {{ session.auditPage.page }} / {{ totalPages }} 页 ·
          {{ session.lastSyncAt ? `同步于 ${formatRelative(session.lastSyncAt, now)}` : '尚未同步' }}
        </p>
      </div>
      <button type="button" class="btn" :disabled="session.loadingLogs" @click="refresh">
        <Spinner v-if="session.loadingLogs" :size="14" />
        <AppIcon v-else name="refresh" :size="14" />
        <span>刷新</span>
      </button>
    </header>

    <!-- 完整性状态卡片：实验二"改不掉"的可视化证据 -->
    <section class="panel panel--integrity" :class="{ 'is-broken': integrity && !integrity.intact }">
      <div class="integrity">
        <div class="integrity__main">
          <span
            class="integrity__icon"
            :class="integrity && !integrity.intact ? 'is-bad' : 'is-ok'"
            aria-hidden="true"
          >
            <AppIcon
              :name="integrity && !integrity.intact ? 'alert-triangle' : 'shield-check'"
              :size="18"
              :stroke-width="2"
            />
          </span>
          <div>
            <p class="integrity__title">
              <template v-if="!integrity">尚未执行完整性校验</template>
              <template v-else-if="integrity.intact">审计链完整，未被篡改</template>
              <template v-else>检测到审计链断裂</template>
            </p>
            <p class="integrity__sub">
              <template v-if="!integrity">
                校验会重算整条哈希链，任何直接改库、删记录、调顺序都会暴露。
              </template>
              <template v-else-if="integrity.intact">
                已校验 {{ integrity.checked ?? '—' }} 条记录 ·
                {{ integrity.legacySkipped ? `跳过改造前无哈希记录 ${integrity.legacySkipped} 条 · ` : '' }}
                校验于 {{ formatDateTime(integrity.checkedAt) }}
              </template>
              <template v-else>
                断裂序号 {{ integrity.firstBrokenSeq }} @ {{ integrity.brokenShard || '当前分片' }} ·
                {{ integrity.brokenReason || integrity.detail }} ·
                校验于 {{ formatDateTime(integrity.checkedAt) }}
              </template>
            </p>
            <!--
              把"日志怎么改都改不掉"这个属性写在卡片里，而不是只在代码里成立。
              三句并列是有意的：第 1 句说写入规则，第 2 句说删除与回改同样留痕
              （删掉或改掉都会破坏记录之间的哈希绑定），第 3 句说证据在链上 ——
              验收时不用翻文档就能把"不可篡改"讲完整。
              措辞不给操作暗示：不提"清空/删除"这类词，避免反被理解成
              "原来是有这个功能的"。
            -->
            <p class="integrity__note">
              日志只追加、不覆盖：不提供修改与删除入口；即便绕过界面直接改库或删记录，
              也会被下一条记录的前序哈希指认出来，且这条校验本身同样留在链上。
            </p>
          </div>
        </div>
        <button type="button" class="btn btn--primary" :disabled="session.verifying" @click="runVerify">
          <Spinner v-if="session.verifying" :size="14" />
          <AppIcon v-else name="shield-check" :size="14" />
          <span>{{ session.verifying ? '校验中…' : '立即校验' }}</span>
        </button>
      </div>
    </section>

    <section class="panel">
      <div class="panel__head">
        <!--
          左侧是标题 + "只读"徽记，上下排布。
          徽记刻意**不**塞进 h3 里：标题与工具栏挤在同一行，
          往标题里加东西会把"操作记录"压成两行，同时把工具栏顶下去，
          结果徽记和筛选控件折到第二行，看起来像两个不相干的区块。
          竖排之后标题保持一行，工具栏留在原位，层级也更顺：
          "这是只读的操作记录"读作一句话。

          "只读"徽记本身要说的事：审计日志的关键属性是"谁都改不了"，
          而这一点原先只体现在完整性校验卡片里 —— 那张卡片回答的是
          "有没有被改过"，不是"能不能改"。补这枚徽记是为了把后者也
          明说出来：不提供删除入口不是漏做，是设计如此。
          措辞只给结论（只读），不展开讲实现。
        -->
        <div class="panel__lead">
          <h3 class="panel__title">
            <AppIcon name="file-text" :size="15" />
            <span>操作记录</span>
          </h3>
          <span class="readonly" title="审计日志为追加写入，不提供修改或删除入口">
            <AppIcon name="snowflake" :size="11" :stroke-width="2" />
            <span>只读</span>
          </span>
        </div>

        <div class="toolbar">
          <div class="search">
            <span class="search__icon"><AppIcon name="search" :size="14" /></span>
            <input
              v-model="keyword"
              class="input"
              type="search"
              placeholder="搜索操作者 / 操作对象 / 请求 / 响应"
              aria-label="搜索审计日志"
              @keyup.enter="applyFilters"
            />
          </div>

          <select v-model="action" class="input select" aria-label="按操作类型筛选" @change="applyFilters">
            <option value="all">全部操作</option>
            <option v-for="a in ACTION_OPTIONS" :key="a" :value="a">
              {{ actionMeta(a).label }}
            </option>
          </select>

          <select v-model="result" class="input select" aria-label="按操作结果筛选" @change="applyFilters">
            <option v-for="r in RESULT_FILTERS" :key="r.key" :value="r.key">
              {{ r.label }}
            </option>
          </select>

          <select v-model="shard" class="input select" aria-label="按分片筛选" @change="applyFilters">
            <option v-for="s in shardOptions" :key="s.key" :value="s.key">{{ s.label }}</option>
          </select>

          <button
            type="button"
            class="btn btn--ghost"
            title="把搜索词与筛选条件恢复为默认（只影响本次查询，不涉及日志数据）"
            @click="resetFilters"
          >
            <AppIcon name="refresh" :size="13" />
            <span>重置筛选</span>
          </button>
        </div>
      </div>

      <div class="table-wrap">
        <table class="table table--dense">
          <thead>
            <tr>
              <th style="width: 58px">序号</th>
              <th style="width: 150px">时间</th>
              <th style="width: 130px">操作者</th>
              <th style="width: 110px">动作</th>
              <th style="width: 80px">结果</th>
              <th style="width: 132px">原因</th>
              <th style="width: 90px">前状态</th>
              <th style="width: 90px">后状态</th>
              <th>请求 / 响应摘要</th>
              <th style="width: 70px">详情</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="log in session.logs" :key="log.id">
              <td class="table__mono seq cell-seq">
                <span :title="log.selfHash ? `selfHash: ${log.selfHash}` : '改造前的旧记录（无哈希）'">
                  {{ log.seq ?? '—' }}
                </span>
              </td>
              <td class="table__mono">
                <div>{{ formatDateTime(log.timestamp) }}</div>
                <div class="ago">{{ formatRelative(log.timestamp, now) }}</div>
              </td>
              <td class="cell-op selectable">
                <div>{{ log.operatorName || 'anonymous' }}</div>
                <div v-if="log.actorType" class="target">{{ log.actorType }}</div>
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
              <td class="reason">
                <span
                  v-if="log.reasonCode"
                  class="reason__label"
                  :title="`${reasonLabel(log.reasonCode)}（${log.reasonCode}）`"
                >
                  {{ reasonLabel(log.reasonCode) }}
                </span>
                <span v-else class="reason__none">—</span>
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

            <tr v-if="!session.logs.length">
              <td colspan="10">
                <div class="empty">
                  <AppIcon name="file-text" :size="22" />
                  <p class="empty__title">没有匹配的日志记录</p>
                  <p class="empty__desc">调整搜索关键词、操作类型、结果或分片筛选</p>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <footer class="pager">
        <span class="pager__info">
          第 {{ session.auditPage.page }} / {{ totalPages }} 页 · 每页 {{ session.auditPage.pageSize }} 条
        </span>
        <div class="pager__btns">
          <button type="button" class="btn btn--sm" :disabled="session.auditPage.page <= 1 || session.loadingLogs" @click="goPage(1)">
            首页
          </button>
          <button type="button" class="btn btn--sm" :disabled="session.auditPage.page <= 1 || session.loadingLogs" @click="goPage(session.auditPage.page - 1)">
            上一页
          </button>
          <button type="button" class="btn btn--sm" :disabled="session.auditPage.page >= totalPages || session.loadingLogs" @click="goPage(session.auditPage.page + 1)">
            下一页
          </button>
          <button type="button" class="btn btn--sm" :disabled="session.auditPage.page >= totalPages || session.loadingLogs" @click="goPage(totalPages)">
            末页
          </button>
        </div>
      </footer>
    </section>

    <!-- 日志详情（可拖拽子窗口） -->
    <AppWindow
      :open="!!detail"
      title="审计日志详情"
      icon="file-text"
      :width="620"
      @close="detail = null"
    >
      <div v-if="detail" class="detail">
        <dl class="detail__kv">
          <div><dt>序号</dt><dd class="selectable mono">{{ detail.seq ?? '—' }}</dd></div>
          <div><dt>时间</dt><dd class="selectable">{{ formatDateTime(detail.timestamp) }}</dd></div>
          <div><dt>操作者</dt><dd class="selectable">{{ detail.operatorName || 'anonymous' }}</dd></div>
          <div><dt>主体类型</dt><dd class="selectable">{{ detail.actorType || '—' }}</dd></div>
          <div><dt>动作</dt><dd>{{ actionMeta(detail.action).label }}</dd></div>
          <div><dt>结果</dt><dd>{{ resultMeta(detail.result || '成功').label }}</dd></div>
          <div v-if="detail.reasonCode">
            <dt>原因</dt>
            <dd>
              <span class="selectable">{{ reasonLabel(detail.reasonCode) }}</span>
              <span class="mono reason__code">{{ detail.reasonCode }}</span>
            </dd>
          </div>
          <div v-if="detail.target"><dt>操作对象</dt><dd class="selectable">{{ detail.target }}</dd></div>
          <div><dt>状态变化</dt><dd class="selectable">{{ detail.statusBefore }} → {{ detail.statusAfter }}</dd></div>
          <div v-if="detail.sourceIp"><dt>来源 IP</dt><dd class="selectable mono">{{ detail.sourceIp }}</dd></div>
          <div v-if="detail.shard"><dt>所属分片</dt><dd class="selectable mono">{{ detail.shard }}</dd></div>
        </dl>

        <div v-if="detail.sourceUserAgent" class="detail__block">
          <div class="detail__label">来源 UA</div>
          <pre class="code selectable">{{ detail.sourceUserAgent }}</pre>
        </div>

        <div class="detail__block">
          <div class="detail__label">请求报文</div>
          <pre class="code selectable">{{ prettyJson(detail.request) || '—' }}</pre>
        </div>

        <div class="detail__block">
          <div class="detail__label">响应报文</div>
          <pre class="code selectable">{{ prettyJson(detail.response) || '—' }}</pre>
        </div>

        <!-- 哈希链证据：证明这条记录在链上如何与前一条绑定 -->
        <div v-if="detail.selfHash || detail.prevHash" class="detail__block">
          <div class="detail__label">哈希链证据</div>
          <div class="hashline">
            <span class="hashline__tag">prevHash</span>
            <code class="mono">{{ detail.prevHash || '（链首）' }}</code>
          </div>
          <div class="hashline">
            <span class="hashline__tag hashline__tag--self">selfHash</span>
            <code class="mono">{{ detail.selfHash || '—' }}</code>
          </div>
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

/* 完整性面板 */
.panel--integrity {
  border-left: 3px solid var(--st-enabled-fg);
}
.panel--integrity.is-broken {
  border-left-color: var(--c-danger);
}

.integrity {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-4);
}

.integrity__main {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  min-width: 0;
}

.integrity__icon {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 36px;
  height: 36px;
  border-radius: 50%;
}
.integrity__icon.is-ok {
  background: var(--st-enabled-bg);
  color: var(--st-enabled-fg);
}
.integrity__icon.is-bad {
  background: var(--c-danger-soft, rgba(220, 60, 60, 0.14));
  color: var(--c-danger);
}

.integrity__title {
  margin: 0 0 2px;
  font-size: var(--fs-base);
  font-weight: 650;
  color: var(--c-text);
}

.integrity__sub {
  margin: 0;
  font-size: var(--fs-sm);
  line-height: 1.6;
  color: var(--c-text-muted);
}

/**
 * 完整性卡片里的"只追加"说明。
 *
 * 比正文再轻一档（subtle + xs）：它是制度性说明，不是当前状态，
 * 不该和上面那句"校验于几点几分"抢注意力。
 */
.integrity__note {
  margin: var(--sp-2) 0 0;
  font-size: var(--fs-xs);
  line-height: 1.65;
  color: var(--c-text-subtle);
}

.toolbar {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  flex-wrap: wrap;
}

/**
 * 「只读」徽记。
 *
 * 用中性色（surface-2 + 次要文字色）而不是告警色：这是系统的常态属性，
 * 不是需要处理的异常。一旦上红/黄，会让人以为日志出了问题，
 * 而真正需要报警的"检测到篡改"反而被淹没。
 *
 * flex-shrink: 0 —— 徽记只有 2 个字 + 1 个图标，被压缩就会换行，
 * 变成上下两行的小方块，比不显示还难看。
 */
.readonly {
  display: inline-flex;
  align-items: center;
  flex-shrink: 0;
  align-self: flex-start;
  gap: 4px;
  padding: 1px 7px;
  border-radius: var(--r-full);
  background: var(--c-surface-2);
  color: var(--c-text-subtle);
  font-size: var(--fs-xs);
  font-weight: 600;
  line-height: 1.7;
  white-space: nowrap;
}

/** 标题 + 只读徽记：竖排，避免与右侧工具栏争抢同一行宽度 */
.panel__lead {
  display: flex;
  flex-direction: column;
  gap: 5px;
  min-width: 0;
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

.cell-seq {
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

/**
 * 原因列。
 *
 * 用中性色而不是红色：这一列里既有"失败原因"也有"越权原因"，
 * 整列泛红会让正常的登录失败与真正的越权攻击在视觉上失去区分度，
 * 而那恰恰是审计员最需要分辨的一点。
 *
 * 限一行 + 省略号：原因文案长短不一（"新旧口令相同" 6 字，"越界访问审计
 * 数据（非审计管理员）" 14 字），不截断会把表格其他列挤变形；
 * 完整文案与原始原因码都在 title 与详情弹窗里，需要时随时可查。
 */
.reason {
  max-width: 132px;
  font-size: var(--fs-xs);
  overflow: hidden;
}
.reason__label {
  display: block;
  overflow: hidden;
  color: var(--c-text-muted);
  text-overflow: ellipsis;
  white-space: nowrap;
}
.reason__none {
  color: var(--c-text-subtle);
}
.reason__code {
  margin-left: var(--sp-2);
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
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
.act--warn {
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
  max-width: 400px;
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

/* 分页 */
.pager {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-3);
  padding: var(--sp-3) var(--sp-4);
  border-top: 1px solid var(--c-border);
}

.pager__info {
  font-size: var(--fs-xs);
  color: var(--c-text-muted);
}

.pager__btns {
  display: flex;
  gap: var(--sp-2);
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
  min-width: 0;
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

.hashline {
  display: flex;
  align-items: baseline;
  gap: var(--sp-2);
  padding: 4px var(--sp-3);
  border-radius: var(--r-sm);
  background: var(--c-surface-2);
  font-size: var(--fs-sm);
}
.hashline + .hashline {
  margin-top: 5px;
}
.hashline__tag {
  flex-shrink: 0;
  padding: 1px 6px;
  border-radius: var(--r-xs);
  background: var(--st-disabled-bg);
  color: var(--st-disabled-fg);
  font-size: var(--fs-xs);
  font-weight: 600;
}
.hashline__tag--self {
  background: var(--c-primary-soft);
  color: var(--c-primary);
}

.mono {
  font-family: var(--font-mono);
  word-break: break-all;
}
</style>
