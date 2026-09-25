<script setup>
import { computed } from 'vue'
import AppIcon from './AppIcon.vue'
import AppWindow from './AppWindow.vue'
import { useSessionStore } from '../stores/session'
import { formatDateTime } from '../utils/format'

/**
 * 越权访问告警弹窗。
 *
 * 与「审计完整性告警」是一对姊妹弹窗，但盯的不是同一类痕迹：
 *   · 完整性告警 = 库里的历史被改写（链断裂）；
 *   · 越权告警   = 有人正试着读他不该读的东西（访问被拒）。
 *
 * 为什么这类事件必须弹窗而不是一条 Toast：
 *   越权尝试往往根本不经过本界面 —— 有人用 curl / PowerShell 直接打
 *   /api/audit/logs，屏幕上不会有任何异常。若只留一条静默的审计记录，
 *   管理员要等到"某天翻日志"才会发现，防护就失去了时效。
 *   这里把它变成管理员当场可见的事件，并给出"谁、从哪来、想访问什么"。
 *
 * 数据来自 session.intrusionAlert，由 checkIntrusion 在发现新的
 * AUDIT_ACCESS_DENIED 事件时写入。
 */
const session = useSessionStore()

/** 拒绝原因码 → 人话。前端只做展示映射，判定归服务端 */
const REASON_TEXT = {
  NO_TICKET: '未携带访问凭证',
  SESSION_INVALID: '访问凭证无效或已失效',
  SESSION_EXPIRED: '访问凭证已过期',
  SESSION_REVOKED: '访问凭证已被吊销',
  NOT_ADMIN: '已登录，但不具备管理员权限',
  ACCOUNT_NOT_ENABLED: '账号未启用'
}

const alert = computed(() => session.intrusionAlert)
const detail = computed(() => alert.value?.detail ?? null)

const reasonText = computed(() => {
  const code = detail.value?.reasonCode
  if (!code) return '—'
  return REASON_TEXT[code] || code
})

/**
 * 被尝试访问的接口与原始查询串。
 *
 * request 字段在库里是以 JSON 字符串保存的，且历史上两种命名风格都出现过，
 * 因此这里同时兼容 PascalCase 与 camelCase，避免因序列化配置差异而显示空白。
 */
const attempt = computed(() => {
  const raw = detail.value?.request
  if (!raw) return null
  let obj = raw
  if (typeof raw === 'string') {
    try {
      obj = JSON.parse(raw)
    } catch {
      return { path: '', query: '', target: '' }
    }
  }
  if (!obj || typeof obj !== 'object') return null
  return {
    path: obj.Path || obj.path || '',
    query: obj.Query || obj.query || '',
    target: obj.AttemptedTarget || obj.attemptedTarget || ''
  }
})

/** 未认证请求的 operatorName 是 anonymous，直接显示出来对管理员没有意义 */
const actorLabel = computed(() => {
  const name = detail.value?.operatorName
  if (!name || name === 'anonymous') return '未认证请求'
  return name
})
</script>

<template>
  <AppWindow
    :open="!!alert"
    title="越权访问告警"
    icon="shield"
    tone="warn"
    :width="600"
    :close-on-overlay="false"
    @close="session.dismissIntrusionAlert()"
  >
    <div v-if="alert" class="alert">
      <div class="alert__head">
        <span class="alert__icon" aria-hidden="true">
          <AppIcon name="ban" :size="20" :stroke-width="2" />
        </span>
        <div>
          <p class="alert__title">检测到越权访问尝试</p>
          <p class="alert__sub">
            有人在没有有效管理员凭证的情况下尝试读取审计数据，已被服务端拒绝并记录在案。
          </p>
        </div>
      </div>

      <dl class="alert__kv">
        <div>
          <dt>审计序号</dt>
          <dd class="mono">{{ alert.seq }}</dd>
        </div>
        <div>
          <dt>操作者</dt>
          <dd>{{ actorLabel }}</dd>
        </div>
        <div>
          <dt>发生时间</dt>
          <dd>{{ detail?.timestamp ? formatDateTime(detail.timestamp) : '—' }}</dd>
        </div>
        <div>
          <dt>拒绝原因</dt>
          <dd>{{ reasonText }}</dd>
        </div>
        <div>
          <dt>来源 IP</dt>
          <dd class="mono">{{ detail?.sourceIp || '—' }}</dd>
        </div>
        <div>
          <dt>累计被拒次数</dt>
          <dd>{{ alert.count }}</dd>
        </div>
      </dl>

      <div v-if="attempt" class="alert__block">
        <div class="alert__label">被尝试访问的接口</div>
        <div class="alert__req">
          <code class="mono">{{ attempt.path || attempt.target || '—' }}</code>
          <span v-if="attempt.query" class="alert__query mono">{{ attempt.query }}</span>
        </div>
      </div>

      <p class="alert__advice">
        该尝试已作为
        <code class="mono">AUDIT_ACCESS_DENIED</code>
        事件写入审计日志，可在「审计日志」页把操作类型筛选为「越权访问被拒」查看全部记录。
        关闭本提示后不会再重复出现。
      </p>
    </div>

    <template #footer>
      <button type="button" class="btn btn--primary" data-autofocus @click="session.dismissIntrusionAlert()">
        我知道了
      </button>
    </template>
  </AppWindow>
</template>

<style scoped>
.alert {
  display: flex;
  flex-direction: column;
  gap: var(--sp-4);
}

.alert__head {
  display: flex;
  gap: var(--sp-3);
  align-items: flex-start;
  padding: var(--sp-3);
  border-radius: var(--r-md);
  background: var(--c-warn-soft);
}

.alert__icon {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 34px;
  height: 34px;
  border-radius: 50%;
  background: var(--c-warn);
  color: #fff;
}

.alert__title {
  margin: 0 0 3px;
  font-size: var(--fs-lg);
  font-weight: 650;
  color: var(--c-warn);
}

.alert__sub {
  margin: 0;
  font-size: var(--fs-sm);
  line-height: 1.6;
  color: var(--c-text-muted);
}

.alert__kv {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--sp-2) var(--sp-4);
  margin: 0;
}
.alert__kv div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.alert__kv dt {
  font-size: var(--fs-xs);
  color: var(--c-text-subtle);
}
.alert__kv dd {
  margin: 0;
  font-size: var(--fs-base);
  color: var(--c-text);
  word-break: break-all;
}

.alert__label {
  margin-bottom: 5px;
  font-size: var(--fs-xs);
  font-weight: 600;
  color: var(--c-text-muted);
}

.alert__req {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--sp-2);
  padding: var(--sp-3);
  border-left: 3px solid var(--c-warn);
  border-radius: var(--r-sm);
  background: var(--c-surface-2);
  font-size: var(--fs-sm);
  color: var(--c-text);
}

.alert__query {
  padding: 1px 6px;
  border-radius: var(--r-xs);
  background: var(--c-warn-soft);
  color: var(--c-warn);
  font-size: var(--fs-xs);
}

.mono {
  font-family: var(--font-mono);
  word-break: break-all;
}

.alert__advice {
  margin: 0;
  font-size: var(--fs-sm);
  line-height: 1.65;
  color: var(--c-text-muted);
}
</style>
