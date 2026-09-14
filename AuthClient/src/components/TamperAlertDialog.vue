<script setup>
import AppIcon from './AppIcon.vue'
import AppWindow from './AppWindow.vue'
import { useSessionStore } from '../stores/session'
import { formatDateTime } from '../utils/format'

/**
 * 审计完整性告警弹窗。
 *
 * 为什么必须是"弹窗"而不是一条 Toast：
 *   审计链断裂意味着有人绕过应用直接改动了数据库中的日志 ——
 *   这是安全事件，不是普通提示。用户明确要求"直接改数据库也要弹窗"，
 *   因此这里用阻断式对话框，并把断点、期望哈希、实际哈希全部摊开，
 *   让管理员一眼看清"哪一条、被改成了什么样"。
 *
 * 数据来自 session.tamperAlert（由 verifyIntegrity 在检出断裂时写入）。
 */
const session = useSessionStore()

function shorten(hash) {
  if (!hash) return '—'
  const s = String(hash)
  if (s.length <= 20) return s
  return `${s.slice(0, 16)}…${s.slice(-8)}`
}
</script>

<template>
  <AppWindow
    :open="!!session.tamperAlert"
    title="审计完整性告警"
    icon="alert-triangle"
    tone="danger"
    :width="600"
    :close-on-overlay="false"
    @close="session.dismissTamperAlert()"
  >
    <div v-if="session.tamperAlert" class="alert">
      <div class="alert__head">
        <span class="alert__icon" aria-hidden="true">
          <AppIcon name="alert-triangle" :size="20" :stroke-width="2" />
        </span>
        <div>
          <p class="alert__title">检测到审计日志被篡改</p>
          <p class="alert__sub">
            哈希链已在序号 <strong>{{ session.tamperAlert.seq }}</strong> 处断裂。
            日志记录可能被直接修改、删除或调换顺序。
          </p>
        </div>
      </div>

      <dl class="alert__kv">
        <div>
          <dt>断裂序号</dt>
          <dd class="mono">{{ session.tamperAlert.seq }}</dd>
        </div>
        <div>
          <dt>所在分片</dt>
          <dd class="mono">{{ session.tamperAlert.shard || '—' }}</dd>
        </div>
        <div>
          <dt>事发时间</dt>
          <dd>{{ session.tamperAlert.brokenAt ? formatDateTime(session.tamperAlert.brokenAt) : '—' }}</dd>
        </div>
        <div>
          <dt>检出方式</dt>
          <dd>{{ session.tamperAlert.detectedBy }}</dd>
        </div>
        <div>
          <dt>检出时间</dt>
          <dd>{{ formatDateTime(session.tamperAlert.detectedAt) }}</dd>
        </div>
      </dl>

      <div class="alert__block">
        <div class="alert__label">断裂原因</div>
        <p class="alert__reason">{{ session.tamperAlert.reason || session.tamperAlert.detail }}</p>
      </div>

      <div class="alert__block">
        <div class="alert__label">哈希比对</div>
        <div class="alert__hash">
          <span class="alert__hash-tag">重算得到</span>
          <code class="mono">{{ shorten(session.tamperAlert.expected) }}</code>
        </div>
        <div class="alert__hash">
          <span class="alert__hash-tag alert__hash-tag--bad">数据库中实际存的是</span>
          <code class="mono">{{ shorten(session.tamperAlert.actual) }}</code>
        </div>
      </div>

      <p class="alert__advice">
        建议：立即核查该序号的原始记录与数据库访问权限，并在确认篡改范围前停止向该库写入。
        本次告警已作为
        <code class="mono">AUDIT_TAMPERED</code>
        事件写入审计日志。
      </p>
    </div>

    <template #footer>
      <button type="button" class="btn" data-autofocus @click="session.dismissTamperAlert()">
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
  background: var(--c-danger-soft, rgba(220, 60, 60, 0.1));
}

.alert__icon {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 34px;
  height: 34px;
  border-radius: 50%;
  background: var(--c-danger);
  color: #fff;
}

.alert__title {
  margin: 0 0 3px;
  font-size: var(--fs-lg);
  font-weight: 650;
  color: var(--c-danger);
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

.alert__reason {
  margin: 0;
  padding: var(--sp-3);
  border-left: 3px solid var(--c-danger);
  border-radius: var(--r-sm);
  background: var(--c-surface-2);
  font-size: var(--fs-sm);
  line-height: 1.65;
  color: var(--c-text);
}

.alert__hash {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  padding: 5px var(--sp-3);
  border-radius: var(--r-sm);
  background: var(--c-surface-2);
  font-size: var(--fs-sm);
}
.alert__hash + .alert__hash {
  margin-top: 5px;
}

.alert__hash-tag {
  flex-shrink: 0;
  padding: 1px 6px;
  border-radius: var(--r-xs);
  background: var(--st-enabled-bg);
  color: var(--st-enabled-fg);
  font-size: var(--fs-xs);
  font-weight: 600;
}
.alert__hash-tag--bad {
  background: var(--c-danger-soft, rgba(220, 60, 60, 0.14));
  color: var(--c-danger);
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
