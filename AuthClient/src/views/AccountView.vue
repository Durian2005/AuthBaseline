<script setup>
import { computed, ref } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import PasswordField from '../components/PasswordField.vue'
import PasswordRules from '../components/PasswordRules.vue'
import Spinner from '../components/Spinner.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { useSessionStore } from '../stores/session'
import { useToastStore } from '../stores/toast'
import { ApiError } from '../api/client'
import { isPasswordStrong } from '../utils/password'
import { formatDuration } from '../utils/format'

const session = useSessionStore()
const toast = useToastStore()

const form = ref({ old: '', next: '', confirm: '' })
const touched = ref(false)
const formError = ref('')

const errors = computed(() => {
  const f = form.value
  return {
    old: !f.old ? '请输入当前密码' : '',
    next: !f.next
      ? '请输入新密码'
      : !isPasswordStrong(f.next)
        ? '新口令复杂度不满足要求'
        : f.next === f.old
          ? '新密码不能与旧密码相同'
          : '',
    confirm: f.confirm !== f.next ? '两次输入的新密码不一致' : ''
  }
})

const canSubmit = computed(() =>
  form.value.old &&
  isPasswordStrong(form.value.next) &&
  form.value.next !== form.value.old &&
  form.value.confirm === form.value.next
)

async function submit() {
  touched.value = true
  formError.value = ''
  if (!canSubmit.value) return

  try {
    const res = await session.changePassword(form.value.old, form.value.next)
    toast.success(res?.message || '密码修改成功')
    form.value = { old: '', next: '', confirm: '' }
    touched.value = false
    // 与后端语义保持一致：口令已变更，旧会话需重新认证
    await new Promise((r) => setTimeout(r, 600))
    session.logout({ silent: true })
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(err.message)
    formError.value = e.message
  }
}
</script>

<template>
  <div class="page">
    <header class="head">
      <div>
        <h2 class="head__title">账号与口令</h2>
        <p class="head__sub">修改口令后，旧口令立即失效，需要重新登录。</p>
      </div>
    </header>

    <div class="cols">
      <!-- 修改口令 -->
      <section class="panel">
        <div class="panel__head">
          <h3 class="panel__title"><AppIcon name="key" :size="15" /><span>修改密码</span></h3>
        </div>

        <div class="panel__body">
          <form class="stack" novalidate @submit.prevent="submit">
            <div v-if="formError" class="alert" role="alert">
              <AppIcon name="alert-triangle" :size="15" :stroke-width="2" />
              <span class="selectable">{{ formError }}</span>
            </div>

            <PasswordField
              v-model="form.old"
              label="当前密码"
              placeholder="请输入当前使用的密码"
              autocomplete="off"
              :invalid="touched && !!errors.old"
              :error="touched ? errors.old : ''"
              autofocus
            />

            <hr class="divider" />

            <PasswordField
              v-model="form.next"
              label="新密码"
              placeholder="设置新的登录密码"
              autocomplete="new-password"
              :invalid="touched && !!errors.next"
              :error="touched ? errors.next : ''"
            />

            <PasswordRules :value="form.next" />

            <PasswordField
              v-model="form.confirm"
              label="确认新密码"
              placeholder="再次输入新密码"
              autocomplete="new-password"
              :invalid="touched && !!errors.confirm"
              :error="touched ? errors.confirm : ''"
              @enter="submit"
            />

            <div class="actions">
              <button type="submit" class="btn btn--primary" :disabled="session.submitting">
                <Spinner v-if="session.submitting" :size="14" />
                <AppIcon v-else name="check-circle" :size="15" />
                <span>确认修改</span>
              </button>
              <button
                type="button"
                class="btn btn--ghost"
                @click="form = { old: '', next: '', confirm: '' }; touched = false; formError = ''"
              >
                清空
              </button>
            </div>
          </form>
        </div>
      </section>

      <!-- 账号状态 -->
      <section class="panel">
        <div class="panel__head">
          <h3 class="panel__title"><AppIcon name="shield" :size="15" /><span>安全状态</span></h3>
        </div>

        <div class="panel__body sec">
          <div class="sec__row">
            <span class="sec__label">登录账号</span>
            <span class="sec__value selectable">{{ session.currentUser?.username }}</span>
          </div>
          <div class="sec__row">
            <span class="sec__label">账号状态</span>
            <StatusBadge :status="session.status" />
          </div>
          <div class="sec__row">
            <span class="sec__label">口令存储</span>
            <span class="sec__value">BCrypt 哈希（不存明文）</span>
          </div>
          <div class="sec__row">
            <span class="sec__label">锁定阈值</span>
            <span class="sec__value">连续 3 次错误 / 锁定 {{ formatDuration(180) }}</span>
          </div>

          <hr class="divider" />

          <ul class="tips">
            <li><AppIcon name="check-circle" :size="13" />口令至少 8 位，含大小写字母与数字</li>
            <li><AppIcon name="check-circle" :size="13" />不要与其他站点复用同一口令</li>
            <li><AppIcon name="check-circle" :size="13" />所有口令操作均记入审计日志</li>
          </ul>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: var(--sp-4);
  max-width: 980px;
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

.cols {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: var(--sp-3);
  align-items: start;
}

.stack {
  display: flex;
  flex-direction: column;
  gap: var(--sp-4);
}

.actions {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
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

.sec {
  display: flex;
  flex-direction: column;
  gap: var(--sp-3);
}

.sec__row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-3);
  font-size: var(--fs-base);
}
.sec__label {
  color: var(--c-text-muted);
}
.sec__value {
  color: var(--c-text);
  text-align: right;
  word-break: break-all;
}

.tips {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
  margin: 0;
  padding: 0;
  list-style: none;
}
.tips li {
  display: flex;
  align-items: flex-start;
  gap: var(--sp-2);
  font-size: var(--fs-sm);
  line-height: 1.5;
  color: var(--c-text-muted);
}
.tips svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--st-enabled-fg);
}
</style>
