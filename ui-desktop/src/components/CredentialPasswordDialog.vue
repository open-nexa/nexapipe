<script setup lang="ts">
/**
 * The password prompt for the platforms that have none of their own.
 *
 * Linux asks through PAM, and PAM has no dialog: it asks the application for the password. So
 * this is the one place in the app where a credential is typed rather than stored — the value goes
 * to Rust, is handed to PAM, and is zeroed there. Nothing here keeps it: the field is cleared the
 * moment the dialog settles, in either direction.
 *
 * Driven by `usePassword`, the same way `AppDialog` is driven by `useConfirm`: a module singleton
 * and a promise, so no caller has to own a `visible` flag.
 */
import { nextTick, onBeforeUnmount, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import AppButton from './base/AppButton.vue';
import AppIcon from './base/AppIcon.vue';
import { usePasswordState } from '../composables/usePassword';

const { request, settle } = usePasswordState();
const { t } = useI18n();

const field = ref<HTMLInputElement | null>(null);
const value = ref('');
let previouslyFocused: HTMLElement | null = null;

function submit(): void {
  const password = value.value;
  value.value = '';
  settle(password === '' ? null : password);
}

function cancel(): void {
  value.value = '';
  settle(null);
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    event.preventDefault();
    cancel();
  }
}

watch(
  () => request.value !== null,
  async (isOpen) => {
    if (isOpen) {
      previouslyFocused = document.activeElement as HTMLElement | null;
      value.value = '';
      await nextTick();
      // The field, not the button: what the user came here to do is type.
      field.value?.focus();
    } else {
      previouslyFocused?.focus?.();
      previouslyFocused = null;
    }
  },
);

onBeforeUnmount(() => {
  previouslyFocused?.focus?.();
});
</script>

<template>
  <Teleport to="body">
    <div v-if="request" class="password-overlay" @click.self="cancel" @keydown="onKeydown">
      <div
        class="password-panel"
        role="alertdialog"
        aria-modal="true"
        :aria-label="request.title"
        tabindex="-1"
        @keydown="onKeydown"
      >
        <header class="password-header">
          <span class="password-icon">
            <AppIcon name="lock" :size="18" />
          </span>
          <h2 class="password-title">{{ request.title }}</h2>
        </header>

        <p class="password-message">{{ request.message }}</p>

        <form class="password-field" @submit.prevent="submit">
          <label class="password-label" for="credential-password">
            {{ t('gate.passwordLabel') }}
          </label>
          <input
            id="credential-password"
            ref="field"
            v-model="value"
            type="password"
            autocomplete="current-password"
            class="password-input"
            @keydown.enter.prevent="submit"
          />
        </form>

        <footer class="password-actions">
          <AppButton tone="ghost" @click="cancel">{{ t('common.cancel') }}</AppButton>
          <AppButton tone="primary" :disabled="value === ''" @click="submit">
            {{ request.confirmText }}
          </AppButton>
        </footer>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.password-overlay {
  position: fixed;
  inset: 0;
  z-index: 300;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--space-6);
  background: var(--bg-overlay);
}

.password-panel {
  width: 100%;
  max-width: 420px;
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-6);
  background: var(--bg-elevated);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-popup);
}

.password-panel:focus-visible {
  box-shadow: var(--shadow-popup), var(--focus-ring);
}

.password-header {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}

.password-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: var(--radius-md);
  background: var(--accent-subtle);
  color: var(--accent-text);
  flex-shrink: 0;
}

.password-title {
  font-size: var(--font-size-16);
  font-weight: var(--font-weight-semibold);
  color: var(--text-primary);
}

.password-message {
  font-size: var(--font-size-13);
  color: var(--text-secondary);
  overflow-wrap: anywhere;
}

.password-field {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.password-label {
  font-size: var(--font-size-12);
  color: var(--text-muted);
}

.password-input {
  padding: var(--space-2) var(--space-3);
  background: var(--bg-inset);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-sm);
  color: var(--text-primary);
  font-size: var(--font-size-13);
}

.password-input:focus-visible {
  outline: none;
  box-shadow: var(--focus-ring);
}

.password-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-2);
}
</style>
