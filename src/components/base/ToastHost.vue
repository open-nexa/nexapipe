<script setup lang="ts">
/**
 * Toast host (§5.6). Renders the `useToast` singleton at the app root — bottom-right, at most
 * four visible, click anywhere on a toast to dismiss it.
 *
 * `aria-live="polite"` so a failure that happens while the user is elsewhere is still announced;
 * errors are not `assertive` on purpose, since a log-poll failure storm should not interrupt
 * whatever the user is reading.
 */
import { useI18n } from 'vue-i18n';
import AppIcon from './AppIcon.vue';
import { useToast } from '../../composables/useToast';

const { toasts, dismiss } = useToast();
const { t } = useI18n();

const ICON: Record<string, string> = {
  success: 'check',
  error: 'alert-circle',
  warning: 'alert-triangle',
  info: 'info',
};
</script>

<template>
  <div class="toast-host" role="status" aria-live="polite">
    <TransitionGroup name="toast">
      <button
        v-for="toast in toasts"
        :key="toast.id"
        type="button"
        class="toast"
        :class="`tone-${toast.tone}`"
        @click="dismiss(toast.id)"
      >
        <span class="toast-icon">
          <AppIcon :name="ICON[toast.tone] ?? 'info'" :size="16" />
        </span>
        <span class="toast-message" data-selectable>{{ toast.message }}</span>
        <span class="toast-close" :aria-label="t('common.close')">
          <AppIcon name="window-close" :size="12" />
        </span>
      </button>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-host {
  position: fixed;
  right: var(--space-5);
  bottom: var(--space-5);
  z-index: 400;
  display: flex;
  flex-direction: column-reverse;
  gap: var(--space-2);
  width: min(360px, calc(100vw - 2 * var(--space-5)));
  pointer-events: none;
}

.toast {
  display: flex;
  align-items: flex-start;
  gap: var(--space-3);
  width: 100%;
  padding: var(--space-3) var(--space-4);
  background: var(--bg-elevated);
  border: 1px solid var(--border-default);
  border-left-width: 3px;
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-popup);
  text-align: left;
  pointer-events: auto;
  transition: transform var(--duration-fast) var(--ease-standard);
}

.toast:hover {
  transform: translateX(-2px);
}

.toast:focus-visible {
  box-shadow: var(--shadow-popup), var(--focus-ring);
}

.toast-icon {
  display: inline-flex;
  margin-top: 1px;
  flex-shrink: 0;
}

.toast-message {
  flex: 1;
  min-width: 0;
  font-size: var(--font-size-13);
  line-height: var(--line-height-normal);
  color: var(--text-primary);
  overflow-wrap: anywhere;
}

.toast-close {
  display: inline-flex;
  margin-top: 2px;
  color: var(--text-muted);
  flex-shrink: 0;
}

.toast:hover .toast-close {
  color: var(--text-secondary);
}

.tone-success {
  border-left-color: var(--success);
}

.tone-success .toast-icon {
  color: var(--success);
}

.tone-error {
  border-left-color: var(--error);
}

.tone-error .toast-icon {
  color: var(--error);
}

.tone-warning {
  border-left-color: var(--warning);
}

.tone-warning .toast-icon {
  color: var(--warning);
}

.tone-info {
  border-left-color: var(--info);
}

.tone-info .toast-icon {
  color: var(--info);
}

/* -- transitions ---------------------------------------------------------------------------- */

.toast-enter-active,
.toast-leave-active {
  transition:
    opacity var(--duration-normal) var(--ease-out),
    transform var(--duration-normal) var(--ease-out);
}

.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateX(12px);
}
</style>
