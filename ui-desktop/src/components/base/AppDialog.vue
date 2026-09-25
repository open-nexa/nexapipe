<script setup lang="ts">
/**
 * Generic dialog, driven by `useConfirm` (§5.6). Replaces the old `ConfirmDialog.vue`, which was
 * rendered at the app root but whose `visible` flag nothing ever set.
 *
 * Accessibility contract from the plan's Phase 4 list: `Esc` closes and returns focus to the
 * element that opened it, Tab stays inside while open, and the destructive action is never the
 * element that receives focus by accident — the panel takes focus first, the confirm button
 * carries `data-autofocus`.
 */
import { nextTick, onBeforeUnmount, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import AppButton from './AppButton.vue';
import AppIcon from './AppIcon.vue';

const props = withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    message: string;
    tone?: 'info' | 'warning' | 'danger';
    confirmText?: string;
    cancelText?: string;
    detail?: string;
  }>(),
  {
    tone: 'info',
    confirmText: undefined,
    cancelText: undefined,
    detail: undefined,
  },
);

const emit = defineEmits<{
  (e: 'confirm'): void;
  (e: 'cancel'): void;
}>();

const { t } = useI18n();
const panel = ref<HTMLElement | null>(null);
const showDetails = ref(false);
let previouslyFocused: HTMLElement | null = null;

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function focusables(): HTMLElement[] {
  if (!panel.value) return [];
  return Array.from(panel.value.querySelectorAll<HTMLElement>(FOCUSABLE));
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    event.preventDefault();
    emit('cancel');
    return;
  }

  if (event.key !== 'Tab') return;

  const items = focusables();
  if (items.length === 0) return;

  const first = items[0]!;
  const last = items[items.length - 1]!;
  const active = document.activeElement as HTMLElement | null;

  if (event.shiftKey && (active === first || active === panel.value)) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  }
}

watch(
  () => props.open,
  async (isOpen) => {
    if (isOpen) {
      previouslyFocused = document.activeElement as HTMLElement | null;
      // The confirm button is deliberately not auto-focused: a destructive action should not be
      // one stray Enter away from the keyboard state that opened the dialog.
      await nextTick();
      panel.value?.focus();
    } else {
      previouslyFocused?.focus?.();
      previouslyFocused = null;
      showDetails.value = false;
    }
  },
);

onBeforeUnmount(() => {
  previouslyFocused?.focus?.();
});
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="dialog-overlay"
      @click.self="emit('cancel')"
      @keydown="onKeydown"
    >
      <div
        ref="panel"
        class="dialog-panel"
        role="alertdialog"
        aria-modal="true"
        :aria-label="title"
        tabindex="-1"
        @keydown="onKeydown"
      >
        <header class="dialog-header">
          <span class="dialog-icon" :class="`tone-${tone}`">
            <AppIcon
              :name="tone === 'danger' ? 'alert-circle' : tone === 'warning' ? 'alert-triangle' : 'info'"
              :size="18"
            />
          </span>
          <h2 class="dialog-title">{{ title }}</h2>
        </header>

        <p class="dialog-message">{{ message }}</p>

        <div v-if="detail" class="dialog-details">
          <button type="button" class="details-toggle" @click="showDetails = !showDetails">
            <AppIcon :name="showDetails ? 'chevron-down' : 'chevron-right'" :size="14" />
            {{ t('common.details') }}
          </button>
          <pre v-if="showDetails" class="details-body" data-selectable>{{ detail }}</pre>
        </div>

        <footer class="dialog-actions">
          <AppButton tone="ghost" @click="emit('cancel')">{{ cancelText || t('common.cancel') }}</AppButton>
          <AppButton
            data-autofocus
            :tone="tone === 'danger' ? 'danger' : 'primary'"
            @click="emit('confirm')"
          >
            {{ confirmText || t('common.confirm') }}
          </AppButton>
        </footer>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.dialog-overlay {
  position: fixed;
  inset: 0;
  z-index: 300;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--space-6);
  background: var(--bg-overlay);
}

.dialog-panel {
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

.dialog-panel:focus-visible {
  box-shadow: var(--shadow-popup), var(--focus-ring);
}

.dialog-header {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}

.dialog-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: var(--radius-md);
  flex-shrink: 0;
}

.dialog-icon.tone-info {
  background: var(--info-subtle);
  color: var(--info);
}

.dialog-icon.tone-warning {
  background: var(--warning-subtle);
  color: var(--warning);
}

.dialog-icon.tone-danger {
  background: var(--error-subtle);
  color: var(--error);
}

.dialog-title {
  font-size: var(--font-size-16);
  font-weight: var(--font-weight-semibold);
  color: var(--text-primary);
}

.dialog-message {
  font-size: var(--font-size-13);
  color: var(--text-secondary);
  /* Localized text wraps; long zh-CN strings must not push the buttons out. */
  overflow-wrap: anywhere;
}

.dialog-details {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.details-toggle {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  font-size: var(--font-size-12);
  color: var(--text-muted);
}

.details-toggle:hover {
  color: var(--text-secondary);
}

.details-body {
  max-height: 140px;
  overflow: auto;
  padding: var(--space-3);
  background: var(--bg-inset);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--font-size-11);
  line-height: var(--line-height-mono);
  color: var(--text-secondary);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.dialog-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-2);
}
</style>
