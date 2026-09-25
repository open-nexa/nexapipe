<script setup lang="ts">
/**
 * Base button. Text comes from the caller (already localized); this component only owns size,
 * tone, and the disabled/loading affordances.
 *
  * Sizing rule from §5.5: `min-width`, never a fixed `width` — the English and Chinese labels for
 * differ in length by roughly 2×, and a fixed width truncates one of them.
 */
import AppIcon from './AppIcon.vue';

withDefaults(
  defineProps<{
    tone?: 'primary' | 'secondary' | 'ghost' | 'danger';
    size?: 'sm' | 'md';
    icon?: string;
    iconAfter?: string;
    disabled?: boolean;
    loading?: boolean;
    /** Fills the container instead of hugging its content. */
    block?: boolean;
    type?: 'button' | 'submit';
  }>(),
  {
    tone: 'secondary',
    size: 'md',
    icon: undefined,
    iconAfter: undefined,
    disabled: false,
    loading: false,
    block: false,
    type: 'button',
  },
);
</script>

<template>
  <button
    class="app-button"
    :class="[`tone-${tone}`, `size-${size}`, { block, loading }]"
    :type="type"
    :disabled="disabled || loading"
    :aria-busy="loading || undefined"
  >
    <span v-if="loading" class="spinner" aria-hidden="true" />
    <AppIcon v-else-if="icon" :name="icon" :size="size === 'sm' ? 14 : 16" />
    <span v-if="$slots.default" class="label"><slot /></span>
    <AppIcon v-if="iconAfter && !loading" :name="iconAfter" :size="size === 'sm' ? 14 : 16" />
  </button>
</template>

<style scoped>
.app-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  min-width: 0;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  font-weight: var(--font-weight-medium);
  line-height: var(--line-height-tight);
  white-space: nowrap;
  transition:
    background-color var(--duration-fast) var(--ease-standard),
    border-color var(--duration-fast) var(--ease-standard),
    color var(--duration-fast) var(--ease-standard);
}

.app-button:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.app-button:not(:disabled):focus-visible {
  box-shadow: var(--focus-ring);
}

/* -- sizes --------------------------------------------------------------------------------- */

.size-md {
  height: 34px;
  padding: 0 var(--space-4);
  font-size: var(--font-size-13);
}

.size-sm {
  height: 28px;
  padding: 0 var(--space-3);
  font-size: var(--font-size-12);
}

.block {
  width: 100%;
}

/* -- tones --------------------------------------------------------------------------------- */

.tone-primary {
  background: var(--accent);
  color: var(--text-on-accent);
}

.tone-primary:not(:disabled):hover {
  background: var(--accent-hover);
}

.tone-primary:not(:disabled):active {
  background: var(--accent-active);
}

.tone-secondary {
  background: var(--bg-card);
  border-color: var(--border-default);
  color: var(--text-primary);
}

.tone-secondary:not(:disabled):hover {
  background: var(--bg-hover);
  border-color: var(--border-strong);
}

.tone-ghost {
  background: transparent;
  color: var(--text-secondary);
}

.tone-ghost:not(:disabled):hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.tone-danger {
  background: var(--error);
  color: var(--text-on-accent);
}

.tone-danger:not(:disabled):hover {
  filter: brightness(0.94);
}

/* -- loading ------------------------------------------------------------------------------- */

.spinner {
  width: 14px;
  height: 14px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: var(--radius-full);
  animation: spin 640ms linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
