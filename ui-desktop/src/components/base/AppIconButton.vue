<script setup lang="ts">
/**
 * Icon-only button. `label` is required and becomes the accessible name — an icon with no text
 * is invisible to a screen reader, and this component refuses to render one silently.
 */
import AppIcon from './AppIcon.vue';

withDefaults(
  defineProps<{
    icon: string;
    label: string;
    tone?: 'default' | 'danger' | 'window';
    size?: 'sm' | 'md';
    disabled?: boolean;
    active?: boolean;
  }>(),
  {
    tone: 'default',
    size: 'md',
    disabled: false,
    active: false,
  },
);
</script>

<template>
  <button
    type="button"
    class="icon-button"
    :class="[`tone-${tone}`, `size-${size}`, { active }]"
    :title="label"
    :aria-label="label"
    :aria-pressed="active || undefined"
    :disabled="disabled"
  >
    <AppIcon :name="icon" :size="size === 'sm' ? 14 : 16" />
  </button>
</template>

<style scoped>
.icon-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  transition:
    background-color var(--duration-fast) var(--ease-standard),
    color var(--duration-fast) var(--ease-standard);
}

.icon-button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.icon-button:not(:disabled):focus-visible {
  box-shadow: var(--focus-ring);
}

.size-md {
  width: 30px;
  height: 30px;
}

.size-sm {
  width: 24px;
  height: 24px;
}

.tone-default:not(:disabled):hover,
.tone-default.active {
  background: var(--bg-hover);
  color: var(--text-primary);
}

/* Window buttons keep the platform convention: only close turns red, and only on hover. */
.tone-window {
  border-radius: 0;
  color: var(--text-secondary);
}

.tone-window:not(:disabled):hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.tone-danger:not(:disabled):hover {
  background: var(--error);
  color: var(--text-on-accent);
}
</style>
