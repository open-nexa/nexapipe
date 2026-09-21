<script setup lang="ts">
/**
 * Base switch. The accessible control is a `role="switch"` button with `aria-checked`, so
 * keyboard and screen-reader behaviour comes for free; the visuals are a track and a thumb.
 *
 * The TUN toggle is built on this (§5.12) — labels and disabled hints come from the caller, and
 * the caller is responsible for explaining *why* it is disabled, not just showing it greyed out.
 */
const model = defineModel<boolean>({ required: true });

withDefaults(
  defineProps<{
    disabled?: boolean;
    /** Accessible name, for switches whose visible label lives elsewhere. */
    label?: string;
    size?: 'sm' | 'md';
  }>(),
  {
    disabled: false,
    label: undefined,
    size: 'md',
  },
);
</script>

<template>
  <button
    type="button"
    role="switch"
    class="app-toggle"
    :class="[`size-${size}`, { on: model }]"
    :aria-checked="model"
    :aria-label="label"
    :disabled="disabled"
    @click="model = !model"
  >
    <span class="track"><span class="thumb" /></span>
  </button>
</template>

<style scoped>
.app-toggle {
  display: inline-flex;
  align-items: center;
  padding: 0;
  border-radius: var(--radius-full);
}

.app-toggle:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.app-toggle:not(:disabled):focus-visible {
  box-shadow: var(--focus-ring);
}

.track {
  position: relative;
  display: block;
  background: var(--border-strong);
  border-radius: var(--radius-full);
  transition: background-color var(--duration-fast) var(--ease-standard);
}

.thumb {
  position: absolute;
  top: 50%;
  left: 2px;
  background: var(--neutral-0);
  border-radius: 50%;
  box-shadow: var(--shadow-sm);
  transform: translateY(-50%);
  transition: transform var(--duration-fast) var(--ease-standard);
}

.on .track {
  background: var(--accent);
}

/* -- sizes --------------------------------------------------------------------------------- */

.size-md .track {
  width: 38px;
  height: 22px;
}

.size-md .thumb {
  width: 18px;
  height: 18px;
}

.size-md.on .thumb {
  transform: translateY(-50%) translateX(16px);
}

.size-sm .track {
  width: 32px;
  height: 18px;
}

.size-sm .thumb {
  width: 14px;
  height: 14px;
}

.size-sm.on .thumb {
  transform: translateY(-50%) translateX(14px);
}
</style>
