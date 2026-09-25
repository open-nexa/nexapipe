<script setup lang="ts">
/**
 * Tooltip for the collapsed sidebar (D5, §5.11 rule 4).
 *
 * The previous implementation rendered tooltip `div`s as siblings inside the nav and positioned
 * them relative to the 60px rail, so a long label painted over the content area with no clipping
 * container. This one teleports to `<body>` and positions itself from the trigger's own rect in
 * fixed coordinates, so nothing can clip it and no stacking context has to be arranged.
 *
 * Shows on hover *and* focus: the collapsed rail is navigable by keyboard, and a label that only
 * appears for mouse users is not a label.
 */
import { onBeforeUnmount, ref, watch } from 'vue';

const props = withDefaults(
  defineProps<{
    label: string;
    placement?: 'right' | 'top' | 'bottom';
    /** Keeps the tooltip quiet when the caller knows the label is not needed (expanded rail). */
    disabled?: boolean;
  }>(),
  {
    placement: 'right',
    disabled: false,
  },
);

const active = ref(false);
const trigger = ref<HTMLElement | null>(null);
const position = ref({ x: 0, y: 0 });

function updatePosition(): void {
  const element = trigger.value;
  if (!element) return;

  const rect = element.getBoundingClientRect();
  if (props.placement === 'top') {
    position.value = { x: rect.left + rect.width / 2, y: rect.top - 8 };
  } else if (props.placement === 'bottom') {
    position.value = { x: rect.left + rect.width / 2, y: rect.bottom + 8 };
  } else {
    position.value = { x: rect.right + 8, y: rect.top + rect.height / 2 };
  }
}

function show(): void {
  if (props.disabled || !props.label) return;
  updatePosition();
  active.value = true;
}

function hide(): void {
  active.value = false;
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') hide();
}

watch(active, (isActive) => {
  if (isActive) {
    window.addEventListener('scroll', hide, true);
    window.addEventListener('resize', updatePosition);
  } else {
    window.removeEventListener('scroll', hide, true);
    window.removeEventListener('resize', updatePosition);
  }
});

onBeforeUnmount(() => {
  window.removeEventListener('scroll', hide, true);
  window.removeEventListener('resize', updatePosition);
});
</script>

<template>
  <span
    ref="trigger"
    class="app-tooltip-trigger"
    @mouseenter="show"
    @mouseleave="hide"
    @focusin="show"
    @focusout="hide"
    @keydown="onKeydown"
  >
    <slot />
  </span>

  <Teleport to="body">
    <div
      v-if="active"
      class="app-tooltip"
      :class="`placement-${placement}`"
      :style="{ left: `${position.x}px`, top: `${position.y}px` }"
      role="tooltip"
    >
      {{ label }}
    </div>
  </Teleport>
</template>

<style scoped>
.app-tooltip-trigger {
  display: inline-flex;
  min-width: 0;
}

.app-tooltip {
  position: fixed;
  z-index: 200;
  max-width: 240px;
  padding: var(--space-1) var(--space-3);
  background: var(--bg-elevated);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-sm);
  box-shadow: var(--shadow-popup);
  color: var(--text-primary);
  font-size: var(--font-size-12);
  line-height: var(--line-height-normal);
  white-space: nowrap;
  pointer-events: none;
}

.placement-right {
  transform: translateY(-50%);
}

.placement-top {
  transform: translate(-50%, -100%);
}

.placement-bottom {
  transform: translateX(-50%);
}
</style>
