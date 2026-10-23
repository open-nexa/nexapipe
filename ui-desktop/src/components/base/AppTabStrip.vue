<script setup lang="ts">
/**
 * The tab strip: which part of a page is on screen.
 *
 * A controlled strip — the page owns which tab is active, because the page is
 * what the tabs are about. The strip owns only the keyboard: a tablist is one
 * tab stop, and the arrow keys move between the tabs inside it, the way the
 * platform's own tab strips behave.
 */
import { ref } from 'vue';

const props = withDefaults(
  defineProps<{
    /** The tabs, in the order they are shown. */
    tabs: { id: string; label: string }[];
    /** The accessible name of the group. */
    label?: string;
    /** Prefix for the generated element ids, so a panel can name the tab that opened it. */
    idPrefix?: string;
  }>(),
  {
    label: undefined,
    idPrefix: undefined,
  },
);

/** The active tab's id. */
const active = defineModel<string>({ required: true });

const buttons = ref<(HTMLButtonElement | null)[]>([]);

function setButton(element: Element | null, index: number): void {
  buttons.value[index] = element as HTMLButtonElement | null;
}

/**
 * Moves between the tabs with the keyboard.
 *
 * Home and End go to the ends of the strip, and the arrows wrap around: a
 * tablist is a cycle rather than a list, and a strip where the right arrow
 * stops at the last tab reads as a broken control.
 */
function onKeydown(event: KeyboardEvent): void {
  const count = props.tabs.length;
  if (count === 0) return;

  const index = props.tabs.findIndex((tab) => tab.id === active.value);
  let next = -1;

  switch (event.key) {
    case 'ArrowRight':
      next = (index + 1) % count;
      break;
    case 'ArrowLeft':
      next = (index - 1 + count) % count;
      break;
    case 'Home':
      next = 0;
      break;
    case 'End':
      next = count - 1;
      break;
    default:
      return;
  }

  event.preventDefault();
  const tab = props.tabs[next];
  if (!tab) return;
  active.value = tab.id;
  buttons.value[next]?.focus();
}
</script>

<template>
  <div class="tab-strip" role="tablist" :aria-label="label" @keydown="onKeydown">
    <button
      v-for="(tab, index) in tabs"
      :key="tab.id"
      :ref="(element) => setButton(element as Element | null, index)"
      type="button"
      role="tab"
      class="tab-strip__tab"
      :class="{ 'tab-strip__tab--active': tab.id === active }"
      :id="idPrefix ? `${idPrefix}-tab-${tab.id}` : undefined"
      :aria-selected="tab.id === active"
      :aria-controls="idPrefix ? `${idPrefix}-panel-${tab.id}` : undefined"
      :tabindex="tab.id === active ? 0 : -1"
      @click="active = tab.id"
    >
      {{ tab.label }}
    </button>
  </div>
</template>

<style scoped>
.tab-strip {
  display: flex;
  align-items: center;
  gap: var(--space-1);
}

.tab-strip__tab {
  padding: var(--space-2) var(--space-3);
  border: none;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-secondary);
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  white-space: nowrap;
  transition:
    background-color var(--duration-fast) var(--ease-standard),
    color var(--duration-fast) var(--ease-standard);
}

.tab-strip__tab:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.tab-strip__tab--active {
  background: var(--accent-subtle);
  color: var(--accent-text);
}

.tab-strip__tab:focus-visible {
  box-shadow: var(--focus-ring);
}
</style>
