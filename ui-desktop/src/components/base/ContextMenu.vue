<script setup lang="ts">
/**
 * The application's right-click menu (docs/ui-refactor-plan.md §5.11).
 *
 * Rendered from the `useContextMenu` singleton and teleported to `<body>`, like `AppTooltip`: the
 * shell is a `height: 100vh` grid with `overflow: hidden`, so anything positioned inside it can
 * be clipped, and arranging a stacking context for every possible host is a losing game.
 *
 * Two details decide whether the clipboard items work at all:
 *
 *   1. The items use `@mousedown.prevent`. A button takes focus on mousedown, which would move the
 *      caret out of the field the user right-clicked — and then paste would have nowhere to go.
 *      Keeping focus where it was is what lets `execCommand` operate on the right element.
 *   2. Keyboard navigation listens on `window` rather than by focusing the panel, for the same
 *      reason: focus stays in the field, so `Escape` closes the menu without disturbing it.
 */
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useContextMenu, type ContextMenuAction, type ContextMenuEntry } from '../../composables/useContextMenu';

const { menu, close, handleContextMenuEvent } = useContextMenu();

/** Keeps the panel off the window edge; the WebView has no chrome to clip against. */
const EDGE_MARGIN = 4;

const panel = ref<HTMLElement | null>(null);
const position = ref({ x: 0, y: 0 });
const activeId = ref<string | null>(null);

const enabledIds = computed(() =>
  menu.value.entries
    .filter((entry): entry is ContextMenuAction => entry.kind === 'action' && !entry.disabled)
    .map((entry) => entry.id),
);

const activeDescendant = computed(() => (activeId.value ? `context-menu-${activeId.value}` : undefined));

function clampToViewport(): void {
  const element = panel.value;
  if (!element) return;

  const { offsetWidth, offsetHeight } = element;
  const maxX = Math.max(EDGE_MARGIN, window.innerWidth - offsetWidth - EDGE_MARGIN);
  const maxY = Math.max(EDGE_MARGIN, window.innerHeight - offsetHeight - EDGE_MARGIN);

  position.value = {
    x: Math.min(Math.max(EDGE_MARGIN, position.value.x), maxX),
    y: Math.min(Math.max(EDGE_MARGIN, position.value.y), maxY),
  };
}

function run(entry: ContextMenuEntry): void {
  if (entry.kind !== 'action' || entry.disabled) return;
  // Close first: the panel is gone before the action runs, so a slow clipboard round-trip cannot
  // leave a menu hanging over the result.
  close();
  entry.run();
}

function hover(entry: ContextMenuEntry): void {
  if (entry.kind === 'action' && !entry.disabled) activeId.value = entry.id;
}

function onKeydown(event: KeyboardEvent): void {
  if (!menu.value.open) return;

  if (event.key === 'Escape') {
    event.preventDefault();
    close();
    return;
  }

  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault();
    const ids = enabledIds.value;
    if (ids.length === 0) return;

    const current = activeId.value ? ids.indexOf(activeId.value) : -1;
    if (current === -1) {
      activeId.value = event.key === 'ArrowDown' ? ids[0] : ids[ids.length - 1];
      return;
    }
    const step = event.key === 'ArrowDown' ? 1 : -1;
    activeId.value = ids[(current + step + ids.length) % ids.length];
    return;
  }

  if (event.key === 'Enter' && activeId.value) {
    event.preventDefault();
    const entry = menu.value.entries.find((item) => item.id === activeId.value);
    if (entry) run(entry);
  }
}

function onPointerDown(event: PointerEvent): void {
  if (panel.value?.contains(event.target as Node)) return;
  close();
}

function attach(): void {
  window.addEventListener('pointerdown', onPointerDown, true);
  window.addEventListener('keydown', onKeydown, true);
  window.addEventListener('scroll', close, true);
  window.addEventListener('resize', close);
  window.addEventListener('blur', close);
}

function detach(): void {
  window.removeEventListener('pointerdown', onPointerDown, true);
  window.removeEventListener('keydown', onKeydown, true);
  window.removeEventListener('scroll', close, true);
  window.removeEventListener('resize', close);
  window.removeEventListener('blur', close);
}

watch(menu, (state) => {
  activeId.value = null;

  if (!state.open) {
    detach();
    return;
  }

  position.value = { x: state.x, y: state.y };
  attach();
  // Measuring before the browser paints: the DOM update and this callback share one flush, so
  // the clamped position is the first thing drawn.
  void nextTick(clampToViewport);
});

onMounted(() => {
  window.addEventListener('contextmenu', handleContextMenuEvent);
});

onBeforeUnmount(() => {
  window.removeEventListener('contextmenu', handleContextMenuEvent);
  detach();
});
</script>

<template>
  <Teleport to="body">
    <Transition name="context-menu">
      <div
        v-if="menu.open"
        ref="panel"
        class="context-menu"
        role="menu"
        :aria-activedescendant="activeDescendant"
        :style="{ left: `${position.x}px`, top: `${position.y}px` }"
        @contextmenu.prevent
      >
        <template v-for="entry in menu.entries" :key="entry.id">
          <div v-if="entry.kind === 'separator'" class="context-menu__separator" role="separator" />

          <button
            v-else
            :id="`context-menu-${entry.id}`"
            type="button"
            class="context-menu__item"
            role="menuitem"
            :disabled="entry.disabled"
            :data-active="activeId === entry.id ? '' : undefined"
            @mousedown.prevent
            @mouseenter="hover(entry)"
            @click="run(entry)"
          >
            {{ entry.label }}
          </button>
        </template>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.context-menu {
  position: fixed;
  z-index: 500;
  min-width: 168px;
  max-width: 280px;
  max-height: calc(100vh - 2 * var(--space-1));
  overflow-y: auto;
  padding: var(--space-1);
  background: var(--bg-elevated);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-popup);
  transform-origin: top left;
}

.context-menu__item {
  display: block;
  width: 100%;
  padding: var(--space-2) var(--space-3);
  border-radius: var(--radius-sm);
  color: var(--text-primary);
  font-size: var(--font-size-13);
  line-height: var(--line-height-tight);
  text-align: left;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.context-menu__item:hover:not(:disabled),
.context-menu__item[data-active] {
  background: var(--bg-hover);
}

.context-menu__item:disabled {
  color: var(--text-muted);
  cursor: default;
}

.context-menu__separator {
  height: 1px;
  margin: var(--space-1) var(--space-2);
  background: var(--border-subtle);
}

/* -- transitions ---------------------------------------------------------------------------- */

.context-menu-enter-active,
.context-menu-leave-active {
  transition:
    opacity var(--duration-fast) var(--ease-out),
    transform var(--duration-fast) var(--ease-out);
}

.context-menu-enter-from,
.context-menu-leave-to {
  opacity: 0;
  transform: scale(0.97);
}
</style>
