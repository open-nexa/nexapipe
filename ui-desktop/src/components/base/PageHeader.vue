<script setup lang="ts">
/**
 * Page header: title on the left, actions on the right, and a drag surface — matching the
 * reference layout, where the header strip drags the window too (§3.1).
 *
 * The action slot is not part of the drag region; the title and the empty space are.
 */
import { useWindowControls } from '../../composables/useWindowControls';

defineProps<{
  title: string;
}>();

const { handleDragDoubleClick } = useWindowControls();
</script>

<template>
  <header
    class="page-header"
    data-tauri-drag-region="true"
    @dblclick="handleDragDoubleClick"
  >
    <h1 class="page-header__title" data-tauri-drag-region="true">{{ title }}</h1>

    <div class="page-header__spacer" data-tauri-drag-region="true" />

    <div v-if="$slots.actions" class="page-header__actions">
      <slot name="actions" />
    </div>
  </header>
</template>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  gap: var(--space-4);
  flex: 0 0 auto;
  padding: var(--space-4) var(--layout-page-pad-x);
  background: var(--bg-card);
  border-bottom: 1px solid var(--border-subtle);
}

.page-header__title {
  font-size: var(--font-size-18);
  font-weight: var(--font-weight-semibold);
  color: var(--text-primary);
  /* Long zh-CN titles wrap instead of pushing the actions off the bar (§5.5). */
  white-space: normal;
  overflow-wrap: anywhere;
}

.page-header__spacer {
  flex: 1;
  min-width: var(--space-2);
}

.page-header__actions {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  flex-shrink: 0;
}
</style>
