<script setup lang="ts">
/**
 * Custom title bar (§5.1, §5.2).
 *
 * A drag region with the product name on the left and, where the window is frameless, the
 * window controls on the right. On macOS the native traffic lights stay over it, so the leading
 * side reserves their width — the difference between "native window" and "content hidden behind
 * a red dot".
 *
 * Double-click to maximize is wired here rather than relied upon from
 * `data-tauri-drag-region`, which does not provide it on every platform.
 */
import { useI18n } from 'vue-i18n';
import WindowControls from './WindowControls.vue';
import AppIcon from '../../components/base/AppIcon.vue';
import { useWindowControls } from '../../composables/useWindowControls';

const { t } = useI18n();
const { isMacos, isFrameless, handleDragDoubleClick } = useWindowControls();
</script>

<template>
  <header
    class="title-bar"
    :class="{ macos: isMacos }"
    data-tauri-drag-region="true"
    @dblclick="handleDragDoubleClick"
  >
    <div class="title-bar__leading" data-tauri-drag-region="true" aria-hidden="true" />

    <div class="title-bar__brand" data-tauri-drag-region="true">
      <AppIcon name="brand" :size="16" />
      <span class="title-bar__name" data-tauri-drag-region="true">{{ t('app.name') }}</span>
    </div>

    <!-- The reliable full-height drag surface: an empty, non-interactive span between the brand
         and the controls. Buttons and inputs never inherit dragging because Tauri matches the
         attribute on the exact target element (§5.2). -->
    <div class="title-bar__spacer" data-tauri-drag-region="true" />

    <WindowControls v-if="isFrameless" />
  </header>
</template>

<style scoped>
.title-bar {
  grid-column: 1 / -1;
  display: flex;
  align-items: stretch;
  height: var(--layout-titlebar-h);
  background: var(--bg-sidebar);
  border-bottom: 1px solid var(--border-subtle);
  flex-shrink: 0;
}

.title-bar__leading {
  width: 0;
  flex-shrink: 0;
}

/* macOS keeps its traffic lights over our bar; reserve their width so nothing hides behind. */
.title-bar.macos .title-bar__leading {
  width: var(--layout-macos-traffic-lights-w);
}

.title-bar__brand {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: 0 var(--space-3);
  color: var(--nav-brand);
}

.title-bar__name {
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-medium);
  color: var(--text-secondary);
  white-space: nowrap;
}

.title-bar__spacer {
  flex: 1;
  min-width: 0;
}
</style>
