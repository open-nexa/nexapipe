<script setup lang="ts">
/**
 * Primary navigation rail (§3.1).
 *
 * Two widths, 200px and 60px, both read from layout tokens. The rail does not own its own
 * collapsed state — it asks `useSidebar`, so the rail, the shell's grid column and the stored
 * preference cannot disagree about the width.
 *
 * The width switch is deliberately *not* animated. Animating a grid track means interpolating
 * `grid-template-columns`, which the WebKitGTK baseline this project targets does not do
 * reliably (§5.11 rule 4). The label cross-fade is the animation instead, and that works
 * everywhere.
 */
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRoute, useRouter } from 'vue-router';
import SideBarFooter from './SideBarFooter.vue';
import SideBarItem from './SideBarItem.vue';
import AppIconButton from '../../components/base/AppIconButton.vue';
import { useSidebar } from '../../composables/useSidebar';

const { t } = useI18n();
const route = useRoute();
const router = useRouter();
const { collapsed, autoCollapsed, toggle } = useSidebar();

/** Order here is the visual order and the tab order — they are not allowed to differ. */
const NAV_ITEMS = [
  { path: '/', icon: 'wifi', labelKey: 'nav.connect' },
  { path: '/config', icon: 'sliders', labelKey: 'nav.config' },
  { path: '/settings', icon: 'settings', labelKey: 'nav.settings' },
  { path: '/logs', icon: 'file-text', labelKey: 'nav.logs' },
] as const;

/**
 * Auto-collapse is not the user's choice, so the control explains the state instead of offering
 * an action that the next resize would immediately undo.
 */
const toggleLabel = computed(() => {
  if (autoCollapsed.value) return t('nav.autoCollapsedHint');
  return collapsed.value ? t('nav.expandSidebar') : t('nav.collapseSidebar');
});
</script>

<template>
  <aside class="side-bar" :class="{ collapsed }">
    <nav class="side-bar__nav" :aria-label="t('nav.primaryNavigation')">
      <SideBarItem
        v-for="item in NAV_ITEMS"
        :key="item.path"
        :icon="item.icon"
        :label="t(item.labelKey)"
        :active="route.path === item.path"
        :collapsed="collapsed"
        @select="router.push(item.path)"
      />
    </nav>

    <div class="side-bar__foot">
      <SideBarFooter :collapsed="collapsed" />

      <div class="side-bar__toggle">
        <AppIconButton
          size="sm"
          :icon="collapsed ? 'chevron-right' : 'chevron-left'"
          :label="toggleLabel"
          :disabled="autoCollapsed"
          @click="toggle"
        />
      </div>
    </div>
  </aside>
</template>

<style scoped>
.side-bar {
  grid-row: 2;
  grid-column: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  min-height: 0;
  overflow: hidden;
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border-subtle);
}

.side-bar__nav {
  flex: 1 1 auto;
  /* The rail scrolls internally only when the nav outgrows it, so the window never gains a second
     scrollbar on a short window (§5.3). */
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
  padding: var(--space-3) var(--space-3) var(--space-2);
}

/* Collapsed: the hover pill spans the full 60px rail, matching the reference layout. */
.side-bar.collapsed .side-bar__nav {
  padding-left: 0;
  padding-right: 0;
}

.side-bar__nav::-webkit-scrollbar {
  width: 6px;
}

.side-bar__foot {
  flex: 0 0 auto;
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  padding: 0 var(--space-2) var(--space-2);
  border-top: 1px solid var(--border-subtle);
}

.side-bar__toggle {
  display: flex;
  justify-content: flex-end;
  padding: 0 var(--space-1);
}

.side-bar.collapsed .side-bar__toggle {
  justify-content: center;
  padding: 0;
}
</style>
