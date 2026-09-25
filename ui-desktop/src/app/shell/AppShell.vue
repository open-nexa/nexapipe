<script setup lang="ts">
/**
 * The application grid (§5.3): title bar across the top, rail and main column below.
 *
 * This component owns two things and nothing else: the CSS grid, and the one
 * `ResizeObserver` that feeds the real window width to `useSidebar`. A media query would have been
 * shorter, but the sidebar's breakpoint has to agree with a *JavaScript* feed so the collapsed
 * state is the same value the rest of the app reads, and container queries are out on the
 * WebKitGTK baseline (§5.11 rule 4).
 *
 * The `PageShell` here is temporary (§7, Phase 1): the four pages are still their pre-refactor
 * selves and do not render their own headers, so the shell supplies one from the route's
 * `meta.titleKey`. Phase 3 moves `PageShell` into each page — at which point the Logs page can
 * declare `full` and each page can own its header actions — and this wrapper goes away with it.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRoute } from 'vue-router';
import TitleBar from './TitleBar.vue';
import SideBar from './SideBar.vue';
import PageShell from './PageShell.vue';
import { useSidebar } from '../../composables/useSidebar';

const { t } = useI18n();
const route = useRoute();
const { collapsed, syncViewportWidth } = useSidebar();

const root = ref<HTMLElement | null>(null);
let observer: ResizeObserver | null = null;

onMounted(() => {
  // A WebView without `ResizeObserver` still gets a correct first value — it just does not track
  // resizes, which degrades to "the rail keeps the width it had at load".
  if (typeof ResizeObserver === 'undefined') {
    syncViewportWidth(window.innerWidth);
    return;
  }

  observer = new ResizeObserver((entries) => {
    const entry = entries[0];
    if (entry) syncViewportWidth(entry.contentRect.width);
  });
  if (root.value) observer.observe(root.value);
});

onBeforeUnmount(() => {
  observer?.disconnect();
  observer = null;
});

/**
 * The nav labels double as page titles: same locale keys, so the header and the rail cannot drift
 * apart in either language.
 */
const title = computed(() => {
  const key = route.meta.titleKey;
  return typeof key === 'string' ? t(key) : t('app.name');
});
</script>

<template>
  <div ref="root" class="app-shell" :class="{ collapsed }">
    <TitleBar />

    <SideBar />

    <main class="app-shell__main">
      <PageShell :title="title">
        <RouterView v-slot="{ Component }">
          <Transition name="page" mode="out-in">
            <component :is="Component" />
          </Transition>
        </RouterView>
      </PageShell>
    </main>
  </div>
</template>

<style scoped>
.app-shell {
  display: grid;
  grid-template-columns: var(--layout-sidebar-w) minmax(0, 1fr);
  grid-template-rows: var(--layout-titlebar-h) minmax(0, 1fr);
  height: 100vh;
  overflow: hidden;
  background: var(--bg-app);
}

.app-shell.collapsed {
  grid-template-columns: var(--layout-sidebar-w-collapsed) minmax(0, 1fr);
}

.app-shell__main {
  grid-row: 2;
  grid-column: 2;
  display: flex;
  flex-direction: column;
  /* Both are load-bearing: without `min-height: 0` the page body refuses to shrink and the window
     grows a scrollbar instead of the page (§5.3). */
  min-width: 0;
  min-height: 0;
}
</style>
