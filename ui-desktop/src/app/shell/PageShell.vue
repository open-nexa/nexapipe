<script setup lang="ts">
/**
 * The page container: header, then exactly one scroll container (§5.3, fixes D4).
 *
 * This is where the old `height: calc(100vh - 180px)` went away. The body is the only element in
 * the app that scrolls, and it scrolls because every ancestor declares `min-height: 0` — without
 * that a flex child refuses to shrink below its content and the page grows instead of scrolling.
 */
import PageHeader from '../../components/base/PageHeader.vue';

withDefaults(
  defineProps<{
    title: string;
    /** Logs mode: the body bleeds to the edges, so the log list can fill the width. */
    full?: boolean;
  }>(),
  {
    full: false,
  },
);
</script>

<template>
  <section class="page-shell">
    <PageHeader :title="title">
      <template v-if="$slots.actions" #actions>
        <slot name="actions" />
      </template>
    </PageHeader>

    <div class="page-shell__body" :class="{ full }">
      <div class="page-shell__content">
        <slot />
      </div>
    </div>
  </section>
</template>

<style scoped>
.page-shell {
  display: flex;
  flex-direction: column;
  flex: 1 1 auto;
  min-height: 0;
  min-width: 0;
  height: 100%;
  background: var(--bg-app);
}

.page-shell__body {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  padding: var(--layout-page-pad-y) var(--layout-page-pad-x);
}

.page-shell__body.full {
  padding: 0;
}

.page-shell__content {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
  width: 100%;
  max-width: var(--layout-content-max-w);
  margin: 0 auto;
  min-height: 0;
}

.page-shell__body.full .page-shell__content {
  max-width: none;
  gap: 0;
  height: 100%;
}
</style>
