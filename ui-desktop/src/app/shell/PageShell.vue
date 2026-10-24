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

/*
 * The scroll area itself is unpadded on purpose.
 *
 * A sticky child is pinned to the scrollport's content edge, so padding here stays on the
 * scrolling plane: scrolled content shows through the strip above the pinned row. That is the
 * gap the config tabs used to sit below. The page padding lives on the content instead, and the
 * scrollport's edge is the same edge the row pins to.
 */
.page-shell__body {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
}

/* `border-box` sizing, so the extra width is exactly the padding and the content column stays at
   `--layout-content-max-w`. */
.page-shell__content {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
  width: 100%;
  max-width: calc(var(--layout-content-max-w) + 2 * var(--layout-page-pad-x));
  margin: 0 auto;
  padding: var(--layout-page-pad-y) var(--layout-page-pad-x);
  min-height: 0;
}

.page-shell__body.full .page-shell__content {
  max-width: none;
  gap: 0;
  padding: 0;
  height: 100%;
}
</style>
