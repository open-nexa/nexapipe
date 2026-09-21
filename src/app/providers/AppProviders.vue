<script setup lang="ts">
/**
 * Cross-cutting overlay host (§3.2).
 *
 * Everything that has to render *above* the shell lives here, once: the confirm dialog and the
 * toast host. Both are driven by module singletons (`useConfirm`, `useToast`) rather than by
 * props threaded down from the root, which is what previously left `ConfirmDialog.vue` rendered
 * but unopenable — nothing ever set its `visible` flag (D2).
 *
 * Theme, locale and platform are not provided here: they are module-level state resolved in
 * `main.ts` before the first paint, so there is nothing left to inject by the time this component
 * mounts.
 */
import AppDialog from '../../components/base/AppDialog.vue';
import ToastHost from '../../components/base/ToastHost.vue';
import { useConfirmState } from '../../composables/useConfirm';

const { request, settle } = useConfirmState();
</script>

<template>
  <slot />

  <AppDialog
    :open="request !== null"
    :title="request?.title ?? ''"
    :message="request?.message ?? ''"
    :tone="request?.tone ?? 'info'"
    :confirm-text="request?.confirmText"
    :cancel-text="request?.cancelText"
    :detail="request?.detail"
    @confirm="settle(true)"
    @cancel="settle(false)"
  />

  <ToastHost />
</template>
