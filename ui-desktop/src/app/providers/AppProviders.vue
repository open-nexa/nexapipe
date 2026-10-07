<script setup lang="ts">
/**
 * Cross-cutting overlay host (§3.2).
 *
 * Everything that has to render *above* the shell lives here, once: the confirm dialog, the toast
 * host and the right-click menu. All three are driven by module singletons (`useConfirm`,
 * `useToast`, `useContextMenu`) rather than by props threaded down from the root, which is what
 * previously left `ConfirmDialog.vue` rendered but unopenable — nothing ever set its `visible`
 * flag (D2).
 *
 * Theme, locale and platform are not provided here: they are module-level state resolved in
 * `main.ts` before the first paint, so there is nothing left to inject by the time this component
 * mounts.
 */
import { onBeforeUnmount, onMounted } from 'vue';
import AppDialog from '../../components/base/AppDialog.vue';
import ContextMenu from '../../components/base/ContextMenu.vue';
import CredentialPasswordDialog from '../../components/CredentialPasswordDialog.vue';
import ToastHost from '../../components/base/ToastHost.vue';
import { useConfirmState } from '../../composables/useConfirm';
import { initQuitGuard } from '../../composables/useQuitGuard';

const { request, settle } = useConfirmState();

/**
 * The quit guard lives here rather than in the shell because this is the component that owns the
 * dialog it asks through, and because nothing it needs depends on the route: whatever page is on
 * screen, leaving has to be offered the same question.
 */
let disposeGuard: (() => void) | null = null;

onMounted(async () => {
  disposeGuard = await initQuitGuard();
});

onBeforeUnmount(() => {
  disposeGuard?.();
  disposeGuard = null;
});
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
    :hide-cancel="request?.hideCancel ?? false"
    @confirm="settle(true)"
    @cancel="settle(false)"
  />

  <!-- Only ever opens on a platform with no prompt of its own to borrow. -->
  <CredentialPasswordDialog />

  <ContextMenu />

  <ToastHost />
</template>
