<script setup lang="ts">
/**
 * Minimize / maximize / close, drawn by us (§5.1).
 *
 * Hidden entirely on Linux, which keeps its native decorations in this phase — a second set of
 * buttons inside a native frame is worse than either choice on its own. The maximize button
 * reflects the window's own state, so it does not lie after a double-click on the drag strip.
 */
import { onMounted, onBeforeUnmount, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { getCurrentWindow } from '@tauri-apps/api/window';
import AppIconButton from '../../components/base/AppIconButton.vue';
import { useWindowControls } from '../../composables/useWindowControls';

const { t } = useI18n();
const { minimize, toggleMaximize, close, isMaximized, isWindows } = useWindowControls();

const maximized = ref(false);
let unlisten: (() => void) | undefined;

async function sync(): Promise<void> {
  maximized.value = await isMaximized();
}

onMounted(async () => {
  await sync();
  try {
    unlisten = await getCurrentWindow().onResized(() => {
      void sync();
    });
  } catch (error) {
    // Outside a Tauri window there is nothing to listen to; the button simply starts unmaximized.
    console.debug('[window] resize listener unavailable:', error);
  }
});

onBeforeUnmount(() => {
  unlisten?.();
});
</script>

<template>
  <div class="window-controls">
    <AppIconButton
      icon="window-minimize"
      tone="window"
      :label="t('window.minimize')"
      @click="minimize"
    />
    <AppIconButton
      :icon="maximized ? 'window-restore' : 'window-maximize'"
      tone="window"
      :label="maximized ? t('window.restore') : t('window.maximize')"
      @click="toggleMaximize"
    />
    <AppIconButton
      icon="window-close"
      :tone="isWindows ? 'danger' : 'window'"
      :label="t('window.close')"
      @click="close"
    />
  </div>
</template>

<style scoped>
.window-controls {
  display: flex;
  align-items: stretch;
  align-self: stretch;
  /* Controls must never be part of the drag surface. */
  -webkit-user-select: none;
  user-select: none;
}
</style>
