<script setup lang="ts">
/**
 * Sidebar footer: what the app is doing, without being a dashboard.
 *
 * Status dot, mode, truncated node ID, version — the honest minimum. No bandwidth readout: no
 * backend command exposes byte counters, so a traffic widget would be decoration (§1).
 */
import { computed, onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { getVersion } from '@tauri-apps/api/app';
import { useProxyStore } from '../../stores/proxy';

defineProps<{
  collapsed: boolean;
}>();

const { t } = useI18n();
const { status, nodeId } = useProxyStore();

const version = ref('');

const statusLabel = computed(() => {
  if (status.value.running) return t('status.running');
  if (status.value.mode === 'starting') return t('status.starting');
  return t('status.stopped');
});

/** Only meaningful while running: `stopped` is not a forwarding mode. */
const modeLabel = computed(() =>
  status.value.running ? t(`mode.${status.value.mode}`) : '',
);

const shortNodeId = computed(() =>
  nodeId.value ? `${nodeId.value.slice(0, 10)}…` : '',
);

onMounted(async () => {
  try {
    version.value = await getVersion();
  } catch (error) {
    // Outside a Tauri window there is no version to read; the row simply omits it.
    console.debug('[sidebar] app version unavailable:', error);
  }
});
</script>

<template>
  <footer class="side-bar-footer" :class="{ collapsed }">
    <div class="side-bar-footer__status" :class="{ running: status.running }">
      <span class="side-bar-footer__dot" aria-hidden="true" />
      <span v-if="!collapsed" class="side-bar-footer__text">{{ statusLabel }}</span>
    </div>

    <template v-if="!collapsed">
      <div v-if="modeLabel" class="side-bar-footer__row">
        <span class="side-bar-footer__value">{{ modeLabel }}</span>
      </div>
      <div v-if="shortNodeId" class="side-bar-footer__row">
        <span class="side-bar-footer__value mono" :title="nodeId">{{ shortNodeId }}</span>
      </div>
      <div v-if="version" class="side-bar-footer__row muted">
        {{ t('common.version') }} {{ version }}
      </div>
    </template>
  </footer>
</template>

<style scoped>
.side-bar-footer {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
  padding: var(--space-3) var(--space-3) var(--space-1);
}

.side-bar-footer.collapsed {
  align-items: center;
  padding: var(--space-3) 0 var(--space-1);
}

.side-bar-footer__status {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  font-size: var(--font-size-12);
  color: var(--text-secondary);
}

.side-bar-footer__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--text-muted);
  flex-shrink: 0;
}

.side-bar-footer__status.running .side-bar-footer__dot {
  background: var(--success);
  box-shadow: 0 0 6px var(--success);
}

.side-bar-footer__status.running {
  color: var(--success-text);
}

.side-bar-footer__row {
  padding-left: var(--space-4);
  font-size: var(--font-size-11);
  color: var(--text-secondary);
}

.side-bar-footer__row.muted {
  color: var(--text-muted);
}

.side-bar-footer__value {
  overflow-wrap: anywhere;
}

.mono {
  font-family: var(--font-mono);
  line-height: var(--line-height-mono);
}
</style>
