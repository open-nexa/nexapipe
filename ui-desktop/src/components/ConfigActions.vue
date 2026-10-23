<script setup lang="ts">
/**
 * The two buttons at the foot of the screen: an example to start from, and a way to clear it all.
 *
 * What they do is the page's business — the example writes four settings, the clear one empties
 * the configuration — so they are reported and acted on there.
 */
import { useI18n } from "vue-i18n";

const emit = defineEmits<{
  /** Fill the settings with an example. */
  (e: "load-example"): void;
  /** Empty the configuration. */
  (e: "clear-config"): void;
}>();

const { t } = useI18n();
</script>

<template>
  <div class="config-actions">
    <button class="btn btn-secondary" @click="emit('load-example')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
      </svg>
      {{ t('config.loadExample') }}
    </button>
    <button class="btn btn-outline" @click="emit('clear-config')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="18" y1="6" x2="6" y2="18"/>
        <line x1="6" y1="6" x2="18" y2="18"/>
      </svg>
      {{ t('config.clearConfig') }}
    </button>
  </div>
</template>

<style scoped>
.config-actions {
  display: flex;
  gap: 10px;
  padding-top: 4px;
}

.btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 10px 16px;
  border: none;
  border-radius: var(--radius-md);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition-normal);
}

.btn svg {
  width: 16px;
  height: 16px;
}

.btn-secondary {
  background: var(--surface-3);
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
}

.btn-secondary:hover {
  background: var(--surface-4);
  border-color: var(--primary-300);
}

.btn-outline {
  background: transparent;
  border: 1.5px solid var(--border-color);
  color: var(--text-secondary);
}

.btn-outline:hover {
  background: var(--surface-2);
  border-color: var(--error-400);
  color: var(--error-600);
}
</style>
