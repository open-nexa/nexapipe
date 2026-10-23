<script setup lang="ts">
/**
 * The one button that empties the configuration.
 *
 * It is at the bottom of the nodes tab rather than at the bottom of the screen, because a screen
 * with tabs has no bottom any more — and because this is the button that destroys nodes, so it
 * belongs where the nodes are.
 *
 * It clears everything, not just the nodes: the addresses, the relay and the credentials stored
 * on this machine all go with it. The dialog says so before it happens.
 */
import { useI18n } from "vue-i18n";
import AppButton from "./base/AppButton.vue";
import { confirm } from "../composables/useConfirm";

const emit = defineEmits<{
  /** Empty the configuration. */
  (e: "clear-config"): void;
}>();

const { t } = useI18n();

async function requestClear(): Promise<void> {
  const ok = await confirm({
    title: t("config.clearConfigTitle"),
    message: t("config.clearConfigMessage"),
    tone: "danger",
    confirmText: t("config.clearConfig"),
  });
  if (!ok) return;
  emit("clear-config");
}
</script>

<template>
  <section class="danger-zone">
    <div class="danger-zone__text">
      <span class="danger-zone__title">{{ t("config.dangerZone") }}</span>
      <span class="danger-zone__hint">{{ t("config.dangerZoneHint") }}</span>
    </div>
    <AppButton tone="danger" icon="trash" @click="requestClear">
      {{ t("config.clearConfig") }}
    </AppButton>
  </section>
</template>

<style scoped>
.danger-zone {
  display: flex;
  align-items: center;
  gap: var(--space-4);
  padding: var(--space-4) var(--space-5);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-lg);
  background: var(--error-subtle);
}

.danger-zone__text {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
  flex: 1;
  min-width: 0;
}

.danger-zone__title {
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-semibold);
  color: var(--error-text);
}

.danger-zone__hint {
  font-size: var(--font-size-12);
  line-height: var(--line-height-normal);
  color: var(--text-secondary);
}
</style>
