<script setup lang="ts">
/**
 * Every domain the configured nodes answer for, in one place.
 *
 * The list is what the nodes hold, gathered: a domain that is proxied is proxied because some
 * node says so, and this is where that is said at a glance rather than node by node.
 */
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import ConfigSection from "./ConfigSection.vue";
import AppIcon from "./base/AppIcon.vue";
import type { NodeConfig } from "../types";

const props = defineProps<{
  /** Every node the store holds. */
  nodes: NodeConfig[];
}>();

const { t } = useI18n();

const allDomains = computed(() => {
  const domains = new Set<string>();
  props.nodes.forEach((node) => {
    node.domains.forEach((d) => domains.add(d));
  });
  return Array.from(domains);
});
</script>

<template>
  <ConfigSection :title="t('config.domainOverview')">
    <div v-if="allDomains.length === 0" class="overview-empty">
      <AppIcon name="globe" :size="20" />
      <span>{{ t("config.noDomains") }}</span>
    </div>

    <div v-else class="domain-tags">
      <span v-for="domain in allDomains" :key="domain" class="domain-tag">{{ domain }}</span>
    </div>

    <p class="hint">{{ t("config.overviewHint", { count: allDomains.length }) }}</p>
  </ConfigSection>
</template>

<style scoped>
.overview-empty {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-4) 0;
  color: var(--text-muted);
  font-size: var(--font-size-13);
}

.domain-tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}

.domain-tag {
  padding: var(--space-1) var(--space-3);
  background: var(--accent-subtle);
  color: var(--accent-text);
  border-radius: var(--radius-full);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-medium);
}
</style>
