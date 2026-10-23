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
    <div class="domain-overview">
      <div v-if="allDomains.length === 0" class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
          <path d="M3 3v5h5"/>
          <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/>
          <path d="M16 21h5v-5"/>
          <path d="M12 3v5"/>
          <path d="M12 16v5"/>
          <path d="M3 12h5"/>
          <path d="M16 12h5"/>
        </svg>
        <span>{{ t('config.noDomains') }}</span>
      </div>
      <div v-else class="domain-tags">
        <span
          v-for="domain in allDomains"
          :key="domain"
          class="domain-tag"
        >
          {{ domain }}
        </span>
      </div>
    </div>
    <p class="hint">{{ t('config.overviewHint', { count: allDomains.length }) }}</p>
  </ConfigSection>
</template>

<style scoped>
.domain-overview {
  min-height: 60px;
  display: flex;
  align-items: center;
}

.empty-state {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-muted);
  font-size: 13px;
}

.empty-state svg {
  width: 20px;
  height: 20px;
}

.domain-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.domain-tag {
  padding: 4px 12px;
  background: var(--primary-50);
  color: var(--primary-600);
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}
</style>
