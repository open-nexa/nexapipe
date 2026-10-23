<script setup lang="ts">
/**
 * How the traffic is spread over the nodes that are configured.
 *
 * The choice is the page's own field — it is written to the store with the addresses beside it —
 * so it is handed in and written back through the model.
 */
import { useI18n } from "vue-i18n";
import ConfigSection from "./ConfigSection.vue";
import type { LoadBalancingStrategy } from "../types";

const loadBalancing = defineModel<LoadBalancingStrategy>("loadBalancing", { required: true });

const { t } = useI18n();

/** Label and description are i18n keys, not literals — they are resolved where they render. */
const loadBalancingOptions: { value: LoadBalancingStrategy; label: string; desc: string }[] = [
  { value: "round_robin", label: "config.strategyRoundRobin", desc: "config.strategyRoundRobinDesc" },
  { value: "random", label: "config.strategyRandom", desc: "config.strategyRandomDesc" },
];
</script>

<template>
  <ConfigSection :title="t('config.loadBalancing')">
    <div class="load-balancing-options">
      <label
        v-for="option in loadBalancingOptions"
        :key="option.value"
        class="strategy-option"
        :class="{ active: loadBalancing === option.value }"
      >
        <input
          v-model="loadBalancing"
          :value="option.value"
          type="radio"
          class="strategy-radio"
        />
        <div class="strategy-content">
          <span class="strategy-label">{{ t(option.label) }}</span>
          <span class="strategy-desc">{{ t(option.desc) }}</span>
        </div>
      </label>
    </div>
  </ConfigSection>
</template>

<style scoped>
.load-balancing-options {
  display: flex;
  gap: 12px;
}

.strategy-option {
  flex: 1;
  padding: 14px 16px;
  border: 2px solid var(--border-color);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all var(--transition-normal);
  background: var(--surface-1);
}

.strategy-option:hover {
  border-color: var(--primary-300);
}

.strategy-option.active {
  border-color: var(--primary-500);
  background: var(--primary-50);
}

.strategy-radio {
  display: none;
}

.strategy-content {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.strategy-label {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}

.strategy-desc {
  font-size: 12px;
  color: var(--text-muted);
}

@media (max-width: 600px) {
  .load-balancing-options {
    flex-direction: column;
  }
}
</style>
