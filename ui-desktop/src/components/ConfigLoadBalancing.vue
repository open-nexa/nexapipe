<script setup lang="ts">
/**
 * How the traffic is spread over the nodes that are configured.
 *
 * The choice is the page's own field — it is written to the store with the addresses beside it —
 * so it is handed in and written back through the model.
 *
 * It is two options, so it is a switch rather than a set of cards: the cards were two thirds of
 * a screen for a question with two answers, and the description of the chosen answer now says
 * what that answer does.
 */
import { computed } from "vue";
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

/** What the chosen strategy does, said under the switch rather than on both of its cards. */
const description = computed(() => {
  const option = loadBalancingOptions.find((candidate) => candidate.value === loadBalancing.value);
  return option ? t(option.desc) : "";
});
</script>

<template>
  <ConfigSection :title="t('config.loadBalancing')">
    <div class="strategy-group" role="radiogroup" :aria-label="t('config.loadBalancing')">
      <label
        v-for="option in loadBalancingOptions"
        :key="option.value"
        class="strategy-option"
        :class="{ 'strategy-option--active': loadBalancing === option.value }"
      >
        <input
          v-model="loadBalancing"
          :value="option.value"
          type="radio"
          name="load-balancing"
          class="strategy-radio"
        />
        <span class="strategy-label">{{ t(option.label) }}</span>
      </label>
    </div>
    <p class="hint">{{ description }}</p>
  </ConfigSection>
</template>

<style scoped>
.strategy-group {
  display: inline-flex;
  gap: var(--space-1);
  padding: var(--space-1);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-sm);
  background: var(--bg-inset);
}

.strategy-option {
  position: relative;
  display: inline-flex;
  align-items: center;
  padding: var(--space-1) var(--space-4);
  border-radius: var(--radius-xs);
  color: var(--text-secondary);
  font-size: var(--font-size-13);
  cursor: pointer;
  transition:
    background-color var(--duration-fast) var(--ease-standard),
    color var(--duration-fast) var(--ease-standard);
}

.strategy-option:hover {
  color: var(--text-primary);
}

.strategy-option--active {
  background: var(--bg-card);
  color: var(--text-primary);
  font-weight: var(--font-weight-medium);
  box-shadow: var(--shadow-sm);
}

.strategy-option:focus-within {
  box-shadow: var(--focus-ring);
}

/* The radio is the control; the label is how it is drawn. It stays in the document so the
   keyboard and the screen reader still find it. */
.strategy-radio {
  position: absolute;
  opacity: 0;
  pointer-events: none;
}
</style>
