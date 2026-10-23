<script setup lang="ts">
/**
 * The node list: the servers this machine dials, and the one way a new one arrives.
 *
 * A node comes from an invite and is not added by hand, so the list has an entry point — the
 * invite button — rather than an empty row to fill in.
 */
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import ConfigSection from "./ConfigSection.vue";
import ConfigNodeCard from "./ConfigNodeCard.vue";
import { useConfigStore } from "../stores/config";
import type { NodeConfig } from "../types";

const props = defineProps<{
  /** Every node the store holds. */
  nodes: NodeConfig[];
  /** The two colours a node's badge is drawn in. */
  typeColors: { ticket: string; endpoint: string };
}>();

const emit = defineEmits<{
  /** The invite button was pressed: the page opens the dialog. */
  (e: "import-invite"): void;
  /** A node's device has to be registered again, which takes an invite. */
  (e: "reenroll"): void;
}>();

const { t } = useI18n();
const { removeNode } = useConfigStore();

/**
 * Nodes with no connection string are not shown at all.
 *
 * The target is no longer editable, so such a node can never be completed, and the backend drops
 * it at start-up anyway (`start_proxy` keeps only nodes with a ticket or an endpoint ID). The
 * loader already discards them, so this filter is the second half of that decision: it keeps the
 * page honest about what it renders even if a node ever loses its target.
 */
const visibleNodes = computed(() =>
  props.nodes.filter((node) => node.ticket.trim() !== "" || node.endpointId.trim() !== ""),
);
</script>

<template>
  <ConfigSection :title="t('config.nodeConfiguration')">
    <template #actions>
      <button @click="emit('import-invite')" class="import-invite-btn">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="8" y="3" width="8" height="4" rx="1"/>
          <path d="M16 5h2a2 2 0 0 1 2 2v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2"/>
        </svg>
        {{ t('invite.import') }}
      </button>
    </template>

    <div class="nodes-container">
      <div v-if="visibleNodes.length === 0" class="nodes-empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="8" y="3" width="8" height="4" rx="1"/>
          <path d="M16 5h2a2 2 0 0 1 2 2v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2"/>
        </svg>
        <span class="nodes-empty-title">{{ t('config.noNodes') }}</span>
        <span class="nodes-empty-hint">{{ t('config.noNodesHint') }}</span>
      </div>

      <ConfigNodeCard
        v-for="(node, index) in visibleNodes"
        :key="node.id"
        :node="node"
        :index="index"
        :can-remove="visibleNodes.length > 1"
        :type-color="node.connectionType === 'ticket' ? typeColors.ticket : typeColors.endpoint"
        @remove="removeNode"
        @reenroll="emit('reenroll')"
      />
    </div>
    <p v-if="visibleNodes.length > 1" class="hint">{{ t('config.multipleNodesHint') }}</p>
  </ConfigSection>
</template>

<style scoped>
/* Solid border, no dashed "add" affordance left anywhere: importing an invite is now the only
   way a node appears, so this button is the one entry point rather than one of two. */
.import-invite-btn {
  padding: 6px 12px;
  border: 1px solid var(--primary-400);
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--primary-600);
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 4px;
  transition: all var(--transition-normal);
}

.import-invite-btn:hover {
  background: var(--primary-50);
}

.import-invite-btn svg {
  width: 14px;
  height: 14px;
}

.nodes-container {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* Shown instead of a blank card when there is nothing configured: an empty node row used to be
   the placeholder, and there is no longer any way to fill one in. */
.nodes-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 32px 16px;
  background: var(--surface-2);
  border: 1px dashed var(--border-light);
  border-radius: var(--radius-md);
  color: var(--text-muted);
  text-align: center;
}

.nodes-empty svg {
  width: 28px;
  height: 28px;
  opacity: 0.6;
}

.nodes-empty-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
}

.nodes-empty-hint {
  font-size: 12px;
  opacity: 0.75;
}
</style>
