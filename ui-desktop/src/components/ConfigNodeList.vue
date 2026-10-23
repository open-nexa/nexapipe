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
import AppButton from "./base/AppButton.vue";
import AppIcon from "./base/AppIcon.vue";
import { useConfigStore } from "../stores/config";
import { confirm } from "../composables/useConfirm";
import { useToast } from "../composables/useToast";
import type { NodeConfig } from "../types";

const props = defineProps<{
  /** Every node the store holds. */
  nodes: NodeConfig[];
}>();

const emit = defineEmits<{
  /** The invite button was pressed: the page opens the dialog. */
  (e: "import-invite"): void;
  /** A node's device has to be registered again, which takes an invite. */
  (e: "reenroll"): void;
}>();

const { t } = useI18n();
const { removeNode } = useConfigStore();
const toast = useToast();

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

/** What a node is called in the dialog that removes it. */
function labelFor(node: NodeConfig): string {
  const index = visibleNodes.value.findIndex((candidate) => candidate.id === node.id);
  return node.name || t("config.nodeFallback", { index: index + 1 });
}

/**
 * Takes a node off the list.
 *
 * Every removal is confirmed, and the reason is that a node cannot be typed back in: it comes
 * from an invite, so a removal that was a mis-click costs the user that invite and leaves the
 * machine without the server it was dialing until they have it again. The dialog says what the
 * removal costs, because the list is the only place that cost can be said.
 *
 * The last node is the one that costs the most: without it the proxy has nothing to dial, and
 * it cannot start until another invite has been imported.
 */
async function requestRemove(node: NodeConfig): Promise<void> {
  const isLast = visibleNodes.value.length === 1;
  // The label is read while the node is still on the list: an unnamed node's
  // fallback carries its position in the list, and once the node is gone there
  // is no position to carry.
  const label = labelFor(node);
  const ok = await confirm({
    title: isLast ? t("config.removeLastNodeTitle") : t("config.removeNodeTitle"),
    message: isLast
      ? t("config.removeLastNodeMessage")
      : t("config.removeNodeMessage", { name: label }),
    tone: "danger",
    confirmText: t("config.removeNode"),
  });
  if (!ok) return;

  removeNode(node.id);
  toast.success(t("config.nodeRemoved", { name: label }));
}
</script>

<template>
  <ConfigSection :title="t('config.nodeConfiguration')">
    <template #actions>
      <AppButton size="sm" tone="secondary" icon="clipboard" @click="emit('import-invite')">
        {{ t("invite.import") }}
      </AppButton>
    </template>

    <div class="nodes-container">
      <div v-if="visibleNodes.length === 0" class="nodes-empty">
        <AppIcon name="clipboard" :size="28" />
        <span class="nodes-empty__title">{{ t("config.noNodes") }}</span>
        <span class="nodes-empty__hint">{{ t("config.noNodesHint") }}</span>
        <AppButton tone="primary" icon="clipboard" @click="emit('import-invite')">
          {{ t("invite.import") }}
        </AppButton>
      </div>

      <ConfigNodeCard
        v-for="(node, index) in visibleNodes"
        :key="node.id"
        :node="node"
        :index="index"
        @remove="requestRemove"
        @reenroll="emit('reenroll')"
      />
    </div>

    <p v-if="visibleNodes.length > 1" class="hint">{{ t("config.multipleNodesHint") }}</p>
  </ConfigSection>
</template>

<style scoped>
.nodes-container {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

/*
 * Shown instead of a blank card when there is nothing configured.
 *
 * It carries the way in as well as the explanation: an empty state that only says "there is
 * nothing here" leaves the reader to find the button that changes that.
 */
.nodes-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-10) var(--space-4);
  background: var(--bg-inset);
  border: 1px dashed var(--border-default);
  border-radius: var(--radius-md);
  color: var(--text-muted);
  text-align: center;
}

.nodes-empty__title {
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-medium);
  color: var(--text-secondary);
}

.nodes-empty__hint {
  font-size: var(--font-size-12);
  margin-bottom: var(--space-2);
}
</style>
