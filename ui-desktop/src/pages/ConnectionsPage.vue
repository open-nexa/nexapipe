<script setup lang="ts">
/**
 * The connections the proxy has open right now.
 *
 * The Connect page answers "how much has gone through the tunnel"; this answers "what, exactly",
 * which is the question that follows when a total looks wrong. Each row is one connection: where
 * it says it is going, which door it came in by, how long it has been open, and how much it has
 * moved on its own.
 *
 * The poll starts with this page and stops with it — a list nobody is looking at is not worth
 * asking the backend for twice a second.
 */
import { computed, onBeforeUnmount, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';
import AppButton from '../components/base/AppButton.vue';
import AppIcon from '../components/base/AppIcon.vue';
import { useConnectionsStore } from '../stores/connections';
import { useConfigStore } from '../stores/config';
import { useProxyStore } from '../stores/proxy';
import { formatBytes } from '../utils/format';
import type { ActiveFlow } from '../types';

const { t } = useI18n();
const { status } = useProxyStore();
const { config, connectionMask } = useConfigStore();
const {
  flows,
  total,
  cropped,
  reading,
  closing,
  closingNode,
  closeFlow,
  closeNodeFlows,
  startPolling,
  stopPolling,
} = useConnectionsStore();

onMounted(() => {
  void startPolling();
});
onBeforeUnmount(() => {
  stopPolling();
});

/** The rows that have a node to be grouped under, in the order the backend listed them. */
const rows = computed(() => flows.value);

/**
 * Groups rows by the node they reach, so "end everything through this backend" has somewhere to
 * live.
 *
 * A flow whose `connection` is null gets a group of its own keyed by endpoint ID: it still has a
 * backend, this configuration just does not name it, and dropping it would be hiding a
 * connection that is open.
 */
/**
 * What may be printed for the node a group of flows reaches.
 *
 * Deliberately not `flow.connection` and not `flow.endpointId`: when the node was configured with
 * a ticket that string *is* the ticket, and a ticket is a credential. The rule the rest of the
 * shell keeps (see `stores/config.ts`) is that a connection string is only ever shown as the mask
 * Rust produced for it, because a mask the renderer computes from the real value is not one — so
 * the group's key is resolved back to a configured node and the mask is asked for by node id. A
 * name the invite gave the node wins, the same way it does on the other pages.
 *
 * Falls back to a placeholder for a flow reaching a backend this configuration does not name: it
 * has a backend, there is simply no configured node to ask for a mask.
 */
function labelFor(key: string): string {
  const node = config.nodes.find(
    (candidate) =>
      (candidate.connectionType === 'ticket' ? candidate.ticket : candidate.endpointId) === key,
  );
  if (!node) return t('connections.unnamedNode');
  return node.name || connectionMask(node.id) || t('connections.unnamedNode');
}

const groups = computed(() => {
  const byKey = new Map<string, { key: string; label: string; flows: ActiveFlow[] }>();
  for (const flow of rows.value) {
    const key = flow.connection ?? flow.endpointId;
    const entry = byKey.get(key);
    if (entry) {
      entry.flows.push(flow);
    } else {
      byKey.set(key, { key, label: labelFor(key), flows: [flow] });
    }
  }
  return [...byKey.values()];
});

/** "12s", "4m", "2h" — the coarsest unit that still reads as a duration. */
function openFor(seconds: number): string {
  if (seconds < 60) return t('connections.openSeconds', { count: seconds });
  if (seconds < 3600) return t('connections.openMinutes', { count: Math.floor(seconds / 60) });
  return t('connections.openHours', { count: Math.floor(seconds / 3600) });
}

/** What the row shows when the client never said where it was going. */
function targetOf(flow: ActiveFlow): string {
  return flow.target ?? t('connections.unknownTarget');
}

function sourceOf(flow: ActiveFlow): string {
  return flow.source ?? t('connections.unknownSource');
}
</script>

<template>
  <div class="connections">
    <div class="connections__summary">
      <span class="connections__count">
        {{ total === null ? t('connections.unavailable') : t('connections.count', { count: total }) }}
      </span>
      <span v-if="cropped" class="connections__cropped">
        {{
          t('connections.cropped', {
            shown: flows.length,
            total: total ?? flows.length,
          })
        }}
      </span>
      <span class="connections__hint">{{ t('connections.hint') }}</span>
    </div>

    <div v-if="!status.running" class="connections__empty">
      <AppIcon name="wifi" :size="32" />
      <p>{{ t('connections.notRunning') }}</p>
    </div>

    <div v-else-if="rows.length === 0" class="connections__empty">
      <AppIcon name="wifi" :size="32" />
      <p>{{ total === null ? t('connections.unavailable') : t('connections.none') }}</p>
    </div>

    <div v-else class="connections__groups">
      <section v-for="group in groups" :key="group.key" class="connection-group">
        <header class="connection-group__head">
          <div class="connection-group__title">
            <span class="connection-group__label">{{ group.label }}</span>
            <span class="connection-group__badge">{{
              t('connections.count', { count: group.flows.length })
            }}</span>
          </div>
          <AppButton
            size="sm"
            tone="ghost"
            :loading="closingNode === group.key"
            :disabled="closing !== null"
            @click="closeNodeFlows(group.key)"
          >
            {{ t('connections.closeNode') }}
          </AppButton>
        </header>

        <ul class="flow-list">
          <li v-for="flow in group.flows" :key="flow.id" class="flow-row">
            <div class="flow-row__main">
              <span class="flow-row__kind">{{ t(`connections.kind.${flow.kind}`) }}</span>
              <span class="flow-row__target">{{ targetOf(flow) }}</span>

              <span class="flow-row__figures">
                <span class="flow-figure flow-figure--sent">
                  <AppIcon name="arrow-up" :size="11" />
                  {{ formatBytes(flow.sent) }}
                </span>
                <span class="flow-figure flow-figure--received">
                  <AppIcon name="arrow-down" :size="11" />
                  {{ formatBytes(flow.received) }}
                </span>
                <span class="flow-figure flow-figure--age">{{ openFor(flow.openForSecs) }}</span>
              </span>

              <AppButton
                size="sm"
                tone="ghost"
                :loading="closing === flow.id"
                :disabled="closingNode !== null"
                @click="closeFlow(flow.id)"
              >
                {{ t('connections.close') }}
              </AppButton>
            </div>

            <div class="flow-row__meta">
              <span class="flow-row__from">{{ sourceOf(flow) }}</span>
            </div>
          </li>
        </ul>
      </section>
    </div>

    <p v-if="reading && rows.length > 0" class="connections__reading">
      {{ t('connections.reading') }}
    </p>
  </div>
</template>

<style scoped>
.connections {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.connections__summary {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  flex-wrap: wrap;
  font-size: var(--font-size-13);
  color: var(--text-secondary);
}

.connections__count {
  font-size: var(--font-size-16);
  font-weight: 600;
  color: var(--text-primary);
}

.connections__cropped {
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
  background: var(--warning-subtle);
  color: var(--warning-text);
  font-size: var(--font-size-11);
}

.connections__hint {
  color: var(--text-muted);
  font-size: var(--font-size-12);
}

.connections__empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--space-3);
  padding: var(--space-12) var(--space-4);
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  color: var(--text-muted);
  text-align: center;
}

.connections__empty p {
  margin: 0;
  font-size: var(--font-size-14);
}

.connections__groups {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.connection-group {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

.connection-group__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-4);
  background: var(--bg-inset);
  border-bottom: 1px solid var(--border-subtle);
}

.connection-group__title {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  min-width: 0;
}

/* Monospace: this is an endpoint ID or a ticket, and it is read next to another one. */
.connection-group__label {
  font-family: var(--font-mono);
  font-size: var(--font-size-12);
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.connection-group__badge {
  flex-shrink: 0;
  padding: 2px var(--space-2);
  border-radius: var(--radius-full);
  background: var(--bg-hover);
  font-size: var(--font-size-11);
  color: var(--text-secondary);
}

.flow-list {
  display: flex;
  flex-direction: column;
  margin: 0;
  padding: 0;
  list-style: none;
}

.flow-row {
  padding: var(--space-3) var(--space-4);
  border-bottom: 1px solid var(--border-subtle);
}

.flow-row:last-child {
  border-bottom: none;
}

.flow-row__main {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  min-width: 0;
}

.flow-row__kind {
  flex-shrink: 0;
  padding: 2px var(--space-2);
  border-radius: var(--radius-sm);
  background: var(--accent-subtle);
  color: var(--accent-text);
  font-size: var(--font-size-11);
  font-weight: 600;
}

.flow-row__target {
  flex: 1 1 auto;
  min-width: 0;
  font-size: var(--font-size-13);
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.flow-row__figures {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  flex-shrink: 0;
}

/* Monospace and tabular so a poll does not shift the row as digits change width. */
.flow-figure {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  font-family: var(--font-mono);
  font-size: var(--font-size-12);
}

.flow-figure--sent {
  color: var(--warning-text);
}

.flow-figure--received {
  color: var(--accent-text);
}

.flow-figure--age {
  color: var(--text-muted);
}

.flow-row__meta {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  margin-top: var(--space-1);
  font-family: var(--font-mono);
  font-size: var(--font-size-11);
  color: var(--text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.flow-row__from {
  color: var(--text-muted);
}

.connections__reading {
  margin: 0;
  font-size: var(--font-size-12);
  color: var(--text-muted);
}
</style>
