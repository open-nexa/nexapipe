<script setup lang="ts">
import { computed } from "vue";
import ProxyStatusControl from "../components/ProxyStatusControl.vue";
import AppIcon from "../components/base/AppIcon.vue";
import { useConfigStore } from "../composables/useConfigStore";
import type { NodeConfig } from "../types";

const { config, proxyStatus, linkKindFor } = useConfigStore();

/**
 * The icon for one node's current path, or null when nothing is connected to it.
 *
 * Only rendered while the proxy is up: an unconnected node has no link kind, and a stale
 * "direct" badge on a node nothing is talking to is worse than no badge.
 */
function nodeLink(node: NodeConfig) {
  const kind = linkKindFor(node);
  if (!kind) return null;
  const icon =
    kind === "direct" ? "link-direct" : kind === "relay" ? "link-relay" : "link-unknown";
  const label = kind === "direct" ? "Direct" : kind === "relay" ? "Relay" : "Connecting";
  return { kind, icon, label };
}

const connectionLabel = computed(() => {
  if (config.nodes.length === 0) return 'Not configured';
  const hasTicket = config.nodes.some(n => n.connectionType === 'ticket');
  const hasEndpoint = config.nodes.some(n => n.connectionType === 'endpoint_id');
  if (hasTicket && hasEndpoint) return 'Hybrid';
  return hasTicket ? 'Ticket' : 'Endpoint ID';
});

const modeLabel = computed(() => {
  if (!proxyStatus.value.running) return 'Not running';
  return proxyStatus.value.mode === 'tun' ? 'TUN' : 'Local Proxy';
});

const modeColor = computed(() => {
  if (!proxyStatus.value.running) return '#6b7280';
  return proxyStatus.value.mode === 'tun' ? '#16a34a' : '#d97706';
});

const uniqueDomains = computed(() => {
  const domains = new Set<string>();
  config.nodes.forEach(node => {
    node.domains.forEach(d => domains.add(d));
  });
  return domains.size;
});
</script>

<template>
  <div class="dashboard">
    <div class="status-card">
      <ProxyStatusControl
        :config="config"
        @status-change="(status) => useConfigStore().setProxyStatus(status)"
      />
    </div>

    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-icon connection">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ connectionLabel }}</span>
          <span class="stat-label">Connection Method</span>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon mode" :style="{ backgroundColor: modeColor + '15', color: modeColor }">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"/>
            <line x1="12" y1="22" x2="12" y2="15.5"/>
            <line x1="22" y1="8.5" x2="12" y2="15.5"/>
            <line x1="2" y1="8.5" x2="12" y2="15.5"/>
          </svg>
        </div>
        <div class="stat-info">
          <span class="stat-value" :style="{ color: modeColor }">{{ modeLabel }}</span>
          <span class="stat-label">Proxy Mode</span>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon domains">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
          </svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ uniqueDomains }}</span>
          <span class="stat-label">Domain Count</span>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon nodes">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <circle cx="12" cy="12" r="4"/>
            <line x1="12" y1="2" x2="12" y2="6"/>
            <line x1="12" y1="18" x2="12" y2="22"/>
            <line x1="4.93" y1="4.93" x2="7.07" y2="7.07"/>
            <line x1="16.93" y1="16.93" x2="19.07" y2="19.07"/>
            <line x1="2" y1="12" x2="6" y2="12"/>
            <line x1="18" y1="12" x2="22" y2="12"/>
            <line x1="6.93" y1="16.93" x2="4.93" y2="19.07"/>
            <line x1="19.07" y1="7.07" x2="16.93" y2="4.93"/>
          </svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ config.nodes.length }}</span>
          <span class="stat-label">Node Count</span>
        </div>
      </div>
    </div>

    <div class="nodes-section">
      <div class="section-header">
        <h2>Node List</h2>
        <span class="section-count">{{ config.nodes.length }} nodes</span>
      </div>

      <div v-if="config.nodes.length === 0" class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
        <span>No nodes configured</span>
        <span class="empty-hint">Go to the Config page to add nodes</span>
      </div>

      <div v-else class="nodes-list">
        <div 
          v-for="(node, index) in config.nodes" 
          :key="node.id" 
          class="node-item"
        >
          <div class="node-index">{{ index + 1 }}</div>
          <div class="node-info">
            <div class="node-header">
              <span 
                class="type-badge" 
                :class="node.connectionType === 'ticket' ? 'ticket' : 'endpoint'"
              >
                {{ node.connectionType === 'ticket' ? 'Ticket' : 'Endpoint ID' }}
              </span>
              <span class="node-domains-count">{{ node.domains.length }} domains</span>
              <span
                v-if="nodeLink(node)"
                class="link-badge"
                :class="nodeLink(node)!.kind"
                :title="nodeLink(node)!.label"
              >
                <AppIcon :name="nodeLink(node)!.icon" :size="12" />
                <span>{{ nodeLink(node)!.label }}</span>
              </span>
            </div>
            <div class="node-value">
              {{ node.connectionType === 'ticket' ? node.ticket : node.endpointId || 'Not configured' }}
            </div>
          </div>
          <div class="node-status" :class="{ running: proxyStatus.running }">
            <span class="status-dot"></span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.status-card {
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 24px;
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
}

.stats-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.stat-card {
  display: flex;
  align-items: center;
  gap: 14px;
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 18px 20px;
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
  transition: all var(--transition-normal);
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.stat-icon {
  width: 44px;
  height: 44px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.stat-icon svg {
  width: 20px;
  height: 20px;
}

.stat-icon.connection {
  background: var(--primary-100);
  color: var(--primary-600);
}

.stat-icon.mode {
  background: var(--warning-100);
  color: var(--warning-600);
}

.stat-icon.domains {
  background: var(--primary-100);
  color: var(--primary-600);
}

.stat-icon.nodes {
  background: var(--success-100);
  color: var(--success-600);
}

.stat-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.stat-value {
  font-size: 18px;
  font-weight: 700;
  color: var(--text-primary);
}

.stat-label {
  font-size: 12px;
  color: var(--text-muted);
}

.nodes-section {
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 20px;
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
}

.section-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 16px;
}

.section-header h2 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
}

.section-count {
  font-size: 12px;
  color: var(--text-muted);
  padding: 2px 8px;
  background: var(--surface-3);
  border-radius: 10px;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  gap: 10px;
  color: var(--text-muted);
}

.empty-state svg {
  width: 48px;
  height: 48px;
  opacity: 0.5;
}

.empty-state span:first-of-type {
  font-size: 14px;
  font-weight: 500;
}

.empty-hint {
  font-size: 12px;
  opacity: 0.7;
}

.nodes-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.node-item {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px 16px;
  background: var(--surface-2);
  border-radius: var(--radius-md);
  border: 1px solid var(--border-light);
  transition: all var(--transition-normal);
}

.node-item:hover {
  background: var(--surface-3);
  border-color: var(--primary-200);
}

.node-index {
  width: 28px;
  height: 28px;
  border-radius: var(--radius-sm);
  background: var(--surface-3);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-secondary);
  flex-shrink: 0;
}

.node-info {
  flex: 1;
  min-width: 0;
}

.node-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.type-badge {
  font-size: 10px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 8px;
}

.type-badge.ticket {
  background: rgba(139, 92, 246, 0.1);
  color: #8b5cf6;
}

.type-badge.endpoint {
  background: rgba(14, 165, 233, 0.1);
  color: #0ea5e9;
}

.node-domains-count {
  font-size: 11px;
  color: var(--text-muted);
}

/* Direct wins the "good" colour; a relay still works, so it is a warning, not an error. */
.link-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 8px;
}

.link-badge.direct {
  background: rgba(6, 182, 212, 0.12);
  color: #0891b2;
}

.link-badge.relay {
  background: rgba(139, 92, 246, 0.12);
  color: #7c3aed;
}

.link-badge.unknown {
  background: var(--surface-3);
  color: var(--text-muted);
}

.node-value {
  font-size: 13px;
  font-family: 'SF Mono', Monaco, 'Courier New', monospace;
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-status {
  flex-shrink: 0;
}

.node-status .status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--text-muted);
}

.node-status.running .status-dot {
  background: var(--success-500);
  box-shadow: 0 0 6px var(--success-500);
}

@media (max-width: 600px) {
  .stats-row {
    grid-template-columns: 1fr;
  }
  
  .stat-card {
    padding: 16px;
  }
  
  .stat-value {
    font-size: 16px;
  }
  
  .node-item {
    padding: 12px;
  }
}
</style>