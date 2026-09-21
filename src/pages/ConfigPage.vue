<script setup lang="ts">
import { ref, watch, computed } from "vue";
import type { ConnectionType, LoadBalancingStrategy } from "../types";
import { useConfigStore } from "../composables/useConfigStore";

const { config, updateConfig, addNode, removeNode, updateConnectionString, updateNodeDomains } = useConfigStore();

const localAddr = ref(config.localAddr);
const dnsAddr = ref(config.dnsAddr);
const upstreamDns = ref(config.upstreamDns);
const loadBalancing = ref<LoadBalancingStrategy>(config.loadBalancing);

const nodeDomainsText = ref<Map<string, string>>(new Map());

config.nodes.forEach(node => {
  nodeDomainsText.value.set(node.id, node.domains.join("\n"));
});

const loadBalancingOptions: { value: LoadBalancingStrategy; label: string; desc: string }[] = [
  { value: 'round_robin', label: 'Round Robin', desc: 'Distribute requests to each node in turn' },
  { value: 'random', label: 'Random', desc: 'Pick a node at random' },
];

function getNodeLabel(index: number): string {
  return `Node ${index + 1}`;
}

function getNodeTypeLabel(type: ConnectionType): string {
  return type === 'ticket' ? 'Ticket' : 'Endpoint ID';
}

function getNodeTypeColor(type: ConnectionType): string {
  return type === 'ticket' ? '#8b5cf6' : '#0ea5e9';
}

function getNodeDomainsText(nodeId: string): string {
  return nodeDomainsText.value.get(nodeId) || "";
}

function updateNodeDomainsText(nodeId: string, text: string) {
  nodeDomainsText.value.set(nodeId, text);
  const domains = text
    .split("\n")
    .map(d => d.trim())
    .filter(d => d.length > 0);
  updateNodeDomains(nodeId, domains);
}

function handleUpdate() {
  updateConfig({
    localAddr: localAddr.value,
    dnsAddr: dnsAddr.value,
    upstreamDns: upstreamDns.value,
    loadBalancing: loadBalancing.value,
  });
}

const allDomains = computed(() => {
  const domains = new Set<string>();
  config.nodes.forEach(node => {
    node.domains.forEach(d => domains.add(d));
  });
  return Array.from(domains);
});

watch(() => config, (newConfig) => {
  localAddr.value = newConfig.localAddr;
  dnsAddr.value = newConfig.dnsAddr;
  upstreamDns.value = newConfig.upstreamDns;
  loadBalancing.value = newConfig.loadBalancing;
}, { deep: true });

watch([localAddr, dnsAddr, upstreamDns, loadBalancing], handleUpdate);

function loadExampleConfig() {
  localAddr.value = "127.0.0.1:8080";
  dnsAddr.value = "10.0.0.1:53";
  upstreamDns.value = "223.5.5.5:53";
  loadBalancing.value = "round_robin";
  
  if (config.nodes.length === 0) {
    addNode({ connectionType: 'ticket', ticket: "", domains: ["example.com", "api.example.com"] });
  }
}

function clearConfig() {
  localAddr.value = "127.0.0.1:8080";
  dnsAddr.value = "10.0.0.1:53";
  upstreamDns.value = "223.5.5.5:53";
  loadBalancing.value = "round_robin";
}
</script>

<template>
  <div class="config-page">
    <div class="config-section">
      <div class="card-header">
        <h2>Node Configuration</h2>
        <div class="card-header-decoration"></div>
        <button @click="addNode()" class="add-node-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          Add Node
        </button>
      </div>
      
      <div class="nodes-container">
        <div 
          v-for="(node, index) in config.nodes" 
          :key="node.id" 
          class="node-card"
        >
          <div class="node-header">
            <span class="node-label">{{ getNodeLabel(index) }}</span>
            <span 
              class="type-badge" 
              :style="{ backgroundColor: getNodeTypeColor(node.connectionType) + '15', color: getNodeTypeColor(node.connectionType), borderColor: getNodeTypeColor(node.connectionType) + '30' }"
            >
              <svg v-if="node.connectionType === 'ticket'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                <path d="M7 16V3h7v13"/>
                <path d="M17 16v-5a2 2 0 0 0-2-2H5"/>
              </svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              {{ getNodeTypeLabel(node.connectionType) }}
            </span>
            <button 
              v-if="config.nodes.length > 1"
              @click="removeNode(node.id)" 
              class="remove-node-btn"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="18" y1="6" x2="6" y2="18"/>
                <line x1="6" y1="6" x2="18" y2="18"/>
              </svg>
            </button>
          </div>
          
          <div class="connection-input-wrapper">
            <div class="input-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10 13a5 5 0 0 1 5-5m0 0a5 5 0 0 1 5 5m-5-5v10"/>
              </svg>
            </div>
            <input
              :value="node.connectionType === 'ticket' ? node.ticket : node.endpointId"
              @input="updateConnectionString(node.id, ($event.target as HTMLInputElement).value)"
              type="text"
              :placeholder="node.connectionType === 'ticket' ? 'Enter Ticket' : 'Enter Endpoint ID'"
              class="form-input"
            />
          </div>
          
          <div class="node-domains-section">
            <label class="form-label">
              <span class="label-text">Proxied Domain List</span>
              <span class="domain-count">{{ node.domains.length }} domains</span>
            </label>
            <div class="textarea-wrapper">
              <div class="input-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                  <polyline points="14 2 14 8 20 8"/>
                  <line x1="16" y1="13" x2="8" y2="13"/>
                  <line x1="16" y1="17" x2="8" y2="17"/>
                </svg>
              </div>
              <textarea
                :value="getNodeDomainsText(node.id)"
                @input="updateNodeDomainsText(node.id, ($event.target as HTMLTextAreaElement).value)"
                rows="2"
                placeholder="One domain per line"
                class="form-textarea"
              ></textarea>
            </div>
          </div>
        </div>
      </div>
      <p class="hint">Multiple nodes are supported; the same domain can be configured on several nodes for load balancing</p>
    </div>

    <div class="config-section">
      <div class="card-header">
        <h2>Domain Overview</h2>
        <div class="card-header-decoration"></div>
      </div>
      
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
          <span>No domains configured</span>
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
      <p class="hint">Shows the unique domains configured across all nodes, {{ allDomains.length }} in total</p>
    </div>

    <div class="config-section">
      <div class="card-header">
        <h2>Network Configuration</h2>
        <div class="card-header-decoration"></div>
      </div>
      
      <div class="form-grid">
        <div class="form-group">
          <label for="localAddr" class="form-label">Local Proxy Address</label>
          <div class="input-wrapper">
            <div class="input-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2a10 10 0 0 0-10 10c0 4.42 2.87 8.17 6.84 9.49"/>
                <path d="M12 2a10 10 0 0 1 10 10c0 4.42-2.87 8.17-6.84 9.49"/>
                <path d="M12 12l4 4"/>
                <path d="M12 12l-4 4"/>
                <path d="M12 12l4-4"/>
                <path d="M12 12l-4-4"/>
              </svg>
            </div>
            <input
              id="localAddr"
              v-model="localAddr"
              type="text"
              placeholder="127.0.0.1:8080"
              class="form-input"
            />
          </div>
        </div>

        <div class="form-group">
          <label for="dnsAddr" class="form-label">DNS Listen Address</label>
          <div class="input-wrapper">
            <div class="input-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <polyline points="12 6 12 12 16 14"/>
              </svg>
            </div>
            <input
              id="dnsAddr"
              v-model="dnsAddr"
              type="text"
              placeholder="10.0.0.1:53"
              class="form-input"
            />
          </div>
        </div>

        <div class="form-group">
          <label for="upstreamDns" class="form-label">Upstream DNS</label>
          <div class="input-wrapper">
            <div class="input-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
              </svg>
            </div>
            <input
              id="upstreamDns"
              v-model="upstreamDns"
              type="text"
              placeholder="223.5.5.5:53"
              class="form-input"
            />
          </div>
        </div>
      </div>
    </div>

    <div class="config-section">
      <div class="card-header">
        <h2>Load Balancing Configuration</h2>
        <div class="card-header-decoration"></div>
      </div>
      
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
            <span class="strategy-label">{{ option.label }}</span>
            <span class="strategy-desc">{{ option.desc }}</span>
          </div>
        </label>
      </div>
    </div>

    <div class="config-actions">
      <button class="btn btn-secondary" @click="loadExampleConfig">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
          <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
        </svg>
        Load Example
      </button>
      <button class="btn btn-outline" @click="clearConfig">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
        Clear Config
      </button>
    </div>
  </div>
</template>

<style scoped>
.config-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
  height: 100%;
  overflow-y: auto;
  padding-right: 4px;
}

.config-page::-webkit-scrollbar {
  width: 4px;
}

.config-page::-webkit-scrollbar-track {
  background: transparent;
}

.config-page::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: 2px;
}

.config-section {
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 20px;
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 16px;
}

.card-header h2 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
}

.card-header-decoration {
  flex: 1;
  height: 2px;
  background: var(--gradient-primary);
  border-radius: 1px;
}

.add-node-btn {
  padding: 6px 12px;
  border: 1px dashed var(--primary-400);
  border-radius: var(--radius-sm);
  background: var(--primary-50);
  color: var(--primary-600);
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 4px;
  transition: all var(--transition-normal);
}

.add-node-btn:hover {
  background: var(--primary-100);
  border-style: solid;
}

.add-node-btn svg {
  width: 14px;
  height: 14px;
}

.nodes-container {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.node-card {
  background: var(--surface-2);
  border-radius: var(--radius-md);
  padding: 16px;
  border: 1px solid var(--border-color);
  transition: all var(--transition-normal);
}

.node-card:hover {
  border-color: var(--primary-300);
}

.node-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
}

.node-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.type-badge {
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 500;
  border: 1px solid;
  display: flex;
  align-items: center;
  gap: 4px;
  transition: all var(--transition-normal);
}

.type-badge svg {
  width: 12px;
  height: 12px;
}

.remove-node-btn {
  margin-left: auto;
  width: 24px;
  height: 24px;
  border: none;
  background: transparent;
  border-radius: var(--radius-sm);
  color: var(--text-muted);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all var(--transition-fast);
}

.remove-node-btn:hover {
  background: var(--error-50);
  color: var(--error-500);
}

.remove-node-btn svg {
  width: 14px;
  height: 14px;
}

.node-domains-section {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--border-light);
}

.form-group {
  margin-bottom: 14px;
}

.form-group:last-child {
  margin-bottom: 0;
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.form-label {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-primary);
  margin-bottom: 6px;
}

.label-text {
  color: var(--text-primary);
}

.domain-count {
  font-size: 11px;
  color: var(--text-muted);
}

.input-wrapper,
.connection-input-wrapper,
.textarea-wrapper {
  position: relative;
}

.input-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  width: 16px;
  height: 16px;
  color: var(--text-muted);
  z-index: 1;
}

.input-icon svg {
  width: 100%;
  height: 100%;
}

.form-input,
.form-textarea,
.form-select {
  width: 100%;
  padding: 10px 12px;
  border: 1.5px solid var(--border-color);
  border-radius: var(--radius-md);
  font-size: 13px;
  transition: all var(--transition-normal);
  box-sizing: border-box;
  background: var(--surface-1);
  color: var(--text-primary);
}

.form-input {
  padding-left: 40px;
}

.form-input:focus,
.form-textarea:focus,
.form-select:focus {
  outline: none;
  border-color: var(--primary-500);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.form-textarea {
  padding-left: 40px;
  resize: vertical;
  min-height: 56px;
  line-height: 1.5;
}

.hint {
  font-size: 12px;
  color: var(--text-muted);
  margin: 6px 0 0 0;
}

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

@media (max-width: 600px) {
  .form-grid {
    grid-template-columns: 1fr;
  }
  
  .load-balancing-options {
    flex-direction: column;
  }
}
</style>