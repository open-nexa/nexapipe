<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from "vue";
import { invoke } from "@tauri-apps/api/core";
import AppIcon from "./base/AppIcon.vue";
import type { ProxyConfig, ProxyStatus, EndpointLink, LinkKind } from "../types";
import { useConfigStore } from "../composables/useConfigStore";

const props = defineProps<{
  config: ProxyConfig;
}>();

const emit = defineEmits<{
  (e: "statusChange", status: ProxyStatus): void;
}>();

const {
  proxyStatus: storeStatus,
  endpointLinks: storeLinks,
  setEndpointLinks,
} = useConfigStore();

/**
 * How often the link type of each node is re-read while the proxy is up. iroh can promote a
 * relayed connection to a direct one at any moment, so this is polled rather than sampled once.
 */
const LINK_POLL_INTERVAL_MS = 5000;

const status = ref<ProxyStatus>(storeStatus.value);
const nodeId = ref<string>("");
const isLoading = ref(false);
const errorMessage = ref<string>("");

function copyNodeId() {
  if (nodeId.value) {
    navigator.clipboard.writeText(nodeId.value);
  }
}

const modeLabel = computed(() => {
  switch (status.value.mode) {
    case "tun":
      return "TUN Mode";
    case "local_proxy":
      return "Local Proxy Mode";
    case "starting":
      return "Starting";
    case "stopped":
      return "Stopped";
    default:
      return status.value.mode;
  }
});

const statusColor = computed(() => {
  if (status.value.running) {
    return "#22c55e";
  }
  return "#6b7280";
});

const modeColor = computed(() => {
  switch (status.value.mode) {
    case "tun":
      return "#16a34a";
    case "local_proxy":
      return "#d97706";
    case "starting":
      return "#3b82f6";
    default:
      return "#6b7280";
  }
});

/**
 * What the link indicator shows: the kind of path traffic is *actually* taking, not the relay
 * mode from the configuration.
 *
 * This used to read the config (ticket vs endpoint ID), which answered a different question —
 * a node given as a ticket may well connect directly, and an endpoint ID is not a promise of a
 * direct path either. Null when no node has reported a path yet, so nothing is claimed.
 */
const linkInfo = computed(() => {
  const kinds: LinkKind[] = storeLinks.value
    .map(l => l.link)
    .filter(k => k !== 'unknown');
  if (kinds.length === 0) return null;

  const direct = kinds.filter(k => k === 'direct').length;
  if (direct === kinds.length) {
    return { label: 'Direct', icon: 'link-direct', color: '#06b6d4' };
  }
  if (direct === 0) {
    return { label: 'Relay', icon: 'link-relay', color: '#8b5cf6' };
  }
  return { label: 'Mixed', icon: 'link-relay', color: '#f59e0b' };
});

/**
 * Reads how every node is currently reaching its backend.
 *
 * Infallible: an empty answer means "nothing is connected", which the UI renders by drawing no
 * link icon at all — a failure here must never become a red error over an otherwise healthy
 * proxy.
 */
async function updateEndpointLinks() {
  try {
    setEndpointLinks(
      await invoke<EndpointLink[]>("get_endpoint_links", {
        useService: props.config.useService,
      }),
    );
  } catch (e) {
    console.error("Failed to get endpoint links:", e);
    setEndpointLinks([]);
  }
}

async function updateStatus() {
  try {
    // The backend returns a structured `ProxyStatus`; the `"true:tun"` string this used to split
    // predates that change, which left the panel permanently showing "Stopped". Kept in sync until
    // this component is replaced in Phase 3.1.
    const result = await invoke<ProxyStatus>("get_proxy_status", {
      useService: props.config.useService,
    });
    status.value = result;
    
    if (status.value.running) {
      try {
        nodeId.value = await invoke<string>("get_node_id", {
          useService: props.config.useService,
        });
      } catch {
        nodeId.value = "";
      }
      await updateEndpointLinks();
    } else {
      nodeId.value = "";
      setEndpointLinks([]);
    }
    
    emit("statusChange", status.value);
    errorMessage.value = "";
  } catch (e: any) {
    errorMessage.value = e.message || "Failed to get status";
    console.error("Failed to get proxy status:", e);
  }
}

let linkPollTimer: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  updateStatus();
  // Only while running: a stopped proxy has no link to report, and the poll would be answered
  // with an empty list anyway.
  linkPollTimer = setInterval(() => {
    if (status.value.running) {
      void updateEndpointLinks();
    }
  }, LINK_POLL_INTERVAL_MS);
});

onUnmounted(() => {
  if (linkPollTimer !== null) {
    clearInterval(linkPollTimer);
    linkPollTimer = null;
  }
});

async function startProxy() {
  if (isLoading.value) return;
  
  isLoading.value = true;
  errorMessage.value = "";
  
  const backendNodes = props.config.nodes
    .filter(n => n.ticket || n.endpointId)
    .map(n => ({
      connection_type: n.connectionType,
      ticket: n.connectionType === 'ticket' ? n.ticket : '',
      endpoint_id: n.connectionType === 'endpoint_id' ? n.endpointId : '',
      domains: n.domains,
    }));
  
  try {
    await invoke<string>("start_proxy", {
      nodes: backendNodes,
      domains: props.config.domains,
      localAddr: props.config.localAddr,
      dnsAddr: props.config.dnsAddr,
      upstreamDns: props.config.upstreamDns,
      loadBalancing: props.config.loadBalancing,
      tunName: props.config.tunName,
      useService: props.config.useService,
        relayMode: props.config.relayMode,
        relayUrl: props.config.relayUrl,
        forceRelay: props.config.forceRelay,
        twoFactorEnabled: props.config.twoFactorEnabled,
        twoFactorClientId: props.config.twoFactorClientId,
        twoFactorSecret: props.config.twoFactorSecret,
        twoFactorAlgorithm: props.config.twoFactorAlgorithm,
      });
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    await updateStatus();
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    const startupError = await invoke<string | null>("get_startup_error");
    if (startupError) {
      errorMessage.value = startupError;
      console.error("Proxy startup error:", startupError);
    }
  } catch (e: any) {
    errorMessage.value = e.message || "Failed to start proxy";
    console.error("Failed to start proxy:", e);
  } finally {
    isLoading.value = false;
  }
}

async function stopProxy() {
  if (isLoading.value) return;
  
  isLoading.value = true;
  errorMessage.value = "";
  
  try {
    await invoke<string>("stop_proxy", {
      useService: props.config.useService,
    });
    
    await new Promise(resolve => setTimeout(resolve, 500));
    await updateStatus();
  } catch (e: any) {
    errorMessage.value = e.message || "Failed to stop proxy";
    console.error("Failed to stop proxy:", e);
  } finally {
    isLoading.value = false;
  }
}
</script>

<template>
  <div class="status-control">
    <div class="card-header">
      <h2>Proxy Status</h2>
      <div class="card-header-decoration"></div>
    </div>
    
    <div class="status-section">
      <div class="status-main">
        <div class="status-ring" :class="{ running: status.running, starting: status.mode === 'starting' }">
          <div class="status-ring-inner"></div>
          <div class="status-ring-glow"></div>
          <div class="status-dot" :style="{ backgroundColor: statusColor }"></div>
        </div>
        <div class="status-text-container">
          <span class="status-title">{{ status.running ? "Running" : "Stopped" }}</span>
          <span class="status-subtitle">{{ modeLabel }}</span>
        </div>
      </div>
      
      <div v-if="status.running" class="mode-indicators">
        <div class="mode-indicator" :style="{ backgroundColor: modeColor + '15', borderColor: modeColor + '30' }">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :style="{ color: modeColor }">
            <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"/>
            <line x1="12" y1="22" x2="12" y2="15.5"/>
            <line x1="22" y1="8.5" x2="12" y2="15.5"/>
            <line x1="2" y1="8.5" x2="12" y2="15.5"/>
          </svg>
          <span :style="{ color: modeColor }">{{ modeLabel }}</span>
        </div>
        <div
          v-if="linkInfo"
          class="connection-indicator"
          :style="{ backgroundColor: linkInfo.color + '15', borderColor: linkInfo.color + '30' }"
          :title="`Traffic is reaching ${linkInfo.label === 'Mixed' ? 'some nodes directly and others through a relay' : (linkInfo.label === 'Direct' ? 'the backend directly' : 'the backend through a relay')}`"
        >
          <AppIcon :name="linkInfo.icon" :size="16" :style="{ color: linkInfo.color }" />
          <span :style="{ color: linkInfo.color }">{{ linkInfo.label }}</span>
        </div>
      </div>
    </div>

    <div v-if="nodeId" class="node-info">
      <div class="info-header">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span class="info-title">Node ID</span>
      </div>
      <div class="node-id-content">
        <code class="node-id">{{ nodeId }}</code>
        <button class="copy-btn" @click="copyNodeId">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
      </div>
    </div>

    <div v-if="errorMessage" class="error-message">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <span>{{ errorMessage }}</span>
    </div>

    <div class="action-buttons">
      <button
        v-if="!status.running"
        class="btn btn-primary"
        :disabled="isLoading || config.nodes.length === 0 || config.nodes.every(n => !n.ticket && !n.endpointId)"
        @click="startProxy"
      >
        <svg v-if="isLoading" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
        <span>{{ isLoading ? 'Starting...' : 'Start Proxy' }}</span>
      </button>
      
      <button
        v-else
        class="btn btn-danger"
        :disabled="isLoading"
        @click="stopProxy"
      >
        <svg v-if="isLoading" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="6" y="4" width="4" height="16"/>
          <rect x="14" y="4" width="4" height="16"/>
        </svg>
        <span>{{ isLoading ? 'Stopping...' : 'Stop Proxy' }}</span>
      </button>
      
      <button
        class="btn btn-secondary"
        :disabled="isLoading"
        @click="updateStatus"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="23 4 23 10 17 10"/>
          <polyline points="1 20 1 14 7 14"/>
          <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
        </svg>
        <span>Refresh Status</span>
      </button>
    </div>
  </div>
</template>

<style scoped>
.status-control {
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 28px;
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
}

.card-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
}

.card-header-decoration {
  flex: 1;
  height: 3px;
  background: var(--gradient-primary);
  border-radius: 2px;
}

.status-section {
  margin-bottom: 20px;
}

.status-main {
  display: flex;
  align-items: center;
  gap: 20px;
  margin-bottom: 16px;
}

.status-ring {
  position: relative;
  width: 56px;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.status-ring-inner {
  width: 48px;
  height: 48px;
  border: 3px solid var(--surface-3);
  border-radius: 50%;
  transition: all var(--transition-slow);
}

.status-ring.running .status-ring-inner {
  border-color: rgba(34, 197, 94, 0.3);
}

.status-ring.starting .status-ring-inner {
  border-color: rgba(59, 130, 246, 0.3);
}

.status-ring-glow {
  position: absolute;
  width: 56px;
  height: 56px;
  border-radius: 50%;
  background: radial-gradient(circle, var(--surface-3) 0%, transparent 70%);
  opacity: 0;
  transition: opacity var(--transition-normal);
}

.status-ring.running .status-ring-glow {
  background: radial-gradient(circle, rgba(34, 197, 94, 0.2) 0%, transparent 70%);
  opacity: 1;
}

.status-ring.starting .status-ring-glow {
  background: radial-gradient(circle, rgba(59, 130, 246, 0.2) 0%, transparent 70%);
  opacity: 1;
}

.status-dot {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: var(--text-muted);
  transition: all var(--transition-normal);
  position: relative;
  z-index: 1;
}

.status-ring.running .status-dot {
  background: var(--success-500);
  box-shadow: 0 0 12px var(--success-500);
}

.status-ring.starting .status-dot {
  background: var(--primary-500);
  animation: pulse 1.5s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% {
    transform: scale(1);
    opacity: 1;
  }
  50% {
    transform: scale(1.2);
    opacity: 0.7;
  }
}

.status-text-container {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.status-title {
  font-size: 18px;
  font-weight: 700;
  color: var(--text-primary);
}

.status-subtitle {
  font-size: 13px;
  color: var(--text-muted);
}

.mode-indicators {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.mode-indicator,
.connection-indicator {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border-radius: 12px;
  border: 1px solid;
  font-size: 13px;
  font-weight: 500;
  transition: all var(--transition-normal);
}

.mode-indicator svg,
.connection-indicator svg {
  width: 16px;
  height: 16px;
}

.node-info {
  background: var(--surface-2);
  border-radius: var(--radius-md);
  padding: 16px;
  margin-bottom: 16px;
  border: 1px solid var(--border-light);
}

.info-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.info-header svg {
  width: 16px;
  height: 16px;
  color: var(--primary-600);
}

.info-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
}

.node-id-content {
  display: flex;
  align-items: center;
  gap: 12px;
}

.node-id {
  flex: 1;
  font-family: 'SF Mono', Monaco, 'Courier New', monospace;
  font-size: 13px;
  color: var(--text-primary);
  background: var(--surface-1);
  padding: 10px 12px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
  word-break: break-all;
}

.copy-btn {
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--surface-3);
  border: none;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
  flex-shrink: 0;
}

.copy-btn:hover {
  background: var(--primary-100);
}

.copy-btn svg {
  width: 16px;
  height: 16px;
  color: var(--text-secondary);
}

.copy-btn:hover svg {
  color: var(--primary-600);
}

.error-message {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 14px;
  background: var(--error-50);
  border-radius: var(--radius-md);
  margin-bottom: 16px;
  border-left: 3px solid var(--error-500);
}

.error-message svg {
  width: 18px;
  height: 18px;
  color: var(--error-500);
  flex-shrink: 0;
  margin-top: 1px;
}

.error-message span {
  font-size: 13px;
  color: var(--error-600);
  line-height: 1.5;
}

.action-buttons {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  border: none;
  border-radius: var(--radius-md);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition-normal);
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none !important;
}

.btn svg {
  width: 18px;
  height: 18px;
}

.btn-primary {
  background: var(--gradient-primary);
  color: white;
  box-shadow: 0 4px 14px rgba(59, 130, 246, 0.3);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
}

.btn-danger {
  background: var(--error-500);
  color: white;
  box-shadow: 0 4px 14px rgba(239, 68, 68, 0.3);
}

.btn-danger:hover:not(:disabled) {
  background: var(--error-600);
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
}

.btn-secondary {
  background: var(--surface-3);
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
}

.btn-secondary:hover:not(:disabled) {
  background: var(--surface-4);
  border-color: var(--primary-300);
  color: var(--text-primary);
}

.spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 480px) {
  .action-buttons {
    flex-direction: column;
  }
  
  .btn {
    width: 100%;
    justify-content: center;
  }
}
</style>
