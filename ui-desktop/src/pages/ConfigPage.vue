<script setup lang="ts">
import { ref, watch, computed } from "vue";
import { useI18n } from "vue-i18n";
import type {
  ConnectionType,
  InvitePayload,
  LoadBalancingStrategy,
  NodeConfig,
  TwoFactorAlgorithm,
} from "../types";
import { useConfigStore } from "../stores/config";
import { useToast } from "../composables/useToast";
import InviteImportDialog from "../components/InviteImportDialog.vue";

const {
  config,
  updateConfig,
  removeNode,
  updateNodeDomains,
  applyInvite,
  setNodeTwoFactor,
  clearNodeTwoFactor,
  hasTwoFactor,
} = useConfigStore();

const { t } = useI18n();
const toast = useToast();

const showInviteDialog = ref(false);
/** A link pasted straight into a node field, handed to the dialog so it opens pre-filled. */
const inviteDraft = ref("");

const localAddr = ref(config.localAddr);
const dnsAddr = ref(config.dnsAddr);
const upstreamDns = ref(config.upstreamDns);
const loadBalancing = ref<LoadBalancingStrategy>(config.loadBalancing);

/** Label and description are i18n keys, not literals — they are resolved where they render. */
const loadBalancingOptions: { value: LoadBalancingStrategy; label: string; desc: string }[] = [
  { value: 'round_robin', label: 'config.strategyRoundRobin', desc: 'config.strategyRoundRobinDesc' },
  { value: 'random', label: 'config.strategyRandom', desc: 'config.strategyRandomDesc' },
];

function getNodeLabel(node: { name?: string }, index: number): string {
  return node.name || t('config.nodeFallback', { index: index + 1 });
}

function openInviteDialog() {
  inviteDraft.value = "";
  showInviteDialog.value = true;
}

/**
 * Nodes arrive from invites and their target is not edited afterwards, so the connection string
 * is shown rather than input. Masked by default because a ticket is a credential: anyone looking
 * at the screen should not be able to read one off it.
 */
const revealed = ref<Record<string, boolean>>({});

function connectionValue(node: NodeConfig): string {
  return node.connectionType === "ticket" ? node.ticket : node.endpointId;
}

function connectionDisplay(node: NodeConfig): string {
  const value = connectionValue(node);
  if (!value) return "—";
  if (revealed.value[node.id] || value.length <= 16) return value;
  return `${value.slice(0, 8)}••••${value.slice(-4)}`;
}

function toggleReveal(nodeId: string): void {
  revealed.value[nodeId] = !revealed.value[nodeId];
}

async function copyConnection(node: NodeConfig): Promise<void> {
  const value = connectionValue(node);
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    toast.success(t("common.copied"));
  } catch {
    toast.error(t("common.copyFailed"));
  }
}

/**
 * Credentials live on the node, so the toggle is per node: turning it on gives this server an
 * empty pair to fill in, turning it off puts it back to "no handshake".
 */
function toggleTwoFactor(nodeId: string) {
  const node = config.nodes.find((n) => n.id === nodeId);
  if (!node) return;
  if (hasTwoFactor(node)) {
    clearNodeTwoFactor(nodeId);
  } else {
    setNodeTwoFactor(nodeId, {});
  }
}

function importInvite(payload: { invite: InvitePayload; applyRelay: boolean }) {
  const outcome = applyInvite(payload.invite, { applyRelay: payload.applyRelay });
  toast.success(t(outcome === "added" ? "invite.added" : "invite.merged"));
}

function getNodeTypeLabel(type: ConnectionType): string {
  return type === 'ticket' ? t('connection.ticket') : t('connection.endpointId');
}

function getNodeTypeColor(type: ConnectionType): string {
  return type === 'ticket' ? '#8b5cf6' : '#0ea5e9';
}

/**
 * Text for a node's domains box, derived from the store on every render.
 *
 * This used to be a `Map` snapshotted once during setup, seeded from the nodes that existed at
 * that moment. A node created afterwards — every node an invite imports — therefore had no
 * entry and rendered an *empty* box, while the count badge beside it printed the live
 * `node.domains.length`: "5 个域名" above an empty field. Because that box is also the editor,
 * the first keystroke then wrote the empty text back through `updateNodeDomainsText`, which is
 * how an imported domain list could disappear for real rather than just look missing.
 *
 * Deriving it means the box can only ever show what the node actually holds, and an import that
 * *merges* domains into an existing node is reflected too.
 */
function getNodeDomainsText(node: NodeConfig): string {
  return node.domains.join("\n");
}

/**
 * One line per domain; blank lines are ignored, so the field tolerates a pasted list with
 * trailing newlines. The box is left as typed until the parsed result differs from what it
 * renders — see `getNodeDomainsText` — which keeps the caret from jumping mid-line.
 */
function updateNodeDomainsText(nodeId: string, text: string) {
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

/**
 * Nodes with no connection string are not shown at all.
 *
 * The target is no longer editable, so such a node can never be completed, and the backend drops
 * it at start-up anyway (`start_proxy` keeps only nodes with a ticket or an endpoint ID). The
 * loader already discards them, so this filter is the second half of that decision: it keeps the
 * page honest about what it renders even if a node ever loses its target.
 */
const visibleNodes = computed(() =>
  config.nodes.filter((node) => node.ticket.trim() !== '' || node.endpointId.trim() !== ''),
);

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
  dnsAddr.value = "198.18.0.254:53";
  upstreamDns.value = "223.5.5.5:53";
  loadBalancing.value = "round_robin";
}

function clearConfig() {
  localAddr.value = "127.0.0.1:8080";
  dnsAddr.value = "198.18.0.254:53";
  upstreamDns.value = "223.5.5.5:53";
  loadBalancing.value = "round_robin";
}
</script>

<template>
  <div class="config-page">
    <div class="config-section">
      <div class="card-header">
        <h2>{{ t('config.nodeConfiguration') }}</h2>
        <div class="card-header-decoration"></div>
        <button @click="openInviteDialog()" class="import-invite-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="8" y="3" width="8" height="4" rx="1"/>
            <path d="M16 5h2a2 2 0 0 1 2 2v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2"/>
          </svg>
          {{ t('invite.import') }}
        </button>
      </div>
      
      <div class="nodes-container">
        <div v-if="visibleNodes.length === 0" class="nodes-empty">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="8" y="3" width="8" height="4" rx="1"/>
            <path d="M16 5h2a2 2 0 0 1 2 2v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2"/>
          </svg>
          <span class="nodes-empty-title">{{ t('config.noNodes') }}</span>
          <span class="nodes-empty-hint">{{ t('config.noNodesHint') }}</span>
        </div>

        <div
          v-for="(node, index) in visibleNodes"
          :key="node.id"
          class="node-card"
        >
          <div class="node-header">
            <span class="node-label">{{ getNodeLabel(node, index) }}</span>
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
              v-if="visibleNodes.length > 1"
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
            <code class="form-input connection-value">{{ connectionDisplay(node) }}</code>
            <button
              type="button"
              class="connection-action"
              :aria-label="revealed[node.id] ? t('node.hide') : t('node.reveal')"
              @click="toggleReveal(node.id)"
            >
              <svg v-if="revealed[node.id]" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
                <path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/>
                <line x1="1" y1="1" x2="23" y2="23"/>
              </svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/>
                <circle cx="12" cy="12" r="3"/>
              </svg>
            </button>
            <button
              type="button"
              class="connection-action"
              :aria-label="t('common.copy')"
              @click="copyConnection(node)"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
            </button>
          </div>
          <p class="connection-hint">{{ t('node.connectionHint') }}</p>
          
          <div class="node-domains-section">
            <label class="form-label">
              <span class="label-text">{{ t('config.proxiedDomains') }}</span>
              <span class="domain-count">{{ t('config.domainsCount', { count: node.domains.length }) }}</span>
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
                :value="getNodeDomainsText(node)"
                @input="updateNodeDomainsText(node.id, ($event.target as HTMLTextAreaElement).value)"
                rows="2"
                :placeholder="t('config.domainsPlaceholder')"
                class="form-textarea"
              ></textarea>
            </div>
          </div>

          <div class="node-2fa-section">
            <button type="button" class="node-2fa-toggle" @click="toggleTwoFactor(node.id)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="11" width="18" height="11" rx="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              <span class="node-2fa-title">{{ t('node.twoFactor') }}</span>
              <span class="node-2fa-state" :class="{ on: hasTwoFactor(node) }">
                {{ hasTwoFactor(node) ? t('common.enabled') : t('common.disabled') }}
              </span>
            </button>
            <div v-if="node.twoFactor" class="node-2fa-fields">
              <div class="node-2fa-field">
                <label class="form-label">{{ t('node.twoFactorClientId') }}</label>
                <input
                  :value="node.twoFactor.clientId"
                  @change="setNodeTwoFactor(node.id, { clientId: ($event.target as HTMLInputElement).value.trim() })"
                  type="text"
                  placeholder="client-001"
                  class="form-input"
                />
              </div>
              <div class="node-2fa-field">
                <label class="form-label">{{ t('node.twoFactorSecret') }}</label>
                <input
                  :value="node.twoFactor.secret"
                  @change="setNodeTwoFactor(node.id, { secret: ($event.target as HTMLInputElement).value.trim() })"
                  type="password"
                  placeholder="JBSWY3DPEHPK3PXP"
                  class="form-input"
                />
              </div>
              <div class="node-2fa-field">
                <label class="form-label">{{ t('node.twoFactorAlgorithm') }}</label>
                <select
                  :value="node.twoFactor.algorithm"
                  @change="setNodeTwoFactor(node.id, { algorithm: ($event.target as HTMLSelectElement).value as TwoFactorAlgorithm })"
                  class="form-select"
                >
                  <option value="sha1">SHA1</option>
                  <option value="sha256">SHA256</option>
                  <option value="sha512">SHA512</option>
                </select>
              </div>
              <p class="node-2fa-hint">{{ t('node.twoFactorHint') }}</p>
            </div>
            <!-- A token is not a credential yet, so there is nothing to edit here: it is spent
                 on the next connect, which writes the real secret into this node. -->
            <p v-else-if="node.enrollment" class="node-2fa-hint">
              {{ t('node.enrollmentPending', { id: node.enrollment.clientId }) }}
            </p>
          </div>
        </div>
      </div>
      <p v-if="visibleNodes.length > 1" class="hint">{{ t('config.multipleNodesHint') }}</p>
    </div>

    <div class="config-section">
      <div class="card-header">
        <h2>{{ t('config.domainOverview') }}</h2>
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
    </div>

    <div class="config-section">
      <div class="card-header">
        <h2>{{ t('config.network') }}</h2>
        <div class="card-header-decoration"></div>
      </div>
      
      <div class="form-grid">
        <div class="form-group">
          <label for="localAddr" class="form-label">{{ t('config.localAddr') }}</label>
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
          <label for="dnsAddr" class="form-label">{{ t('config.dnsAddr') }}</label>
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
              placeholder="198.18.0.254:53"
              class="form-input"
            />
          </div>
        </div>

        <div class="form-group">
          <label for="upstreamDns" class="form-label">{{ t('config.upstreamDns') }}</label>
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
        <h2>{{ t('config.loadBalancing') }}</h2>
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
            <span class="strategy-label">{{ t(option.label) }}</span>
            <span class="strategy-desc">{{ t(option.desc) }}</span>
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
        {{ t('config.loadExample') }}
      </button>
      <button class="btn btn-outline" @click="clearConfig">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
        {{ t('config.clearConfig') }}
      </button>
    </div>

    <InviteImportDialog
      :open="showInviteDialog"
      :initial-value="inviteDraft"
      @close="showInviteDialog = false"
      @import="importInvite"
    />
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

/* 2FA belongs to the node, so it is edited on the node: the fields sit behind a toggle because
   most servers have no credentials at all. */
.node-2fa-section {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--border-light);
}

.node-2fa-toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
  font-size: 12px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: pointer;
}

.node-2fa-toggle:hover {
  color: var(--text-primary);
}

.node-2fa-toggle svg {
  width: 14px;
  height: 14px;
}

.node-2fa-title {
  flex: 1;
  text-align: left;
}

.node-2fa-state {
  color: var(--text-muted);
}

.node-2fa-state.on {
  color: var(--success);
}

.node-2fa-fields {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 10px;
}

/* No leading icon in these fields, unlike the connection and domain inputs above. */
.node-2fa-fields .form-input,
.node-2fa-fields .form-select {
  padding-left: 12px;
}

.node-2fa-hint {
  font-size: 11px;
  color: var(--text-muted);
  line-height: 1.5;
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

/* The connection string is displayed, not edited: a node arrives from an invite and its target
   is not retyped afterwards. Masked copy, with reveal and copy on the right. */
.connection-value {
  padding-right: 84px;
  background: var(--surface-2);
  color: var(--text-secondary);
  font-family: 'SF Mono', Monaco, 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.5;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.connection-value:focus {
  border-color: var(--border-light);
  box-shadow: none;
}

.connection-action {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.connection-action:hover {
  background: var(--surface-3);
  color: var(--text-primary);
}

.connection-action:nth-of-type(1) {
  right: 40px;
}

.connection-action:nth-of-type(2) {
  right: 8px;
}

.connection-action svg {
  width: 15px;
  height: 15px;
}

.connection-hint {
  margin: 6px 0 0;
  font-size: 11px;
  color: var(--text-muted);
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