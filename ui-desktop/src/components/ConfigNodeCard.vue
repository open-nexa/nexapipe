<script setup lang="ts">
/**
 * One node: the server this machine dials, the domains it answers for, and the credentials it
 * answers with.
 *
 * A node arrives from an invite and is not added by hand, so its target is shown rather than
 * typed, and the credentials it may or may not have are edited here, on the node that has them.
 *
 * The connection string and the secret are handled by [`useNodeCredentials`], which keeps them
 * behind the credential door and forgets them when the door shuts.
 */
import { useI18n } from "vue-i18n";
import { computed } from "vue";
import type { ConnectionType, NodeConfig, TwoFactorAlgorithm } from "../types";
import { useConfigStore } from "../stores/config";
import { useNodeCredentials } from "../composables/useNodeCredentials";

const props = defineProps<{
  /** The node this card is about. */
  node: NodeConfig;
  /** Where the node sits in the list, for the label a node without a name is given. */
  index: number;
  /** Whether the node may be removed: the last one standing may not. */
  canRemove: boolean;
  /** The colour the node's badge is drawn in. */
  typeColor: string;
}>();

const emit = defineEmits<{
  /** The node was taken off the list. */
  (e: "remove", nodeId: string): void;
  /** The node's device has to be registered again, which takes an invite. */
  (e: "reenroll"): void;
}>();

const { t } = useI18n();
const { setNodeTwoFactor, clearNodeTwoFactor, twoFactorState, updateNodeDomains } = useConfigStore();
const {
  revealedSecrets,
  secretMask,
  connectionDisplay,
  isRevealed,
  toggleReveal,
  copyConnection,
  secretDisplay,
  secretInputType,
  onSecretChange,
  toggleSecret,
} = useNodeCredentials();

function getNodeLabel(node: NodeConfig, index: number): string {
  return node.name || t("config.nodeFallback", { index: index + 1 });
}

function getNodeTypeLabel(type: ConnectionType): string {
  return type === "ticket" ? t("connection.ticket") : t("connection.endpointId");
}

/**
 * Credentials live on the node, so the toggle is per node: turning it on gives this server an
 * empty pair to fill in, turning it off puts it back to "no handshake".
 *
 * A node that is waiting to enroll is left alone: the token is armed and the credential comes
 * with the next connect, so writing an empty pair over it would replace a registration that is
 * about to succeed with a credential that has nothing in it.
 */
function toggleTwoFactor(nodeId: string): void {
  const node = props.node;
  if (!node) return;
  const state = twoFactorState(node);
  if (state === "pending") return;
  if (state === "on") {
    clearNodeTwoFactor(nodeId);
  } else {
    setNodeTwoFactor(nodeId, {});
  }
}

/**
 * What the 2FA line reads.
 *
 * A node that is waiting to enroll says so: it is not 2FA-off, it is 2FA that has not been
 * answered yet, and reading it as "disabled" is what made a scanned invite look like it had not
 * been applied at all.
 */
const twoFactorStateLabel = computed(() => {
  const state = twoFactorState(props.node);
  if (state === "on") return t("common.enabled");
  if (state === "pending") return t("node.twoFactorPending");
  return t("common.disabled");
});

/**
 * Text for a node's domains box, derived from the store on every render.
 *
 * This used to be a `Map` snapshotted once during setup, seeded from the nodes that existed at
 * that moment. A node created afterwards — every node an invite imports — therefore had no
 * entry and rendered an *empty* box, while the count badge beside it printed the live
 * `node.domains.length`: "5 domains" above an empty field. Because that box is also the editor,
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
function updateNodeDomainsText(nodeId: string, text: string): void {
  const domains = text
    .split("\n")
    .map((d) => d.trim())
    .filter((d) => d.length > 0);
  updateNodeDomains(nodeId, domains);
}
</script>

<template>
  <div class="node-card">
    <div class="node-header">
      <span class="node-label">{{ getNodeLabel(node, index) }}</span>
      <span
        class="type-badge"
        :style="{ backgroundColor: typeColor + '15', color: typeColor, borderColor: typeColor + '30' }"
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
        v-if="canRemove"
        @click="emit('remove', node.id)"
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
        :aria-label="isRevealed(node.id) ? t('node.hide') : t('node.reveal')"
        @click="toggleReveal(node)"
      >
        <svg v-if="isRevealed(node.id)" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
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
      <button
        type="button"
        class="node-2fa-toggle"
        :disabled="twoFactorState(node) === 'pending'"
        @click="toggleTwoFactor(node.id)"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <span class="node-2fa-title">{{ t('node.twoFactor') }}</span>
        <span
          class="node-2fa-state"
          :class="{ on: twoFactorState(node) === 'on', pending: twoFactorState(node) === 'pending' }"
        >
          {{ twoFactorStateLabel }}
        </span>
      </button>
      <!-- The fields are for a credential the node holds. A node that is still
           waiting to enroll has none yet — it has a token — so the wait is what
           is shown, and the fields would be editing a credential that is not
           there. The toggle above is disabled in that state for the same
           reason. -->
      <div v-if="node.twoFactor && !node.enrollment" class="node-2fa-fields">
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
        <!-- A credential that is a key has no secret to show and no algorithm to
             choose: the public half below is what the server holds, and the
             private half never leaves the machine. -->
        <template v-if="node.publicKey">
          <div class="node-2fa-field">
            <label class="form-label">{{ t('node.twoFactorPublicKey') }}</label>
            <input
              :value="node.publicKey"
              type="text"
              readonly
              class="form-input"
            />
          </div>
          <p class="node-2fa-hint">{{ t('node.twoFactorKeyHint') }}</p>
        </template>
        <template v-else>
          <div class="node-2fa-field">
            <label class="form-label">{{ t('node.twoFactorSecret') }}</label>
            <!-- Empty until a reveal is open, with the mask as the placeholder rather than as
                 the value: a mask sitting in the field is a value, and a user who adds one
                 character to it would store bullets as the TOTP secret. -->
            <input
              :value="revealedSecrets[node.id] ?? ''"
              @change="onSecretChange(node, $event)"
              :type="secretInputType(node)"
              :placeholder="secretDisplay(node)"
              class="form-input"
            />
            <button
              v-if="secretMask(node.id)"
              type="button"
              class="node-2fa-reveal"
              :aria-label="revealedSecrets[node.id] !== undefined ? t('node.hide') : t('node.reveal')"
              @click="toggleSecret(node)"
            >
              {{ revealedSecrets[node.id] !== undefined ? t('node.hide') : t('node.reveal') }}
            </button>
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
        </template>
        <div class="node-2fa-field">
          <label class="form-label">{{ t('node.twoFactorDevice') }}</label>
          <!-- Read-only: which secret this node answers with is decided by what the
               server filed it under, and a name edited here would be a name the
               server does not have. What changes it is a registration invite. -->
          <input
            :value="node.twoFactor.device ?? ''"
            :placeholder="node.twoFactor.device ? '' : t('node.deviceNone')"
            type="text"
            readonly
            class="form-input"
          />
        </div>
        <p v-if="!node.twoFactor.device" class="node-2fa-hint">
          {{ t('node.deviceHint') }}
        </p>
        <button
          v-if="!node.twoFactor.device"
          type="button"
          class="node-2fa-reveal"
          @click="emit('reenroll')"
        >
          {{ t('node.deviceReenroll') }}
        </button>
        <p class="node-2fa-hint">{{ t('node.twoFactorHint') }}</p>
      </div>
      <!-- A token is not a credential yet, so there is nothing to edit here: it is spent
           on the next connect, which writes the real secret into this node. -->
      <p v-else-if="node.enrollment" class="node-2fa-hint">
        {{ t('node.enrollmentPending', { id: node.enrollment.clientId }) }}
      </p>
    </div>
  </div>
</template>

<style scoped>
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

/* A node that is waiting to enroll cannot be toggled: the token is armed, and
   the credential comes with the next connect. */
.node-2fa-toggle:disabled {
  cursor: default;
  opacity: 0.7;
}

.node-2fa-toggle:disabled:hover {
  color: var(--text-secondary);
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

/* Waiting for the server to answer the enrollment: neither on nor off. */
.node-2fa-state.pending {
  color: var(--warning);
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

.label-text {
  color: var(--text-primary);
}

.domain-count {
  font-size: 11px;
  color: var(--text-muted);
}

.connection-input-wrapper,
.textarea-wrapper {
  position: relative;
}

/* The connection string is displayed, not edited: a node arrives from an invite and its target
   is not retyped afterwards. Masked copy, with reveal and copy on the right.

   The rule is written as a descendant of the wrapper so that it wins over the shared
   `.form-input` padding whatever order the two stylesheets end up in. */
.connection-input-wrapper .connection-value {
  padding-right: 84px;
  background: var(--surface-2);
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.5;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.connection-input-wrapper .connection-value:focus {
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
</style>
