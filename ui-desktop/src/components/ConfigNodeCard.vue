<script setup lang="ts">
/**
 * One node: the server this machine dials, the domains it answers for, and the credentials it
 * answers with.
 *
 * A node arrives from an invite and is not added by hand, so its target is shown rather than
 * typed, and the credentials it may or may not have are edited here, on the node that has them.
 *
 * The card folds away. Three nodes are three copies of the same four fields, and only one of them
 * is being worked on at a time — the others are there to be counted, not read.
 *
 * The connection string and the secret are handled by [`useNodeCredentials`], which keeps them
 * behind the credential door and forgets them when the door shuts.
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import AppButton from "./base/AppButton.vue";
import AppIcon from "./base/AppIcon.vue";
import AppIconButton from "./base/AppIconButton.vue";
import AppToggle from "./base/AppToggle.vue";
import type { ConnectionType, NodeConfig, TwoFactorAlgorithm } from "../types";
import { useConfigStore } from "../stores/config";
import { useNodeCredentials } from "../composables/useNodeCredentials";

const props = defineProps<{
  /** The node this card is about. */
  node: NodeConfig;
  /** Where the node sits in the list, for the label a node without a name is given. */
  index: number;
}>();

const emit = defineEmits<{
  /** The node was taken off the list. */
  (e: "remove", node: NodeConfig): void;
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

/**
 * Whether the card is open.
 *
 * Open to begin with: one node is the common case, and a card that opens onto nothing tells the
 * reader less than one that shows what is configured.
 */
const expanded = ref(true);

/**
 * The domains box, so it can be put back at the top of the list.
 *
 * The value is set by the renderer rather than typed, and setting the value of a textarea
 * puts the caret at the end of it — and the scroll position goes with the caret. A list of
 * five domains in a box that shows three therefore opened with the first domain half a line
 * above the top edge, which reads as a rendering fault rather than as a list.
 */
const domainsBox = ref<HTMLTextAreaElement | null>(null);

onMounted(() => {
  if (domainsBox.value) domainsBox.value.scrollTop = 0;
});

function getNodeLabel(node: NodeConfig, index: number): string {
  return node.name || t("config.nodeFallback", { index: index + 1 });
}

function getNodeTypeLabel(type: ConnectionType): string {
  return type === "ticket" ? t("connection.ticket") : t("connection.endpointId");
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
 * Whether this node has a two-factor configuration.
 *
 * The switch says whether the credentials are *there*, not whether they are filled in: a node whose
 * fields have been opened but not yet typed into still has a two-factor configuration, and a
 * switch that read "off" beside fields that are open would be answering a different question.
 *
 * A node that is waiting to enroll is left alone: the token is armed and the credential comes
 * with the next connect, so writing an empty pair over it would replace a registration that is
 * about to succeed with a credential that has nothing in it.
 */
const twoFactorOn = computed({
  get: (): boolean => twoFactorState(props.node) === "on",
  set: (on: boolean): void => {
    if (twoFactorState(props.node) === "pending") return;
    if (on) {
      if (!props.node.twoFactor) setNodeTwoFactor(props.node.id, {});
      return;
    }
    clearNodeTwoFactor(props.node.id);
  },
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
  <article class="node-card">
    <header class="node-card__header">
      <AppIconButton
        :icon="expanded ? 'chevron-down' : 'chevron-right'"
        :label="expanded ? t('config.collapseNode') : t('config.expandNode')"
        size="sm"
        @click="expanded = !expanded"
      />

      <span class="node-card__name">{{ getNodeLabel(node, index) }}</span>

      <span class="node-card__badge" :class="`node-card__badge--${node.connectionType}`">
        <AppIcon :name="node.connectionType === 'ticket' ? 'clipboard' : 'link-direct'" :size="12" />
        {{ getNodeTypeLabel(node.connectionType) }}
      </span>

      <span class="node-card__count">
        {{ t("config.domainsCount", { count: node.domains.length }) }}
      </span>

      <AppIconButton
        icon="trash"
        :label="t('config.removeNode')"
        tone="danger"
        size="sm"
        @click="emit('remove', node)"
      />
    </header>

    <div v-show="expanded" class="node-card__body">
      <div class="node-field">
        <span class="form-label">{{ t("node.connection") }}</span>
        <div class="connection-row">
          <!-- The connection string is displayed, not edited: a node arrives from an invite and
               its target is not retyped afterwards. Masked copy, with reveal and copy on the
               right. -->
          <code class="connection-value">{{ connectionDisplay(node) }}</code>
          <AppIconButton
            :icon="isRevealed(node.id) ? 'eye-off' : 'eye'"
            :label="isRevealed(node.id) ? t('node.hide') : t('node.reveal')"
            size="sm"
            @click="toggleReveal(node)"
          />
          <AppIconButton
            icon="copy"
            :label="t('common.copy')"
            size="sm"
            @click="copyConnection(node)"
          />
        </div>
        <p class="hint">{{ t("node.connectionHint") }}</p>
      </div>

      <div class="node-field">
        <label class="form-label" :for="`node-domains-${node.id}`">
          {{ t("config.proxiedDomains") }}
        </label>
        <textarea
          :id="`node-domains-${node.id}`"
          ref="domainsBox"
          :value="getNodeDomainsText(node)"
          @input="updateNodeDomainsText(node.id, ($event.target as HTMLTextAreaElement).value)"
          rows="3"
          :placeholder="t('config.domainsPlaceholder')"
          class="form-textarea"
        ></textarea>
      </div>

      <div class="node-field">
        <div class="node-2fa-row">
          <AppIcon name="lock" :size="14" />
          <span class="node-2fa-title">{{ t("node.twoFactor") }}</span>
          <span
            class="node-2fa-state"
            :class="{ on: twoFactorState(node) === 'on', pending: twoFactorState(node) === 'pending' }"
          >
            {{ twoFactorStateLabel }}
          </span>
          <AppToggle
            v-model="twoFactorOn"
            :label="t('node.twoFactor')"
            size="sm"
            :disabled="twoFactorState(node) === 'pending'"
          />
        </div>

        <!-- The fields are for a credential the node holds. A node that is still waiting to
             enroll has none yet — it has a token — so the wait is what is shown, and the fields
             would be editing a credential that is not there. The switch above is disabled in that
             state for the same reason. -->
        <div v-if="node.twoFactor && !node.enrollment" class="node-2fa-fields">
          <div class="node-field">
            <label class="form-label" :for="`node-client-${node.id}`">
              {{ t("node.twoFactorClientId") }}
            </label>
            <input
              :id="`node-client-${node.id}`"
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
            <div class="node-field">
              <label class="form-label" :for="`node-public-key-${node.id}`">
                {{ t("node.twoFactorPublicKey") }}
              </label>
              <input
                :id="`node-public-key-${node.id}`"
                :value="node.publicKey"
                type="text"
                readonly
                class="form-input"
              />
            </div>
            <p class="hint">{{ t("node.twoFactorKeyHint") }}</p>
          </template>
          <template v-else>
            <div class="node-field">
              <label class="form-label" :for="`node-secret-${node.id}`">
                {{ t("node.twoFactorSecret") }}
              </label>
              <div class="secret-row">
                <!-- Empty until a reveal is open, with the mask as the placeholder rather than as
                     the value: a mask sitting in the field is a value, and a user who adds one
                     character to it would store bullets as the TOTP secret. -->
                <input
                  :id="`node-secret-${node.id}`"
                  :value="revealedSecrets[node.id] ?? ''"
                  @change="onSecretChange(node, $event)"
                  :type="secretInputType(node)"
                  :placeholder="secretDisplay(node)"
                  class="form-input"
                />
                <AppIconButton
                  v-if="secretMask(node.id)"
                  :icon="revealedSecrets[node.id] !== undefined ? 'eye-off' : 'eye'"
                  :label="revealedSecrets[node.id] !== undefined ? t('node.hide') : t('node.reveal')"
                  size="sm"
                  @click="toggleSecret(node)"
                />
              </div>
            </div>
            <div class="node-field">
              <label class="form-label" :for="`node-algorithm-${node.id}`">
                {{ t("node.twoFactorAlgorithm") }}
              </label>
              <select
                :id="`node-algorithm-${node.id}`"
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
          <div class="node-field">
            <label class="form-label" :for="`node-device-${node.id}`">
              {{ t("node.twoFactorDevice") }}
            </label>
            <!-- Read-only: which secret this node answers with is decided by what the
                 server filed it under, and a name edited here would be a name the
                 server does not have. What changes it is a registration invite. -->
            <input
              :id="`node-device-${node.id}`"
              :value="node.twoFactor.device ?? ''"
              :placeholder="node.twoFactor.device ? '' : t('node.deviceNone')"
              type="text"
              readonly
              class="form-input"
            />
          </div>
          <p v-if="!node.twoFactor.device" class="hint">{{ t("node.deviceHint") }}</p>
          <AppButton
            v-if="!node.twoFactor.device"
            size="sm"
            tone="secondary"
            @click="emit('reenroll')"
          >
            {{ t("node.deviceReenroll") }}
          </AppButton>
          <p class="hint">{{ t("node.twoFactorHint") }}</p>
        </div>
        <!-- A token is not a credential yet, so there is nothing to edit here: it is spent
             on the next connect, which writes the real secret into this node. -->
        <p v-else-if="node.enrollment" class="hint">
          {{ t("node.enrollmentPending", { id: node.enrollment.clientId }) }}
        </p>
      </div>
    </div>
  </article>
</template>

<style scoped>
.node-card {
  background: var(--bg-inset);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  overflow: hidden;
}

.node-card__header {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-2) var(--space-3);
}

.node-card__name {
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-semibold);
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/*
 * The two kinds of node are told apart by a badge, and the badge is told apart by tone rather
 * than by a colour of its own: a raw colour does not follow the theme, and a themed one has
 * nothing to say that two semantic tones do not.
 */
.node-card__badge {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: 2px var(--space-2);
  border: 1px solid transparent;
  border-radius: var(--radius-full);
  font-size: var(--font-size-11);
  font-weight: var(--font-weight-medium);
  white-space: nowrap;
}

.node-card__badge--ticket {
  background: var(--accent-subtle);
  color: var(--accent-text);
  border-color: var(--accent);
}

.node-card__badge--endpoint {
  background: var(--info-subtle);
  color: var(--info-text);
  border-color: var(--info);
}

.node-card__count {
  margin-left: auto;
  font-size: var(--font-size-11);
  color: var(--text-muted);
  white-space: nowrap;
}

.node-card__body {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4) var(--space-3);
  border-top: 1px solid var(--border-subtle);
}

.node-field {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  min-width: 0;
}

/* The connection string and the secret are credentials: they are shown in a monospace face, so
   that a ticket and an endpoint id read as what they are. */
.connection-row,
.secret-row {
  display: flex;
  align-items: center;
  gap: var(--space-1);
  padding: var(--space-1) var(--space-1) var(--space-1) var(--space-3);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-sm);
  background: var(--bg-card);
}

.secret-row {
  padding-right: var(--space-1);
}

.connection-row .form-input,
.secret-row .form-input {
  border: none;
  background: transparent;
  padding-left: 0;
  padding-right: 0;
  font-family: var(--font-mono);
}

.secret-row .form-input:focus,
.connection-row .form-input:focus {
  box-shadow: none;
}

.connection-value {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: var(--font-mono);
  font-size: var(--font-size-12);
  color: var(--text-secondary);
}

.node-2fa-row {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  color: var(--text-secondary);
}

.node-2fa-title {
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-medium);
  color: var(--text-primary);
}

/* The state of the 2FA line is spelled out, because a switch alone does not say whether the
   credential is there, absent, or still on its way. */
.node-2fa-state {
  flex: 1;
  font-size: var(--font-size-11);
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
  gap: var(--space-3);
  padding-top: var(--space-2);
}
</style>
