<script setup lang="ts">
/**
 * The configuration screen: the relay this machine dials, the nodes it dials, and the settings
 * both of them are reached through.
 *
 * The page itself is the composition — the door in front of it, and the sections behind the door.
 * What belongs to the screen rather than to a section lives in [`useConfigPage`]; what belongs to
 * a section lives in that section.
 */
import { computed, onMounted, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useConfigStore } from "../stores/config";
import { useCredentialGate, clearRefusal } from "../stores/gate";
import { useConfigPage } from "../composables/useConfigPage";
import CredentialLock from "../components/CredentialLock.vue";
import InviteImportDialog from "../components/InviteImportDialog.vue";
import ConfigNodeList from "../components/ConfigNodeList.vue";
import ConfigDomainOverview from "../components/ConfigDomainOverview.vue";
import ConfigNetwork from "../components/ConfigNetwork.vue";
import ConfigLoadBalancing from "../components/ConfigLoadBalancing.vue";
import ConfigRelay from "../components/ConfigRelay.vue";
import ConfigActions from "../components/ConfigActions.vue";

const { config } = useConfigStore();

/**
 * The whole page is behind the door, so the door is read from it.
 *
 * `refusal` is what the last attempt to open it came back with — a password that
 * was not accepted, or a prompt that was dismissed — and it is printed on the
 * locked page rather than swallowed: a button that was pressed and did nothing
 * is the one thing a locked page owes an explanation for.
 */
const { ensureUnlocked, unlocked, refusal, canAuthenticate, pending, refresh } =
  useCredentialGate();

const { t } = useI18n();

const {
  localAddr,
  dnsAddr,
  upstreamDns,
  loadBalancing,
  loadExampleConfig,
  clearConfig,
  showInviteDialog,
  inviteDraft,
  openInviteDialog,
  importInvite,
  updateRelayMode,
  updateRelayUrl,
  commitRelayUrl,
  updateRelayAuthToken,
  commitRelayAuthToken,
} = useConfigPage();

/**
 * Re-read the door every time the page is opened.
 *
 * The window is two minutes of memory and nothing checks it while it runs, so a
 * page that was unlocked and left must not still be open when it is come back
 * to — and a machine that lost what it asks with while the app was in the
 * background is found out here. What the last refusal said belongs to the visit
 * that was refused, so it goes too.
 */
onMounted(() => {
  clearRefusal();
  void refresh();
});

/** Why the page is shut, which is also what opening it will cost. */
const lockedBody = computed(() =>
  canAuthenticate.value ? t("gate.lockedBody") : t("gate.unavailableBody"),
);

async function unlockPage(): Promise<void> {
  await ensureUnlocked(t("gate.reasonConfig"));
}

/**
 * The door shuts, and what it was holding goes with it.
 *
 * The invite dialog is mounted outside the `v-if` that hides the rest of the page, so a window
 * that lapses — or the lock button — leaves it open on a page that is shut. Its import writes
 * nodes and relay settings, which is what the door is for, so it goes with everything else.
 * The credentials the node list holds are forgotten by the composable that keeps them.
 */
watch(unlocked, (isUnlocked) => {
  if (isUnlocked) return;
  showInviteDialog.value = false;
});

/**
 * The two colours a node's badge is drawn in: one for a node reached by a ticket, one for a node
 * reached by an endpoint id.
 *
 * They are raw values, and the token guard allows those only in this file, so they are written
 * down here and handed to the section that draws the badges rather than being repeated there.
 */
const nodeTypeColors = { ticket: "#8b5cf6", endpoint: "#0ea5e9" } as const;
</script>

<template>
  <div class="config-page">
    <!-- The door comes first, because it decides whether there is a page under it. -->
    <div class="config-lockbar">
      <CredentialLock :reason="t('gate.reasonConfig')" />
    </div>

    <div v-if="!unlocked" class="config-locked">
      <span class="config-locked__icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </span>
      <h2 class="config-locked__title">{{ t('gate.lockedTitle') }}</h2>
      <p class="config-locked__body">{{ lockedBody }}</p>
      <!-- What the last attempt came back with. Said here because the button that
           was pressed is here: a press that does nothing has to answer for itself. -->
      <p v-if="refusal" class="config-locked__error" role="alert">{{ refusal }}</p>
      <button
        v-if="canAuthenticate"
        type="button"
        class="config-locked__action"
        :disabled="pending"
        @click="unlockPage"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2"/>
          <path d="M7 11V7a4 4 0 0 1 7.5-2"/>
        </svg>
        {{ pending ? t('gate.confirming') : t('gate.unlock') }}
      </button>
    </div>

    <!-- Behind the door, so a locked page renders none of it: what is not on the
         screen cannot be read out of it, which is the whole point. -->
    <template v-if="unlocked">
      <ConfigNodeList
        :nodes="config.nodes"
        :type-colors="nodeTypeColors"
        @import-invite="openInviteDialog"
        @reenroll="showInviteDialog = true"
      />

      <ConfigDomainOverview :nodes="config.nodes" />

      <ConfigNetwork
        v-model:local-addr="localAddr"
        v-model:dns-addr="dnsAddr"
        v-model:upstream-dns="upstreamDns"
      />

      <ConfigLoadBalancing v-model:load-balancing="loadBalancing" />

      <ConfigRelay
        :relay-mode="config.relayMode"
        :relay-url="config.relayUrl"
        :relay-auth-token="config.relayAuthToken"
        :relay-auth-token-relay="config.relayAuthTokenRelay"
        @update:relay-mode="updateRelayMode"
        @update:relay-url="updateRelayUrl"
        @commit:relay-url="commitRelayUrl"
        @update:relay-auth-token="updateRelayAuthToken"
        @commit:relay-auth-token="commitRelayAuthToken"
      />

      <ConfigActions @load-example="loadExampleConfig" @clear-config="clearConfig" />
    </template>

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

/* The door, as the page's first row: right-aligned, because it is a state and an action rather
   than a section of its own. */
.config-lockbar {
  display: flex;
  justify-content: flex-end;
}

/* What a shut page is. The sections are not rendered at all while it shows, so there is nothing
   to scroll past and nothing in the document to read out of it. */
.config-locked {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 48px 24px;
  background: var(--surface-1);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-card);
  text-align: center;
}

.config-locked__icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 56px;
  height: 56px;
  border-radius: var(--radius-lg);
  background: var(--surface-2);
  color: var(--text-muted);
}

.config-locked__icon svg {
  width: 26px;
  height: 26px;
}

.config-locked__title {
  margin: 4px 0 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
}

.config-locked__body {
  margin: 0;
  max-width: 420px;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-muted);
}

.config-locked__error {
  margin: 0;
  padding: 6px 12px;
  border-radius: var(--radius-sm);
  background: var(--error-50);
  color: var(--error-600);
  font-size: 12px;
}

.config-locked__action {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 4px;
  padding: 10px 18px;
  border: 1px solid var(--primary-400);
  border-radius: var(--radius-md);
  background: transparent;
  color: var(--primary-600);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition-normal);
}

.config-locked__action:hover {
  background: var(--primary-50);
}

.config-locked__action svg {
  width: 16px;
  height: 16px;
}

/* The connection string is shown in a monospace face, so that a ticket and an endpoint id read
   as what they are. The stack is a raw value, and the token guard allows a raw font stack only
   in this file, so the rule that carries it lives here and reaches the card through the page's
   scope. */
:deep(.connection-value) {
  font-family: 'SF Mono', Monaco, 'Courier New', monospace;
}
</style>
