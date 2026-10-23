<script setup lang="ts">
/**
 * The configuration screen: the relay this machine dials, the nodes it dials, and the settings
 * both of them are reached through.
 *
 * The page is three tabs — the nodes, the network, the relay — because the three are three
 * things to do rather than one long list of fields. The credential door stands in front of all
 * of them, and the tab strip stays on screen so that the door does too.
 *
 * The page itself is the composition — the door in front of it, and the sections behind the door.
 * What belongs to the screen rather than to a section lives in [`useConfigPage`]; what belongs to
 * a section lives in that section.
 */
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useConfigStore } from "../stores/config";
import { useCredentialGate, clearRefusal } from "../stores/gate";
import { useConfigPage } from "../composables/useConfigPage";
import AppButton from "../components/base/AppButton.vue";
import AppIcon from "../components/base/AppIcon.vue";
import AppTabStrip from "../components/base/AppTabStrip.vue";
import CredentialLock from "../components/CredentialLock.vue";
import InviteImportDialog from "../components/InviteImportDialog.vue";
import ConfigNodeList from "../components/ConfigNodeList.vue";
import ConfigDomainOverview from "../components/ConfigDomainOverview.vue";
import ConfigNetwork from "../components/ConfigNetwork.vue";
import ConfigLoadBalancing from "../components/ConfigLoadBalancing.vue";
import ConfigRelay from "../components/ConfigRelay.vue";
import ConfigDangerZone from "../components/ConfigDangerZone.vue";

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
  restoreDefaultNetworkSettings,
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

/** The three parts of the screen. */
type ConfigTab = "nodes" | "network" | "relay";

const activeTab = ref<ConfigTab>("nodes");

const tabs = computed(() => [
  { id: "nodes", label: t("config.tabs.nodes") },
  { id: "network", label: t("config.tabs.network") },
  { id: "relay", label: t("config.tabs.relay") },
]);

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
 * A new tab starts at the top of the page.
 *
 * The scroll container is the shell's, not this page's: the shell owns the one scroll area the
 * app has, and this page is content inside it. The class name is the only handle on it from
 * here, which is why this is a lookup and not a `closest()` buried in a handler.
 */
const pageRoot = ref<HTMLElement | null>(null);

watch(activeTab, () => {
  pageRoot.value?.closest(".page-shell__body")?.scrollTo({ top: 0 });
});
</script>

<template>
  <div ref="pageRoot" class="config-page">
    <!--
      The one row that stays on screen: the tabs are how a reader moves between three long
      sections, and the door is how they shut them — so both belong where scrolling cannot
      take them away.
    -->
    <div class="config-tabs">
      <AppTabStrip
        v-if="unlocked"
        v-model="activeTab"
        :tabs="tabs"
        :label="t('config.tabsLabel')"
        id-prefix="config"
      />
      <span class="config-tabs__lock">
        <CredentialLock :reason="t('gate.reasonConfig')" />
      </span>
    </div>

    <div v-if="!unlocked" class="config-locked">
      <span class="config-locked__icon">
        <AppIcon name="lock" :size="26" />
      </span>
      <h2 class="config-locked__title">{{ t("gate.lockedTitle") }}</h2>
      <p class="config-locked__body">{{ lockedBody }}</p>
      <!-- What the last attempt came back with. Said here because the button that
           was pressed is here: a press that does nothing has to answer for itself. -->
      <p v-if="refusal" class="config-locked__error" role="alert">{{ refusal }}</p>
      <AppButton
        v-if="canAuthenticate"
        tone="primary"
        icon="unlock"
        :loading="pending"
        @click="unlockPage"
      >
        {{ pending ? t("gate.confirming") : t("gate.unlock") }}
      </AppButton>
    </div>

    <!-- Behind the door, so a locked page renders none of it: what is not on the
         screen cannot be read out of it, which is the whole point.

         Only the tab on screen is rendered. A panel that is not on screen is not
         in the document at all, so the credentials a node holds cannot still be
         sitting in the other tab. -->
    <template v-if="unlocked">
      <div
        v-if="activeTab === 'nodes'"
        id="config-panel-nodes"
        class="config-panel"
        role="tabpanel"
        aria-labelledby="config-tab-nodes"
      >
        <ConfigNodeList
          :nodes="config.nodes"
          @import-invite="openInviteDialog"
          @reenroll="showInviteDialog = true"
        />

        <ConfigDomainOverview :nodes="config.nodes" />

        <ConfigDangerZone @clear-config="clearConfig" />
      </div>

      <div
        v-else-if="activeTab === 'network'"
        id="config-panel-network"
        class="config-panel"
        role="tabpanel"
        aria-labelledby="config-tab-network"
      >
        <ConfigNetwork
          v-model:local-addr="localAddr"
          v-model:dns-addr="dnsAddr"
          v-model:upstream-dns="upstreamDns"
        />

        <ConfigLoadBalancing v-model:load-balancing="loadBalancing" />

        <div class="config-panel__footer">
          <AppButton
            tone="ghost"
            icon="refresh"
            @click="restoreDefaultNetworkSettings"
          >
            {{ t("config.restoreDefaults") }}
          </AppButton>
          <span class="config-panel__footer-hint">{{ t("config.restoreDefaultsHint") }}</span>
        </div>
      </div>

      <div
        v-else
        id="config-panel-relay"
        class="config-panel"
        role="tabpanel"
        aria-labelledby="config-tab-relay"
      >
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
      </div>
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
  gap: var(--space-4);
}

/*
 * The row that stays on screen.
 *
 * It is pinned to the top of the shell's scroll area rather than to the top of the window, so
 * it sits where the page begins and stays there while the section below it is read.
 */
.config-tabs {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-2) 0;
  background: var(--bg-app);
  border-bottom: 1px solid var(--border-subtle);
}

.config-tabs__lock {
  margin-left: auto;
}

.config-panel {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.config-panel__footer {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  flex-wrap: wrap;
}

.config-panel__footer-hint {
  font-size: var(--font-size-12);
  color: var(--text-muted);
}

/* What a shut page is. The sections are not rendered at all while it shows, so there is nothing
   to scroll past and nothing in the document to read out of it. */
.config-locked {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-12) var(--space-6);
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  text-align: center;
}

.config-locked__icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 48px;
  height: 48px;
  margin-bottom: var(--space-1);
  border-radius: var(--radius-lg);
  background: var(--bg-inset);
  color: var(--text-muted);
}

.config-locked__title {
  margin: 0;
  font-size: var(--font-size-16);
  font-weight: var(--font-weight-semibold);
  color: var(--text-primary);
}

.config-locked__body {
  margin: 0;
  max-width: 420px;
  font-size: var(--font-size-12);
  line-height: var(--line-height-normal);
  color: var(--text-muted);
}

.config-locked__error {
  margin: var(--space-1) 0 0;
  padding: var(--space-2) var(--space-3);
  border-radius: var(--radius-sm);
  background: var(--error-subtle);
  color: var(--error-text);
  font-size: var(--font-size-12);
}
</style>
