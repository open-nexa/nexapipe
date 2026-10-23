/**
 * The configuration screen's own state: the settings it edits, the actions that write them, and
 * the invite it imports.
 *
 * What is here belongs to the page rather than to one of its sections. The four settings are
 * edited by one section and reset by another — the network section types three addresses and the
 * load-balancing section picks the fourth, while the buttons at the foot of the screen write all
 * four at once — so the values live here and the sections are handed them. The invite dialog is
 * mounted outside the locked/unlocked switch, so it outlives the section it was opened from and
 * belongs to the page too.
 *
 * The store holds the configuration; what is held here is the screen's copy of the four settings,
 * which the store is told about and which the store pulls back whenever it changes elsewhere.
 */
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import type { LoadBalancingStrategy, RelayMode } from "../types";
import { useConfigStore } from "../stores/config";
import { defaultConfig } from "../stores/config/schema";
import { useCredentialGate } from "../stores/gate";
import { useToast } from "./useToast";
import { errorDetail, errorKey } from "../api/errors";

export function useConfigPage() {
  const {
    config,
    updateConfig,
    resetConfig,
    applyInvite,
    setRelayMode,
    setRelayUrl,
    setRelayAuthToken,
  } = useConfigStore();
  const { ensureUnlocked } = useCredentialGate();
  const { t } = useI18n();
  const toast = useToast();

  const localAddr = ref(config.localAddr);
  const dnsAddr = ref(config.dnsAddr);
  const upstreamDns = ref(config.upstreamDns);
  const loadBalancing = ref<LoadBalancingStrategy>(config.loadBalancing);

  /** Writes the four settings back to the store. */
  function handleUpdate(): void {
    updateConfig({
      localAddr: localAddr.value,
      dnsAddr: dnsAddr.value,
      upstreamDns: upstreamDns.value,
      loadBalancing: loadBalancing.value,
    });
  }

  /**
   * The store is the truth about the settings, so they are pulled back from it whenever it
   * changes — including a change this screen did not make.
   */
  watch(
    () => config,
    (newConfig) => {
      localAddr.value = newConfig.localAddr;
      dnsAddr.value = newConfig.dnsAddr;
      upstreamDns.value = newConfig.upstreamDns;
      loadBalancing.value = newConfig.loadBalancing;
    },
    { deep: true },
  );

  watch([localAddr, dnsAddr, upstreamDns, loadBalancing], handleUpdate);

  /**
   * Puts the network settings back to what a fresh installation has.
   *
   * These are the defaults the configuration starts from, so the button is a way back to them
   * rather than a set of example values to copy from — which is why it used to be called
   * "load an example" and why pressing it did nothing on a machine whose settings were
   * already the defaults. The toast says what happened either way: a press that changes
   * nothing still has to answer for itself.
   *
   * The DNS strategy is left alone. It says what happens to the machine's own name
   * resolution, and a button labelled "defaults" should not quietly change that.
   */
  function restoreDefaultNetworkSettings(): void {
    localAddr.value = defaultConfig.localAddr;
    dnsAddr.value = defaultConfig.dnsAddr;
    upstreamDns.value = defaultConfig.upstreamDns;
    loadBalancing.value = defaultConfig.loadBalancing;
    toast.success(t('config.networkDefaultsRestored'));
  }

  function clearConfig(): void {
    // Reset the whole config rather than these four fields: every node carries a
    // ticket and, once 2FA is set up, a TOTP secret, and resetting only the
    // scalars left all of that in storage under a button that says clear. The
    // deep watch above pulls the scalars back from the store, and the store
    // persists on its own, so the credentials are gone from disk too.
    resetConfig();
  }

  const showInviteDialog = ref(false);
  /** A link pasted straight into a node field, handed to the dialog so it opens pre-filled. */
  const inviteDraft = ref("");
  function openInviteDialog(): void {
    inviteDraft.value = "";
    showInviteDialog.value = true;
  }

  async function importInvite(payload: { uri: string; applyRelay: boolean }): Promise<void> {
    // Asked here as well as at the door of the page: the dialog outlives a window
    // that closed while it was open, and an import is a write to the same
    // configuration the page-level guard protects.
    if (!(await ensureUnlocked(t("gate.reasonConfig")))) return;
    try {
      const outcome = await applyInvite(payload.uri, { applyRelay: payload.applyRelay });
      toast.success(t(outcome === "added" ? "invite.added" : "invite.merged"));
    } catch (error) {
      toast.error(t(errorKey(error, "error.invite.parse_failed")));
      console.error("[invite] import failed:", errorDetail(error));
    }
  }

  /**
   * Another relay is in use.
   *
   * The mode says whether a relay is in use, not which one: the URL is kept in every mode, so
   * looking at another mode and coming back does not lose the relay or the token issued for it.
   */
  function updateRelayMode(mode: RelayMode): void {
    setRelayMode(mode);
  }

  /**
   * The relay URL as it is typed.
   *
   * The store keeps the raw text while the field is being typed into and trims it when the field
   * is left, which is what `commitRelayUrl` asks it to do.
   */
  function updateRelayUrl(url: string): void {
    config.relayUrl = url;
  }

  /** The URL field was left: the store trims it and says what happens to the token. */
  function commitRelayUrl(): void {
    setRelayUrl(config.relayUrl);
  }

  /** The bearer token as it is typed; the store binds it to the relay when the field is left. */
  function updateRelayAuthToken(token: string): void {
    config.relayAuthToken = token;
  }

  /** The token field was left: the store trims it and binds it to the relay it was typed for. */
  function commitRelayAuthToken(): void {
    setRelayAuthToken(config.relayAuthToken);
  }

  return {
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
  };
}
