/**
 * Persisted user configuration, plus the migration chain that gets old payloads here.
 *
 * Module-singleton composable rather than Pinia, consistent with the self-built decision
 * (docs/ui-refactor-plan.md §5.7). The split is by concern: this store owns what the *user*
 * configured and persists it; `proxy.ts` owns runtime status; `prefs.ts` owns UI preferences.
 *
 * Persistence is versioned (D11): `nexa-config` held a flat object with no version field, so
 * migrations could not be sequenced. The current shape is `{ version: 3, ...config }` under
 * `nexapipe.config`, and each future migration is a `from -> to` step in `migrate()`.
 *
 * # Credentials are not persisted here
 *
 * As of version 2 a TOTP secret, an enrollment token and the relay bearer are **not** written to
 * `localStorage`: they go to the encrypted store behind `api/credentials.ts`, whose master key
 * the OS keychain holds. As of version 3 the two connection strings are not either — a ticket
 * names an endpoint *and* carries how to reach it, so it is a credential and not configuration.
 *
 * What is persisted is the shape — that a node has 2FA, its client id and its algorithm, and
 * which of the two spellings of a connection string it uses — and the values are read back into
 * this config by [`initConfigStore`], which the app awaits before it mounts. A payload written
 * by an earlier version does carry them, and the same call moves them into the store rather
 * than leaving them in a file nothing protects.
 *
 * # This directory
 *
 * The store is a module of its own, and the concerns it holds are the files beside this one:
 * `schema.ts` (the shape and its defaults), `persistence.ts` (what goes to disk),
 * `credentials.ts` (the encrypted store), `relay.ts`, `device.ts`, `nodes.ts`, `invite.ts` and
 * `state.ts` (the configuration itself). This file is the face of the store: the actions, the
 * getters and the two start-up calls, and the names other files import.
 */
import { computed, watch } from 'vue';
import { clearCredentials, credentialStoreStatus } from '../../api/credentials';
import type { LoadBalancingStrategy, ProxyConfig, RelayMode } from '../../types';
import {
  connectionMasks,
  credentialProtection,
  dropNodesWithoutAConnectionString,
  hydrateCredentials,
  markCredentialsHydrated,
  refreshConnectionMasks,
  secretMasks,
} from './credentials';
import { ensureDeviceIdFor } from './device';
import { applyInvite } from './invite';
import {
  clearNodeTwoFactor,
  completeEnrollment,
  hasTwoFactor,
  removeNode,
  setNodeTwoFactor,
  twoFactorState,
  updateNode,
  updateNodeDomains,
} from './nodes';
import { dropLegacyKeyIfRedundant, persist, SAVE_DEBOUNCE_MS } from './persistence';
import {
  relayTokenAfter,
  relayTokenRelayFor,
  relayTokenToSend,
  writeRelayAuthToken,
  writeRelayMode,
  writeRelayUrl,
} from './relay';
import { defaultConfig, generateNodeId } from './schema';
import { config } from './state';

export { generateNodeId, relayTokenAfter, relayTokenRelayFor, relayTokenToSend };
export type { RelayToken, RelayTokenChange } from './relay';

/**
 * Completes loading the configuration: everything except the credentials is already in `config`
 * by the time this module is imported, and the credentials are read here because reading them is
 * asynchronous.
 *
 * Awaited before the app mounts, so no page ever renders a node's credentials as absent and then
 * fills them in. What is *not* awaited here is [`initConfigStoreDeferred`] — the display masks and
 * the store's protection level, which nothing on the first screen renders.
 */
export async function initConfigStore(): Promise<void> {
  try {
    // Assigned once, rather than filled in as each lookup returns: see
    // `hydrateCredentials`.
    Object.assign(config, await hydrateCredentials(config));

    // Now, and only now, that the store has answered: see
    // `dropNodesWithoutAConnectionString`.
    config.nodes = dropNodesWithoutAConnectionString(config.nodes);

    // Only from here may a save touch the store. Nothing before this line has
    // read it, so nothing before this line may delete from it — a failure
    // above leaves the secrets in `config` empty, and an ungated mirror would
    // empty the store to match.
    markCredentialsHydrated();

    // And only from here may the device name be generated, for the same reason:
    // generating one writes the config, and a write before the store had
    // answered is a write that could empty it.
    await ensureDeviceIdFor(config);

    // The legacy key goes now, and only because it can be proved redundant:
    // `persist` swallows a write failure, so the payload is read back rather
    // than trusted. A save that did not happen must not cost the user the copy
    // it was meant to replace.
    dropLegacyKeyIfRedundant(config);
  } catch (error) {
    // A store that cannot be read leaves the nodes without credentials: they will refuse to
    // handshake and the UI says so. Not fatal — the app has to stay usable enough to re-import
    // an invite. The credential store stays unhydrated, so the next save writes
    // `localStorage` and leaves the store alone — and the legacy payload
    // stays there to read next launch.
    console.error('[config] failed to load credentials:', error);
  }
}

/**
 * What [`initConfigStore`] deliberately leaves for after the first paint.
 *
 * Two reads, both of them pure projections and neither of which any first-screen surface
 * renders: the masks a credential is *displayed* as, and whether the master key ended up in the
 * OS keychain or in a file beside the store. The settings page is the only thing that prints
 * either, and it is not where a launch lands.
 *
 * They were on the mount path because they sat in the same function as the credential read
 * that genuinely has to happen first. That cost 2 IPC round-trips per configured node before
 * anything was on screen — each one re-reading and decrypting the whole store file, serialised
 * behind `STORE_LOCK` on the Rust side — plus one more for the protection level. On a machine
 * with a handful of nodes that is hundreds of milliseconds of empty window, which is exactly
 * what showing the window only after mount is trying to avoid.
 *
 * A mask is empty until this runs, which is what a page falling back to it already handles: see
 * `connectionMask`. Nothing was reading it before, because nothing was painted before either.
 */
export async function initConfigStoreDeferred(): Promise<void> {
  await refreshConnectionMasks(config.nodes);

  try {
    credentialProtection.level = await credentialStoreStatus();
  } catch (error) {
    // Leaves it `null`, and the settings page says the level is unknown rather than claiming
    // the keychain case it cannot confirm.
    console.error('[config] failed to read the credential store status:', error);
  }
}

let saveTimer: ReturnType<typeof setTimeout> | undefined;

watch(
  () => ({ ...config }),
  (next) => {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => persist(next as ProxyConfig), SAVE_DEBOUNCE_MS);
  },
  { deep: true },
);

export function useConfigStore() {
  /**
   * Applies a change to the configuration.
   *
   * The relay is not written through here: a token belongs to the relay it
   * was issued for, and an assignment that said nothing about the token
   * carried it over to whatever relay came next. The relay has its own
   * setters, which say what happens to the token — see `setRelayUrl`.
   */
  function updateConfig(updates: Partial<ProxyConfig>): void {
    const next = { ...updates };
    const mode = next.relayMode;
    const url = next.relayUrl;
    const token = next.relayAuthToken;
    delete next.relayMode;
    delete next.relayUrl;
    delete next.relayAuthToken;
    // The relay a token was issued for is not written from outside either:
    // it is the answer to a question only this store can ask.
    delete next.relayAuthTokenRelay;

    Object.assign(config, next);
    if (mode !== undefined) setRelayMode(mode);
    if (url !== undefined) setRelayUrl(url);
    if (token !== undefined) setRelayAuthToken(token);
  }

  /** Sets the relay URL; the token goes with the relay it was issued for. */
  function setRelayUrl(url: string): void {
    writeRelayUrl(config, url);
  }

  /** Sets the relay mode; the relay and its token are left alone. */
  function setRelayMode(mode: RelayMode): void {
    writeRelayMode(config, mode);
  }

  /** Stores the token the user typed, bound to the relay it was typed for. */
  function setRelayAuthToken(token: string): void {
    writeRelayAuthToken(config, token);
  }

  /** The name this machine answers as; generated on first use. */
  async function ensureDeviceId(): Promise<string> {
    return ensureDeviceIdFor(config);
  }

  function setLoadBalancing(strategy: LoadBalancingStrategy): void {
    config.loadBalancing = strategy;
  }

  function resetConfig(): void {
    Object.assign(config, { ...defaultConfig, nodes: [], domains: [] });

    // Every node is gone, so every credential is: the store is cleared rather than left holding
    // secrets for nodes that no longer exist.
    void clearCredentials().catch((error: unknown) => {
      console.error('[config] failed to clear the credential store:', error);
    });
  }

  return {
    config,
    credentialProtection: computed(() => credentialProtection.level),
    /** The mask to print for a node's connection string. Empty when the store has not answered. */
    connectionMask: (nodeId: string): string => connectionMasks[nodeId] ?? '',
    /** The mask to print for a node's TOTP secret, same terms. */
    secretMask: (nodeId: string): string => secretMasks[nodeId] ?? '',
    updateConfig,
    setRelayUrl,
    setRelayMode,
    setRelayAuthToken,
    removeNode,
    updateNode,
    updateNodeDomains,
    ensureDeviceId,
    applyInvite,
    completeEnrollment,
    setNodeTwoFactor,
    clearNodeTwoFactor,
    hasTwoFactor,
    twoFactorState,
    setLoadBalancing,
    resetConfig,
  };
}
