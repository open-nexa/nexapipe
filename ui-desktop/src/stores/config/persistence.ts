/**
 * What goes to disk, and what comes back.
 *
 * The configuration is persisted in `localStorage` under `nexapipe.config`, as
 * `{ version: 3, ...config }` — versioned (D11), because `nexa-config` held a
 * flat object with no version field and migrations could not be sequenced.
 * The payload is redacted on the way out: the credentials are not written
 * here, they live in the encrypted store.
 *
 * The legacy key is read here too, and dropped here — once the current shape
 * has been written and read back, which is the only moment at which the copy
 * it replaces can be proved redundant.
 */
import type { PersistedConfig, ProxyConfig } from '../../types';
import { hasHydratedCredentials, persistCredentials } from './credentials';
import { defaultConfig, isRecord, migrate, normalizeConfig } from './schema';

const STORAGE_KEY = 'nexapipe.config';
const LEGACY_STORAGE_KEY = 'nexa-config';
const CONFIG_VERSION = 3;
export const SAVE_DEBOUNCE_MS = 300;

/**
 * Whether a migrated legacy payload may be deleted yet.
 *
 * Now `true`: every page and component reads this store, and the second loader that used to read
 * `nexa-config` (`composables/useConfigStore.ts`) is gone, so the legacy key has no readers left.
 *
 * `true` is *whether it may go*, not *when*: the copy is written first either way, so an older
 * build downgraded onto this one still finds its configuration (§5.7, R3). The moment it goes is
 * decided in `initConfigStore`, which is the first place that can prove a current-shaped payload
 * exists.
 *
 * A function rather than a `const`, because a constant `false` makes the branch unreachable to
 * TypeScript and turns the constant itself into an unused-local error.
 */
function dropLegacyKey(): boolean {
  return true;
}

/**
 * Whether a legacy payload was read and its key is still awaiting deletion.
 *
 * Set by `loadConfig`, which cannot delete it: see the comment there. It is cleared once
 * `initConfigStore` has written a current-shaped payload and read it back, and it stays set if
 * hydration failed, so the next launch reads the legacy payload again rather than finding
 * neither copy.
 */
let legacyKeyDropPending = false;

function readJson(key: string): Record<string, unknown> | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    return isRecord(parsed) ? parsed : null;
  } catch (error) {
    console.error(`[config] failed to parse localStorage["${key}"]:`, error);
    return null;
  }
}

function removeKey(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch (error) {
    console.error(`[config] failed to remove localStorage["${key}"]:`, error);
  }
}

/**
 * Read order, first hit wins:
 *   `nexapipe.config` — current shape, carries `{ version, ... }`
 *   `nexa-config`  — legacy; copied into the current shape as version 1. Never overwrite
 *                       anything when the current key already exists, so a downgrade-then-upgrade
 *                       cycle cannot lose data (R3). See `dropLegacyKey` for why the legacy key
 *                       survives the migration in this phase.
 */
export function loadConfig(): ProxyConfig {
  const current = readJson(STORAGE_KEY);
  if (current) {
    const version = typeof current.version === 'number' ? current.version : CONFIG_VERSION;
    return migrate(normalizeConfig(current), version);
  }

  const legacy = readJson(LEGACY_STORAGE_KEY);
  if (legacy) {
    // Neither written nor dropped here. This runs while the module is being
    // imported, which is before `initConfigStore` has read the credential store,
    // and a save made before that read is deliberately a no-op — see `persist`.
    // Deleting the legacy key at this point would therefore remove the only
    // durable copy the configuration has without ever writing its replacement.
    // Both happen in `initConfigStore`, once hydration has succeeded.
    legacyKeyDropPending = true;
    return migrate(normalizeConfig(legacy), 0);
  }

  return { ...defaultConfig };
}

/**
 * The shape that goes into `localStorage`: everything except the credentials.
 *
 * A node keeps its credential *structure* — that it has 2FA, with which client id and algorithm,
 * and which spelling of connection string it uses — because those are configuration, and a node
 * with none is a node that performs no handshake. The secret and the connection string
 * themselves do not: they belong to the encrypted store, and leaving them here would keep the
 * copies this whole change is about removing.
 */
function toPersisted(config: ProxyConfig): PersistedConfig {
  return {
    version: CONFIG_VERSION,
    ...config,
    relayAuthToken: '',
    nodes: config.nodes.map((node) => {
      const { twoFactor, enrollment, deviceKey, ...rest } = node;
      return {
        ...rest,
        ticket: '',
        endpointId: '',
        // The device key is a credential: it lives in the encrypted store, and
        // the copy that would be left here is the one thing an attacker would
        // want. The public half is not — the server holds it too — so it stays.
        deviceKey: '',
        ...(twoFactor ? { twoFactor: { ...twoFactor, secret: '' } } : {}),
        ...(enrollment ? { enrollment: { ...enrollment, token: '' } } : {}),
      };
    }),
  };
}

export function persist(config: ProxyConfig): void {
  // The redaction in `toPersisted` is only honest once the store has answered:
  // it blanks the connection strings on the way out because they are supposed
  // to have been filed in the encrypted store by then. When hydration failed
  // they have not been, and `localStorage` may still be holding the only copy —
  // a version-2 payload written before this migration. Writing over it there
  // loses the node, and the mirror below is gated for the same reason, so
  // nothing would have taken its place. Leave the stored payload alone until
  // the store has been read; losing an edit is recoverable, losing a node is
  // an invite the user has to go and find again.
  if (hasHydratedCredentials()) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(toPersisted(config)));
    } catch (error) {
      console.error('[config] failed to save:', error);
    }
  }

  // Not awaited: a save is a mirror, and the in-memory config is what the app runs on. A failure
  // here means the credential will be missing after a restart, which is worth shouting about but
  // must not stop the app from working now.
  persistCredentials(config).catch((error: unknown) => {
    console.error('[config] failed to save credentials:', error);
  });
}

/**
 * Drops the legacy key, now that the current shape has been written.
 *
 * The legacy key goes only because it can be proved redundant: `persist` swallows a write
 * failure, so the payload is read back rather than trusted. A save that did not happen must not
 * cost the user the copy it was meant to replace.
 */
export function dropLegacyKeyIfRedundant(config: ProxyConfig): void {
  if (legacyKeyDropPending && dropLegacyKey()) {
    persist(config);
    if (readJson(STORAGE_KEY)) {
      removeKey(LEGACY_STORAGE_KEY);
      legacyKeyDropPending = false;
      console.info('[config] migrated legacy nexa-config to version', CONFIG_VERSION);
    }
  }
}
