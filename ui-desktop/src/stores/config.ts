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
 */
import { computed, reactive, watch } from 'vue';
import {
  clearCredentials,
  credentialDisplay,
  credentialStoreStatus,
  deleteCredential,
  getCredential,
  putCredential,
} from '../api/credentials';
import { acceptInvite } from '../api/invite';
import type {
  ConnectionType,
  EnrollmentToken,
  IssuedCredential,
  LoadBalancingStrategy,
  NodeConfig,
  NodeTwoFactor,
  PersistedConfig,
  ProxyConfig,
} from '../types';

const STORAGE_KEY = 'nexapipe.config';
const LEGACY_STORAGE_KEY = 'nexa-config';
const CONFIG_VERSION = 3;
const SAVE_DEBOUNCE_MS = 300;

/**
 * Whether a migrated legacy payload may be deleted yet.
 *
 * Now `true`: every page and component reads this store, and the second loader that used to read
 * `nexa-config` (`composables/useConfigStore.ts`) is gone, so the legacy key has no readers left.
 * It is deleted in the same commit that removed that loader — the copy is written first either
 * way, so an older build downgraded onto this one still finds its configuration (§5.7, R3).
 *
 * A function rather than a `const`, because a constant `false` makes the branch unreachable to
 * TypeScript and turns the constant itself into an unused-local error.
 */
function dropLegacyKey(): boolean {
  return true;
}

export function generateNodeId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

const defaultConfig: ProxyConfig = {
  nodes: [],
  domains: [],
  localAddr: '127.0.0.1:8080',
  dnsAddr: '198.18.0.254:53',
  upstreamDns: '223.5.5.5:53',
  loadBalancing: 'round_robin',
  tunName: 'nexa-tun',
  useTun: false,
  useService: false,
  relayMode: 'pinned',
  relayUrl: '',
  relayAuthToken: '',
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

function asBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

/**
 * A node's 2FA credentials, or `undefined` when it has none — which is a node that performs no
 * handshake, not a node with blank credentials.
 */
function normalizeTwoFactor(raw: unknown): NodeTwoFactor | undefined {
  if (!isRecord(raw)) return undefined;
  const secret = asString(raw.secret, '').trim();
  const clientId = asString(raw.clientId, '');
  // A node whose secret lives in the credential store persists with an empty one: the stored
  // shape still says "this node authenticates, with this client id", and `initConfigStore` puts
  // the secret back. Dropping the whole structure here would turn a configured node into one
  // that performs no handshake until somebody re-entered its credentials.
  if (!secret && !clientId) return undefined;
  const algorithm =
    raw.algorithm === 'sha256' || raw.algorithm === 'sha512' ? raw.algorithm : 'sha1';
  return { clientId, secret, algorithm };
}

/**
 * A node's pending enrollment token, if it has one.
 *
 * A token with nothing in it is treated as no token at all: the server would refuse it, and a
 * node carrying an empty one would enroll instead of using the credentials it already has.
 */
function normalizeEnrollment(raw: unknown): EnrollmentToken | undefined {
  if (!isRecord(raw)) return undefined;
  const token = asString(raw.token, '').trim();
  const clientId = asString(raw.clientId, '');
  // Same reason as `normalizeTwoFactor`: a spent-or-stored token is an empty string here, and
  // the client id is what says which node is waiting for one.
  if (!token && !clientId) return undefined;
  return { clientId, token };
}

function normalizeNode(raw: unknown): NodeConfig | null {
  if (!isRecord(raw)) return null;
  const connectionType = raw.connectionType === 'endpoint_id' ? 'endpoint_id' : 'ticket';
  const twoFactor = normalizeTwoFactor(raw.twoFactor);
  const enrollment = normalizeEnrollment(raw.enrollment);
  // `name` is cosmetic but it is the label an invite gave itself; dropping it here would blank
  // every imported node's name on the next reload.
  const name = asString(raw.name, '').trim();
  return {
    id: asString(raw.id, '') || generateNodeId(),
    connectionType,
    ticket: asString(raw.ticket, ''),
    endpointId: asString(raw.endpointId, ''),
    domains: Array.isArray(raw.domains) ? raw.domains.filter((d) => typeof d === 'string') : [],
    ...(name ? { name } : {}),
    ...(twoFactor ? { twoFactor } : {}),
    ...(enrollment ? { enrollment } : {}),
  };
}

/**
 * Accepts both the current shape and the legacy flat payload and returns a complete
 * `ProxyConfig`. Unknown keys are dropped, missing keys fall back to the defaults, so a payload
 * written by an older build stays loadable.
 */
function normalizeConfig(raw: Record<string, unknown>): ProxyConfig {
  const config: ProxyConfig = { ...defaultConfig };

  if (Array.isArray(raw.nodes)) {
    config.nodes = raw.nodes.map(normalizeNode).filter((node): node is NodeConfig => node !== null);
    // A node with neither a ticket nor an endpoint ID routes nothing, but it is *not* dropped
    // here any more: from version 3 the connection string lives in the encrypted store, so a
    // payload that has just been read has none of them until the store has answered, and
    // dropping them at load time would delete every node on the second launch. See
    // `dropNodesWithoutAConnectionString`, which runs once the store has had its say.
  } else if (raw.connectionType || raw.ticket || raw.endpointId) {
    // Pre-nodes payload: a single connection lived at the top level.
    const node = normalizeNode({
      id: generateNodeId(),
      connectionType: asString(raw.connectionType, 'ticket'),
      ticket: raw.ticket,
      endpointId: raw.endpointId,
      domains: raw.domains,
    });
    if (node) config.nodes = [node];
  }

  if (Array.isArray(raw.domains)) {
    config.domains = raw.domains.filter((d): d is string => typeof d === 'string');
  }

  config.localAddr = asString(raw.localAddr, config.localAddr);
  config.dnsAddr = asString(raw.dnsAddr, config.dnsAddr);
  config.upstreamDns = asString(raw.upstreamDns, config.upstreamDns);
  config.tunName = asString(raw.tunName, config.tunName) || defaultConfig.tunName;
  config.relayUrl = asString(raw.relayUrl, config.relayUrl);
  config.relayAuthToken = asString(raw.relayAuthToken, config.relayAuthToken);

  if (raw.loadBalancing === 'random' || raw.loadBalancing === 'round_robin') {
    config.loadBalancing = raw.loadBalancing;
  }
  if (
    raw.relayMode === 'pinned' ||
    raw.relayMode === 'default' ||
    raw.relayMode === 'disabled' ||
    raw.relayMode === 'custom'
  ) {
    config.relayMode = raw.relayMode;
  }
  // 2FA used to be one global pair. It applied to every server, so the honest migration is to
  // copy it onto every node this payload had; a node that already carries its own keeps them.
  const legacyTwoFactor = normalizeTwoFactor({
    clientId: raw.twoFactorClientId,
    secret: raw.twoFactorSecret,
    algorithm: raw.twoFactorAlgorithm,
  });
  if (legacyTwoFactor) {
    for (const node of config.nodes) {
      if (!node.twoFactor) node.twoFactor = { ...legacyTwoFactor };
    }
  }

  // `useTun` is new in version 1 and defaults to off, so a payload written before the explicit
  // mode model keeps running in local proxy mode rather than suddenly claiming the tunnel.
  config.useTun = asBoolean(raw.useTun, defaultConfig.useTun);
  config.useService = asBoolean(raw.useService, config.useService);

  return config;
}

/**
 * Migration steps, ordered oldest first.
 *
 * Empty today — version 1 is the first versioned shape, and payloads that predate versioning are
 * handled by `normalizeConfig` (which tolerates the flat legacy object). Each future step takes
 * the shape it migrates *from*:
 *
 *   if (version < 2) { current = withClusterSettings(current); }
 *
 * Version 3 is deliberately not here either: no key moved, was renamed or changed type. It
 * stopped two *values* being written, and what happens to a payload that still carries them is
 * decided in `hydrateCredentials`, which is the only place that can see both the payload and the
 * store.
 */
function migrate(config: ProxyConfig, _fromVersion: number): ProxyConfig {
  return config;
}

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
function loadConfig(): ProxyConfig {
  const current = readJson(STORAGE_KEY);
  if (current) {
    const version = typeof current.version === 'number' ? current.version : CONFIG_VERSION;
    return migrate(normalizeConfig(current), version);
  }

  const legacy = readJson(LEGACY_STORAGE_KEY);
  if (legacy) {
    const migrated = migrate(normalizeConfig(legacy), 0);
    persist(migrated);
    if (dropLegacyKey()) removeKey(LEGACY_STORAGE_KEY);
    console.info('[config] migrated legacy nexa-config to version', CONFIG_VERSION);
    return migrated;
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
      const { twoFactor, enrollment, ...rest } = node;
      return {
        ...rest,
        ticket: '',
        endpointId: '',
        ...(twoFactor ? { twoFactor: { ...twoFactor, secret: '' } } : {}),
        ...(enrollment ? { enrollment: { ...enrollment, token: '' } } : {}),
      };
    }),
  };
}

/**
/**
 * Whether `hydrateCredentials` has finished.
 *
 * Until it has, every secret in the config is empty — not because the user cleared it, but because
 * nothing has read the store back yet. A mirror that ran inside that window would read the
 * emptiness as a deletion and drop credentials it has not read, and the store is the only copy.
 */
let credentialsHydrated = false;

/**
 * Mirrors the credentials into the encrypted store: written when a node has them, deleted when it
 * does not, so a credential that was cleared here is not left behind there.
 *
 * Gated on `credentialsHydrated`, because "cleared here" and "not read back yet" look the same in
 * `config` and only one of them is something the user did.
 */
async function persistCredentials(config: ProxyConfig): Promise<void> {
  if (!credentialsHydrated) {
    return;
  }

  if (config.relayAuthToken.trim()) {
    await putCredential('relay', config.relayAuthToken);
  } else {
    await deleteCredential('relay');
  }

  for (const node of config.nodes) {
    if (node.twoFactor?.secret.trim()) {
      await putCredential('totp', node.twoFactor.secret, node.id);
    } else {
      await deleteCredential('totp', node.id);
    }

    if (node.enrollment?.token.trim()) {
      await putCredential('enrollment', node.enrollment.token, node.id);
    } else {
      await deleteCredential('enrollment', node.id);
    }

    // Both spellings are mirrored, not just the one `connectionType` names: the
    // other one is what a node that was re-imported the other way round would
    // otherwise find still sitting in the store, and a stale connection string is
    // worse than none because it looks like the one to use.
    if (node.ticket.trim()) {
      await putCredential('ticket', node.ticket, node.id);
    } else {
      await deleteCredential('ticket', node.id);
    }

    if (node.endpointId.trim()) {
      await putCredential('endpoint', node.endpointId, node.id);
    } else {
      await deleteCredential('endpoint', node.id);
    }
  }
}

function persist(config: ProxyConfig): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(toPersisted(config)));
  } catch (error) {
    console.error('[config] failed to save:', error);
  }

  // Not awaited: a save is a mirror, and the in-memory config is what the app runs on. A failure
  // here means the credential will be missing after a restart, which is worth shouting about but
  // must not stop the app from working now.
  persistCredentials(config).catch((error: unknown) => {
    console.error('[config] failed to save credentials:', error);
  });
}

/**
 * Reads the credentials back into `config`, migrating anything `localStorage` still holds.
 *
 * A payload written before version 2 carries its secrets in the clear. This is where they leave:
 * the store wins when it has a value, and when it does not but the payload does, the payload's
 * value is *written* to the store rather than merely trusted — so the migration happens once and
 * the cleartext copy is gone on the next save.
 *
 * Returns a copy rather than filling `config` in place: each lookup awaits, and the config watcher
 * is live while they run, so a node-by-node fill would expose a config whose first node has been
 * read and whose second has not — and a save started there deletes the second node's credentials
 * as if the user had cleared them.
 */
async function hydrateCredentials(source: ProxyConfig): Promise<ProxyConfig> {
  const hydrated: ProxyConfig = {
    ...source,
    nodes: source.nodes.map((node) => ({ ...node })),
  };

  const relay = await getCredential('relay');
  if (relay) {
    hydrated.relayAuthToken = relay;
  } else if (hydrated.relayAuthToken.trim()) {
    await putCredential('relay', hydrated.relayAuthToken);
  }

  for (const node of hydrated.nodes) {
    const secret = await getCredential('totp', node.id);
    if (secret) {
      node.twoFactor = {
        clientId: node.twoFactor?.clientId ?? '',
        secret,
        algorithm: node.twoFactor?.algorithm ?? 'sha1',
      };
    } else if (node.twoFactor?.secret.trim()) {
      await putCredential('totp', node.twoFactor.secret, node.id);
    }

    const token = await getCredential('enrollment', node.id);
    if (token) {
      node.enrollment = { clientId: node.enrollment?.clientId ?? '', token };
    } else if (node.enrollment?.token.trim()) {
      await putCredential('enrollment', node.enrollment.token, node.id);
    }

    // The store wins, and a payload that still carries the connection string has it
    // written rather than merely trusted — that is the version 3 migration, and it
    // is the reason a node's connection string is empty in the payload from now on.
    const ticket = await getCredential('ticket', node.id);
    if (ticket) {
      node.ticket = ticket;
    } else if (node.ticket.trim()) {
      await putCredential('ticket', node.ticket, node.id);
    }

    const endpointId = await getCredential('endpoint', node.id);
    if (endpointId) {
      node.endpointId = endpointId;
    } else if (node.endpointId.trim()) {
      await putCredential('endpoint', node.endpointId, node.id);
    }
  }

  return hydrated;
}

/**
 * Drops nodes that have nothing to connect with, once the credential store has answered.
 *
 * This used to happen while the payload was being read, which cannot work from version 3: the
 * connection string is in the store, so every node looks empty at that point and the second
 * launch would delete all of them. It happens here instead — after `hydrateCredentials`, and
 * only on the path where that succeeded, because a store that could not be read must not look
 * like a user who deleted every node.
 */
function dropNodesWithoutAConnectionString(nodes: NodeConfig[]): NodeConfig[] {
  return nodes.filter((node) => {
    if (node.ticket.trim() !== '' || node.endpointId.trim() !== '') return true;
    console.warn(
      '[config] dropping a node with no connection string in the payload or the credential store:',
      node.id,
    );
    return false;
  });
}

/**
 * Completes loading the configuration: everything except the credentials is already in `config`
 * by the time this module is imported, and the credentials are read here because reading them is
 * asynchronous.
 *
 * Awaited before the app mounts, so no page ever renders a node's credentials as absent and then
 * fills them in.
 */
export async function initConfigStore(): Promise<void> {
  try {
    // Assigned once, rather than filled in as each lookup returns: see
    // `hydrateCredentials`.
    Object.assign(config, await hydrateCredentials(config));

    // Now, and only now, that the store has answered: see
    // `dropNodesWithoutAConnectionString`.
    config.nodes = dropNodesWithoutAConnectionString(config.nodes);
    await refreshConnectionMasks();

    // Only from here may a save touch the store. Nothing before this line has
    // read it, so nothing before this line may delete from it — a failure
    // above leaves the secrets in `config` empty, and an ungated mirror would
    // empty the store to match.
    credentialsHydrated = true;
  } catch (error) {
    // A store that cannot be read leaves the nodes without credentials: they will refuse to
    // handshake and the UI says so. Not fatal — the app has to stay usable enough to re-import
    // an invite. `credentialsHydrated` stays false, so the next save writes
    // `localStorage` and leaves the store alone.
    console.error('[config] failed to load credentials:', error);
  }

  try {
    credentialProtection.level = await credentialStoreStatus();
  } catch (error) {
    // Leaves it `null`, and the settings page says the level is unknown rather than claiming
    // the keychain case it cannot confirm.
    console.error('[config] failed to read the credential store status:', error);
  }
}

const config = reactive<ProxyConfig>(loadConfig());

/**
 * Where the credential store's master key ended up: `"keychain"`, or `"file"` when no keychain
 * would take it — a headless Linux session with no Secret Service, a keychain that refused the
 * app. The credentials are encrypted either way, so this is information rather than a warning:
 * what changes is who holds the key, and the user is the one who should know.
 *
 * `null` until startup has asked. Read once there, because it cannot change while the app runs.
 */
const credentialProtection = reactive<{ level: string | null }>({ level: null });

/**
 * What a surface may print for a node's connection string: the mask Rust produced, keyed by node.
 *
 * The value itself is here too — `start_proxy` takes it as an argument, so the renderer has not
 * stopped holding it — but nothing renders it. Asking Rust for the mask rather than shortening
 * what is already in memory is the difference: a mask the renderer computes is not one, because
 * the thing it computed it from is one devtools panel away.
 *
 * Empty until the store has been asked, which is why a page falling back to it shows nothing
 * rather than a value of its own.
 */
const connectionMasks = reactive<Record<string, string>>({});

/** The same, for the TOTP secret a node authenticates with. */
const secretMasks = reactive<Record<string, string>>({});

async function refreshConnectionMasks(): Promise<void> {
  const shown = await Promise.all(
    config.nodes.map(async (node) => {
      const connection = node.connectionType === 'ticket' ? 'ticket' : 'endpoint';
      const [target, secret] = await Promise.all([
        credentialDisplay(connection, node.id).catch((error: unknown) => {
          console.error('[config] failed to read a connection string for display:', error);
          return null;
        }),
        credentialDisplay('totp', node.id).catch((error: unknown) => {
          console.error('[config] failed to read a secret for display:', error);
          return null;
        }),
      ]);
      return [node.id, target ?? '', secret ?? ''] as const;
    }),
  );

  for (const [id, target, secret] of shown) {
    connectionMasks[id] = target;
    secretMasks[id] = secret;
  }
  // A node that is gone takes its masks: leaving them would keep a projection of
  // credentials nothing is connecting to any more.
  for (const id of Object.keys(connectionMasks)) {
    if (!config.nodes.some((node) => node.id === id)) delete connectionMasks[id];
  }
  for (const id of Object.keys(secretMasks)) {
    if (!config.nodes.some((node) => node.id === id)) delete secretMasks[id];
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
  function updateConfig(updates: Partial<ProxyConfig>): void {
    Object.assign(config, updates);
  }

  /**
   * Creates a node. Private on purpose: a node is something an invite brings, so there is no
   * longer any code path that can add an empty one (the old `addNode()` used to be wired to a
   * button on the Config page).
   */
  function createNode(node: Partial<NodeConfig> & { connectionType: ConnectionType }): NodeConfig {
    const created: NodeConfig = {
      id: node.id || generateNodeId(),
      connectionType: node.connectionType,
      ticket: node.ticket ?? '',
      endpointId: node.endpointId ?? '',
      domains: node.domains ? [...node.domains] : [],
      ...(node.name ? { name: node.name } : {}),
      ...(node.twoFactor ? { twoFactor: node.twoFactor } : {}),
    };
    config.nodes.push(created);
    return created;
  }

  /**
   * Applies a parsed invite: one node carrying its target and domains, plus the two settings an
   * invite reaches that are *not* per-node — the relay and the 2FA credentials.
   *
   * An endpoint already in the list is reused instead of duplicated: a second node pointing at
   * the same backend would only split traffic between two identical entries, and importing the
   * same invite twice (or a newer one for the same server) is meant to top up its domains.
   *
   * The invite's relay is *not* applied unless the caller opts in: the relay is a global setting,
   * so adopting it silently would repoint every other node's home relay on the strength of one
   * invite. It says how that endpoint is reachable, not what this machine should use.
   *
   * Returns which of the two happened, so the caller can say so.
   */
  async function applyInvite(
    uri: string,
    options: { applyRelay?: boolean } = {},
  ): Promise<'added' | 'merged'> {
    // The credentials go into the store before this returns, and the call answers which node they
    // were filed under: a parsed invite no longer carries a connection string or a secret, so the
    // comparison that decides "new node or an existing one" is made where the values are.
    const accepted = await acceptInvite(uri);

    const name = accepted.name?.trim() || undefined;
    let outcome: 'added' | 'merged';
    let node: NodeConfig | undefined = config.nodes.find((n) => n.id === accepted.nodeId);

    if (node) {
      outcome = 'merged';
      // A name already typed here wins: it is the label the user chose for this endpoint.
      if (name && !node.name) node.name = name;
    } else {
      node = createNode({
        id: accepted.nodeId,
        connectionType: accepted.connectionType,
        domains: [],
        ...(name ? { name } : {}),
      });
      outcome = 'added';
    }

    const domains = [...node.domains];
    for (const domain of accepted.domains) {
      if (!domains.includes(domain)) domains.push(domain);
    }
    node.domains = domains;

    if (accepted.relay && options.applyRelay) {
      config.relayMode = 'custom';
      config.relayUrl = accepted.relay;
    }

    // The credentials belong to the server this invite came from, so they land on its node and
    // nowhere else — a second server keeps whatever it was given before. What is set here is the
    // *shape*: the secret and the token are already in the store, and keeping them out of this
    // object is the whole point of `accept_invite`.
    if (accepted.totp) {
      node.twoFactor = {
        clientId: accepted.totp.clientId,
        secret: '',
        algorithm: accepted.totp.algorithm,
      };
      delete node.enrollment;
    }

    // A registration invite carries a token instead: it is spent on the next connection, which
    // answers with the secret this node is to keep. Stored on the node rather than applied to
    // `twoFactor` because a token is not a credential — writing it there would make the node
    // present the token as its TOTP secret and be refused.
    if (accepted.enrollment) {
      node.enrollment = { clientId: accepted.enrollment.clientId, token: '' };
      delete node.twoFactor;
    }

    // Read back the one credential the renderer still has to hold: `start_proxy` takes the
    // connection string as an argument, and the mirror below has to agree with the store or the
    // next save would delete what was just filed.
    const [ticket, endpointId] = await Promise.all([
      getCredential('ticket', node.id),
      getCredential('endpoint', node.id),
    ]);
    node.ticket = ticket ?? '';
    node.endpointId = endpointId ?? '';

    await refreshConnectionMasks();
    return outcome;
  }

  /**
   * Writes the credential a server issued for an enrollment token onto the node that spent it,
   * and clears the token.
   *
   * A token can only be spent once, so this is the only moment the secret exists on this side:
   * without it a restart falls back to the invite, which the server has already forgotten.
   * Returns the node it landed on, or `null` when no node was waiting for one — the credential
   * is then dropped rather than attached somewhere it does not belong.
   */
  function completeEnrollment(credential: IssuedCredential): NodeConfig | null {
    const node =
      config.nodes.find(
        (candidate) => candidate.enrollment?.clientId === credential.clientId,
      ) ?? config.nodes.find((candidate) => candidate.enrollment);
    if (!node) return null;

    node.twoFactor = {
      clientId: credential.clientId,
      secret: credential.secret,
      algorithm: credential.algorithm,
    };
    delete node.enrollment;
    return node;
  }

  /** Sets or replaces one node's 2FA credentials, leaving every other node alone. */
  function setNodeTwoFactor(nodeId: string, patch: Partial<NodeTwoFactor>): void {
    const node = config.nodes.find((candidate) => candidate.id === nodeId);
    if (!node) return;
    node.twoFactor = {
      clientId: patch.clientId ?? node.twoFactor?.clientId ?? '',
      secret: patch.secret ?? node.twoFactor?.secret ?? '',
      algorithm: patch.algorithm ?? node.twoFactor?.algorithm ?? 'sha1',
    };
  }

  /** Drops a node's credentials, which is what "this server has no 2FA" looks like. */
  function clearNodeTwoFactor(nodeId: string): void {
    const node = config.nodes.find((candidate) => candidate.id === nodeId);
    if (node) delete node.twoFactor;
    // The store is told as well: what is dropped here must not survive there.
    void deleteCredential('totp', nodeId).catch((error: unknown) => {
      console.error('[config] failed to delete the stored secret:', error);
    });
  }

  /** Whether a node would perform a handshake: credentials with a secret in them. */
  function hasTwoFactor(node: NodeConfig): boolean {
    return !!node.twoFactor && node.twoFactor.secret.trim() !== '';
  }

  function removeNode(nodeId: string): void {
    const index = config.nodes.findIndex((node) => node.id === nodeId);
    if (index !== -1) config.nodes.splice(index, 1);

    // A removed node takes its credentials with it. Done here rather than by sweeping the store
    // for orphans, because this is the only place a node stops existing.
    // The connection string goes too, from this change on: it is a credential here, so a node
    // that stops existing must not leave one behind under its id.
    void Promise.all([
      deleteCredential('totp', nodeId),
      deleteCredential('enrollment', nodeId),
      deleteCredential('ticket', nodeId),
      deleteCredential('endpoint', nodeId),
    ]).catch((error: unknown) => {
      console.error('[config] failed to delete the credentials of a removed node:', error);
    });
    void refreshConnectionMasks().catch((error: unknown) => {
      console.error('[config] failed to refresh the connection masks:', error);
    });
  }

  function updateNode(nodeId: string, updates: Partial<NodeConfig>): void {
    const node = config.nodes.find((candidate) => candidate.id === nodeId);
    if (node) Object.assign(node, updates);
  }

  /**
   * Deliberately absent: `updateConnectionString`.
   *
   * A node's target is whatever its invite named, and there is no longer a UI that retypes one —
   * the connection string is displayed with a reveal/copy affordance instead of edited. Keeping a
   * setter around would only invite the old free-text field back.
   */

  function updateNodeDomains(nodeId: string, domains: string[]): void {
    updateNode(nodeId, { domains });
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
    removeNode,
    updateNode,
    updateNodeDomains,
    applyInvite,
    completeEnrollment,
    setNodeTwoFactor,
    clearNodeTwoFactor,
    hasTwoFactor,
    setLoadBalancing,
    resetConfig,
  };
}
