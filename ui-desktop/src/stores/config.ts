/**
 * Persisted user configuration, plus the migration chain that gets old payloads here.
 *
 * Module-singleton composable rather than Pinia, consistent with the self-built decision
 * (docs/ui-refactor-plan.md §5.7). The split is by concern: this store owns what the *user*
 * configured and persists it; `proxy.ts` owns runtime status; `prefs.ts` owns UI preferences.
 *
 * Persistence is versioned (D11): `nexa-config` held a flat object with no version field, so
 * migrations could not be sequenced. The current shape is `{ version: 1, ...config }` under
 * `nexapipe.config`, and each future migration is a `from -> to` step in `migrate()`.
 */
import { reactive, watch } from 'vue';
import type {
  ConnectionType,
  InvitePayload,
  LoadBalancingStrategy,
  NodeConfig,
  NodeTwoFactor,
  PersistedConfig,
  ProxyConfig,
} from '../types';

const STORAGE_KEY = 'nexapipe.config';
const LEGACY_STORAGE_KEY = 'nexa-config';
const CONFIG_VERSION = 1;
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
  if (!secret) return undefined;
  const algorithm =
    raw.algorithm === 'sha256' || raw.algorithm === 'sha512' ? raw.algorithm : 'sha1';
  return { clientId: asString(raw.clientId, ''), secret, algorithm };
}

function normalizeNode(raw: unknown): NodeConfig | null {
  if (!isRecord(raw)) return null;
  const connectionType = raw.connectionType === 'endpoint_id' ? 'endpoint_id' : 'ticket';
  const twoFactor = normalizeTwoFactor(raw.twoFactor);
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
    config.nodes = raw.nodes
      .map(normalizeNode)
      .filter((node): node is NodeConfig => node !== null)
      // A node with neither a ticket nor an endpoint ID routes nothing and is dropped by the
      // backend at start-up, so it is dropped here too. They can only be left over from the
      // "Add Node" button that created an empty row to be filled in by hand: nodes now come from
      // invites, which always carry a connection string. Dropping them at load rather than
      // hiding them in the UI keeps the stored config, the node count and what actually
      // connects in agreement, and stops the placeholder being written back on every save.
      .filter((node) => node.ticket.trim() !== '' || node.endpointId.trim() !== '');
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

function persist(config: ProxyConfig): void {
  const payload: PersistedConfig = { version: CONFIG_VERSION, ...config };
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
  } catch (error) {
    console.error('[config] failed to save:', error);
  }
}

const config = reactive<ProxyConfig>(loadConfig());

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
  function applyInvite(
    invite: InvitePayload,
    options: { applyRelay?: boolean } = {},
  ): 'added' | 'merged' {
    const connectionType: ConnectionType =
      invite.kind === 'ticket' ? 'ticket' : 'endpoint_id';
    const existing = config.nodes.find(
      (node) =>
        node.connectionType === connectionType &&
        (connectionType === 'ticket' ? node.ticket : node.endpointId) === invite.target,
    );

    const name = invite.name?.trim() || undefined;
    let outcome: 'added' | 'merged';
    let node: NodeConfig;

    if (existing) {
      node = existing;
      outcome = 'merged';
      // A name already typed here wins: it is the label the user chose for this endpoint.
      if (name && !node.name) node.name = name;
    } else {
      node = createNode({
        connectionType,
        ticket: connectionType === 'ticket' ? invite.target : '',
        endpointId: connectionType === 'endpoint_id' ? invite.target : '',
        domains: [],
        ...(name ? { name } : {}),
      });
      outcome = 'added';
    }

    const domains = [...node.domains];
    for (const domain of invite.domains) {
      if (!domains.includes(domain)) domains.push(domain);
    }
    node.domains = domains;

    if (invite.relay && options.applyRelay) {
      config.relayMode = 'custom';
      config.relayUrl = invite.relay;
    }

    // The credentials belong to the server this invite came from, so they land on its node and
    // nowhere else — a second server keeps whatever it was given before.
    if (invite.totp) {
      node.twoFactor = {
        clientId: invite.totp.clientId,
        secret: invite.totp.secret,
        algorithm: invite.totp.algorithm,
      };
    }

    return outcome;
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
  }

  /** Whether a node would perform a handshake: credentials with a secret in them. */
  function hasTwoFactor(node: NodeConfig): boolean {
    return !!node.twoFactor && node.twoFactor.secret.trim() !== '';
  }

  function removeNode(nodeId: string): void {
    const index = config.nodes.findIndex((node) => node.id === nodeId);
    if (index !== -1) config.nodes.splice(index, 1);
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
  }

  return {
    config,
    updateConfig,
    removeNode,
    updateNode,
    updateNodeDomains,
    applyInvite,
    setNodeTwoFactor,
    clearNodeTwoFactor,
    hasTwoFactor,
    setLoadBalancing,
    resetConfig,
  };
}
