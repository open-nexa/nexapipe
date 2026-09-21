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
  LoadBalancingStrategy,
  NodeConfig,
  PersistedConfig,
  ProxyConfig,
} from '../types';
import { detectConnectionType } from '../utils/connection';

const STORAGE_KEY = 'nexapipe.config';
const LEGACY_STORAGE_KEY = 'nexa-config';
const CONFIG_VERSION = 1;
const SAVE_DEBOUNCE_MS = 300;

/**
 * Whether a migrated legacy payload may be deleted yet.
 *
 * `false` while `composables/useConfigStore.ts` still reads `nexa-config` — that is, while the
 * un-migrated pages are still the ones writing the user's configuration. Deleting the key now
 * would silently reset the Config page to an empty node list and look like data loss, so the copy
 * is written and the original is left alone until the last reader is gone. Phase 3 flips this to
 * `true` in the same commit that deletes the old loader (§5.7, R3).
 *
 * A function rather than a `const`, because a constant `false` makes the branch unreachable to
 * TypeScript and turns the constant itself into an unused-local error.
 */
function dropLegacyKey(): boolean {
  return false;
}

export function generateNodeId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

const defaultConfig: ProxyConfig = {
  nodes: [],
  domains: [],
  localAddr: '127.0.0.1:8080',
  dnsAddr: '10.0.0.254:53',
  upstreamDns: '223.5.5.5:53',
  loadBalancing: 'round_robin',
  tunName: 'nexa-tun',
  useTun: false,
  useService: false,
  relayMode: 'pinned',
  relayUrl: '',
  forceRelay: false,
  twoFactorEnabled: false,
  twoFactorClientId: '',
  twoFactorSecret: '',
  twoFactorAlgorithm: 'sha1',
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

function normalizeNode(raw: unknown): NodeConfig | null {
  if (!isRecord(raw)) return null;
  const connectionType = raw.connectionType === 'endpoint_id' ? 'endpoint_id' : 'ticket';
  return {
    id: asString(raw.id, '') || generateNodeId(),
    connectionType,
    ticket: asString(raw.ticket, ''),
    endpointId: asString(raw.endpointId, ''),
    domains: Array.isArray(raw.domains) ? raw.domains.filter((d) => typeof d === 'string') : [],
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
  config.twoFactorClientId = asString(raw.twoFactorClientId, config.twoFactorClientId);
  config.twoFactorSecret = asString(raw.twoFactorSecret, config.twoFactorSecret);

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
  if (
    raw.twoFactorAlgorithm === 'sha1' ||
    raw.twoFactorAlgorithm === 'sha256' ||
    raw.twoFactorAlgorithm === 'sha512'
  ) {
    config.twoFactorAlgorithm = raw.twoFactorAlgorithm;
  }

  // `useTun` is new in version 1 and defaults to off, so a payload written before the explicit
  // mode model keeps running in local proxy mode rather than suddenly claiming the tunnel.
  config.useTun = asBoolean(raw.useTun, defaultConfig.useTun);
  config.useService = asBoolean(raw.useService, config.useService);
  config.forceRelay = asBoolean(raw.forceRelay, config.forceRelay);
  config.twoFactorEnabled = asBoolean(raw.twoFactorEnabled, config.twoFactorEnabled);

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

  function addNode(node?: Partial<NodeConfig>): NodeConfig {
    const newNode: NodeConfig = {
      id: node?.id || generateNodeId(),
      connectionType: node?.connectionType || 'ticket',
      ticket: node?.ticket || '',
      endpointId: node?.endpointId || '',
      domains: node?.domains || [],
    };
    config.nodes.push(newNode);
    return newNode;
  }

  function removeNode(nodeId: string): void {
    const index = config.nodes.findIndex((node) => node.id === nodeId);
    if (index !== -1) config.nodes.splice(index, 1);
  }

  function updateNode(nodeId: string, updates: Partial<NodeConfig>): void {
    const node = config.nodes.find((candidate) => candidate.id === nodeId);
    if (node) Object.assign(node, updates);
  }

  function updateConnectionString(nodeId: string, value: string): void {
    const node = config.nodes.find((candidate) => candidate.id === nodeId);
    if (!node) return;
    const info = detectConnectionType(value);
    node.connectionType = info.type;
    if (info.type === 'ticket') {
      node.ticket = info.value;
      node.endpointId = '';
    } else {
      node.endpointId = info.value;
      node.ticket = '';
    }
  }

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
    addNode,
    removeNode,
    updateNode,
    updateConnectionString,
    updateNodeDomains,
    setLoadBalancing,
    resetConfig,
  };
}
