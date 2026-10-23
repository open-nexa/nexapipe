/**
 * The shape of the configuration, and the defaults it starts from.
 *
 * Two halves, and they answer different questions. The defaults are what a
 * configuration looks like when the user has said nothing: an empty node list,
 * the machine's own DNS left alone, the tunnel off. The normalizers are what a
 * payload that *has* been written looks like when it is read back: every key
 * checked, every unknown key dropped, every missing key filled in from the
 * defaults, so a payload written by an older build stays loadable.
 *
 * The types are the ones in `../../types`; nothing here knows about the
 * credential store, about the relay or about `localStorage`.
 */
import type {
  EnrollmentToken,
  NodeConfig,
  NodeTwoFactor,
  ProxyConfig,
} from '../../types';

export const defaultConfig: ProxyConfig = {
  nodes: [],
  domains: [],
  localAddr: '127.0.0.1:8080',
  dnsAddr: '198.18.0.254:53',
  upstreamDns: '223.5.5.5:53',
  // The machine's DNS is left alone except for the configured domains, unless the
  // user says otherwise. This is the strategy that leaves the machine's own names —
  // and another tunnel's — resolving where they always did.
  dnsStrategy: 'scoped',
  loadBalancing: 'round_robin',
  tunName: 'nexa-tun',
  useTun: false,
  useService: false,
  relayMode: 'pinned',
  relayUrl: '',
  relayAuthToken: '',
  relayAuthTokenRelay: '',
  deviceId: '',
};

export function generateNodeId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
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
  const device = asString(raw.device, '').trim();
  return { clientId, secret, algorithm, ...(device ? { device } : {}) };
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
  const device = asString(raw.device, '').trim();
  return { clientId, token, ...(device ? { device } : {}) };
}

function normalizeNode(raw: unknown): NodeConfig | null {
  if (!isRecord(raw)) return null;
  const connectionType = raw.connectionType === 'endpoint_id' ? 'endpoint_id' : 'ticket';
  const twoFactor = normalizeTwoFactor(raw.twoFactor);
  const enrollment = normalizeEnrollment(raw.enrollment);
  // `name` is cosmetic but it is the label an invite gave itself; dropping it here would blank
  // every imported node's name on the next reload.
  const name = asString(raw.name, '').trim();
  // The device key and its public half. The private one is a credential and is
  // stripped from the persisted shape, so it is normally empty here and comes
  // back from the encrypted store; the public one is not a secret and stays.
  const deviceKey = asString(raw.deviceKey, '').trim();
  const publicKey = asString(raw.publicKey, '').trim();
  return {
    id: asString(raw.id, '') || generateNodeId(),
    connectionType,
    ticket: asString(raw.ticket, ''),
    endpointId: asString(raw.endpointId, ''),
    domains: Array.isArray(raw.domains) ? raw.domains.filter((d) => typeof d === 'string') : [],
    ...(name ? { name } : {}),
    ...(twoFactor ? { twoFactor } : {}),
    ...(enrollment ? { enrollment } : {}),
    ...(deviceKey ? { deviceKey } : {}),
    ...(publicKey ? { publicKey } : {}),
  };
}

/**
 * Accepts both the current shape and the legacy flat payload and returns a complete
 * `ProxyConfig`. Unknown keys are dropped, missing keys fall back to the defaults, so a payload
 * written by an older build stays loadable.
 */
export function normalizeConfig(raw: Record<string, unknown>): ProxyConfig {
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
  // Only the three spellings there are. A payload carrying anything else falls back to
  // the default rather than to a strategy nobody chose: this setting says what happens
  // to the machine's name resolution, and a typo must not be read as "replace all of it".
  if (raw.dnsStrategy === 'scoped' || raw.dnsStrategy === 'global' || raw.dnsStrategy === 'none') {
    config.dnsStrategy = raw.dnsStrategy;
  }
  config.tunName = asString(raw.tunName, config.tunName) || defaultConfig.tunName;
  config.relayUrl = asString(raw.relayUrl, config.relayUrl);
  // Empty is the state before it has been generated, not a name: `ensureDeviceId` fills it
  // in on the first run and a payload that never had one is a payload from before devices.
  config.deviceId = asString(raw.deviceId, '').trim();
  config.relayAuthToken = asString(raw.relayAuthToken, config.relayAuthToken);
  // The relay a stored token was issued for. A payload written before the
  // pairing existed carries no such thing, and the token in it is bound to
  // the relay the configuration names — see `hydrateCredentials`.
  config.relayAuthTokenRelay = asString(raw.relayAuthTokenRelay, config.relayAuthTokenRelay);

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
export function migrate(config: ProxyConfig, _fromVersion: number): ProxyConfig {
  return config;
}
