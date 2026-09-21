export type ConnectionType = 'ticket' | 'endpoint_id';

export type RelayMode = 'pinned' | 'default' | 'disabled' | 'custom';

export type LoadBalancingStrategy = 'round_robin' | 'random';

export type TwoFactorAlgorithm = 'sha1' | 'sha256' | 'sha512';

/**
 * How the proxy is forwarding traffic. Mirrors `ProxyModeKind` in `src-tauri/src/status.rs`,
 * serialized in snake_case; `starting` and `stopped` describe the absence of a live mode.
 */
export type ProxyMode = 'tun' | 'local_proxy' | 'starting' | 'stopped';

/**
 * What the service manager reports about the system service. Mirrors `ServiceState` in
 * `src-tauri/src/service/platform.rs`, serialized in snake_case. This is *not* the same question
 * as `is_service_running`, which asks whether the daemon answers on the IPC port: an installed but
 * unstarted service is `stopped`, not absent.
 */
export type ServiceState = 'not_installed' | 'stopped' | 'running';

export interface NodeConfig {
  id: string;
  connectionType: ConnectionType;
  ticket: string;
  endpointId: string;
  domains: string[];
}

export interface ProxyConfig {
  nodes: NodeConfig[];
  domains: string[];
  localAddr: string;
  dnsAddr: string;
  upstreamDns: string;
  loadBalancing: LoadBalancingStrategy;
  tunName: string;
  /**
   * Forwarding mode: `true` requests TUN, `false` the local proxy. TUN is gated on the service
   * being installed (see docs/ui-refactor-plan.md §5.12) and is never chosen implicitly.
   */
  useTun: boolean;
  /** Execution backend: in-process, or through the installed system service. */
  useService: boolean;
  relayMode: RelayMode;
  relayUrl: string;
  forceRelay: boolean;
  twoFactorEnabled: boolean;
  twoFactorClientId: string;
  twoFactorSecret: string;
  twoFactorAlgorithm: TwoFactorAlgorithm;
}

/** The persisted shape: user config plus the schema version the migration chain walks. */
export interface PersistedConfig extends ProxyConfig {
  version: number;
}

export interface ProxyStatus {
  running: boolean;
  mode: ProxyMode;
}

/**
 * How a node currently reaches its backend, as reported by iroh at runtime: `unknown` means
 * connected but no path selected yet.
 *
 * Deliberately *not* derived from the relay mode in the config, and not from the node being a
 * ticket either — those say what is allowed, this says what actually happened.
 */
export type LinkKind = 'direct' | 'relay' | 'unknown';

/** Mirrors `EndpointLink` in `src-tauri/src/status.rs`. */
export interface EndpointLink {
  /**
   * The ticket or endpoint ID exactly as the node was configured, so the UI can match a link to
   * the node it belongs to. A ticket is opaque here, so the resolved ID alone would not do.
   */
  connection: string;
  /** The backend's endpoint ID; a ticket resolves to the node it names. */
  endpointId: string;
  link: LinkKind;
}

/**
 * A failure crossing the Rust/frontend boundary, as produced by `AppError` in
 * `src-tauri/src/error.rs`. `code` is stable and is looked up as `error.<code>` in the locale
 * files; `detail` is a raw English diagnostic meant for the log, never the headline message.
 */
export interface AppError {
  code: string;
  detail?: string;
}
