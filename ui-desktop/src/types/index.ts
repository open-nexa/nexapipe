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

/**
 * The 2FA credentials one endpoint is reached with.
 *
 * Kept per node rather than once per client because every server has its own `[auth].clients`
 * entry: a single shared pair is what forced a second server to be given the first one's secret.
 * A node without credentials performs no handshake, which is also how one client mixes servers
 * that demand 2FA with ones that do not.
 */
export interface NodeTwoFactor {
  clientId: string;
  secret: string;
  algorithm: TwoFactorAlgorithm;
}

/**
 * A one-time enrollment token, which is what a `--registration` invite carries instead of a
 * secret.
 *
 * It is spent by the first connection that uses it — the server answers with the real
 * credential and rotates the client's secret in the same step — so a node holding a token is
 * a node that has not been issued credentials yet. Whatever comes back has to be written into
 * `twoFactor`: the token cannot be spent twice, so a restart that still only holds the invite
 * has nothing left to authenticate with.
 */
export interface EnrollmentToken {
  clientId: string;
  token: string;
}

/** What the server issued for a spent token: the credentials to keep from here on. */
export interface IssuedCredential {
  clientId: string;
  secret: string;
  algorithm: TwoFactorAlgorithm;
}

export interface NodeConfig {
  id: string;
  connectionType: ConnectionType;
  ticket: string;
  endpointId: string;
  domains: string[];
  /**
   * Cosmetic label, set only when the node came from an invite that named itself. Nothing routes
   * on it and it is never sent to the backend: the UI falls back to "Node N" when it is absent.
   */
  name?: string;
  /** Credentials for this endpoint alone. Absent means no handshake for this server. */
  twoFactor?: NodeTwoFactor;
  /**
   * A token to spend instead of presenting credentials. Cleared once the issued secret has
   * landed in `twoFactor`, so a node is never left holding both.
   */
  enrollment?: EnrollmentToken;
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
  /** Bearer token for a custom relay that requires one. */
  relayAuthToken: string;
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

/** How one configured node answered its last probe. Mirrors `NodeHealthStatus` in `src-tauri/src/status.rs`. */
export interface NodeHealth {
  /**
   * The ticket or endpoint ID exactly as the node was configured — the same key `EndpointLink`
   * carries, so a link and a health reading for one node can be paired.
   */
  connection: string;
  /** Whether it answered. False before the first probe has run: unasked means unanswered. */
  reachable: boolean;
  /** Probes in a row that have failed. Zero while it answers. */
  consecutiveFailures: number;
  /**
   * How long it has been down, in seconds. `null` while it answers, and `null` when it has
   * never answered — which is not "down for no time at all".
   */
  downForSecs: number | null;
  /** How long ago it was last probed, in seconds. `null` before the first probe. */
  sinceLastProbeSecs: number | null;
}

/**
 * The 2FA half of an invite *as it is shown*. Mirrors `InviteTotpPayload` in
 * `src-tauri/src/lib.rs`, which deliberately carries no secret: an invite is shown to be
 * recognised, and the secret stays a credential after the connection it authorises is set up.
 * `algorithm` is already lowercase, which is what a node's `twoFactor.algorithm` holds.
 */
export interface InviteTotp {
  clientId: string;
  algorithm: TwoFactorAlgorithm;
  issuer: string;
}

/**
 * The enrollment half of an invite *as it is shown*: which client the token is pending for, and
 * nothing else. The token itself never reaches the renderer — `acceptInvite` files it.
 */
export interface InviteEnrollment {
  clientId: string;
}

/**
 * A parsed `nexapipe://` invite. Mirrors `InvitePayload` in `src-tauri/src/lib.rs`, which gets it
 * from the one parser in `crates/nexapipe-client/src/provisioning.rs` — the UI never parses an
 * invite itself, so a code printed by the server reads the same here as it does on Android.
 *
 * Everything a surface could print, and nothing a surface should not: the connection string is
 * the mask Rust produced, and neither a TOTP secret nor an enrollment token is in here at all.
 */
export interface InvitePayload {
  /** `endpoint` for a bare Node ID, `ticket` for an address-bearing ticket. */
  kind: 'endpoint' | 'ticket';
  /** The Node ID, or the ticket, as `credentials::mask` renders it. */
  targetMasked: string;
  name?: string;
  domains: string[];
  relay?: string;
  totp?: InviteTotp;
  /**
   * A one-time enrollment token (`--registration` invites). Mutually exclusive with `totp`:
   * the parser refuses a code carrying both, so the UI never has to pick a winner.
   */
  enrollment?: InviteEnrollment;
}

/**
 * What `acceptInvite` answers: which node the invite belongs to, and everything about it that is
 * not a credential. Mirrors `InviteAccepted` in `src-tauri/src/lib.rs`.
 *
 * `nodeId` is an existing node's when one already held this connection string, so importing the
 * same invite twice tops a node up instead of adding a second one pointing at the same backend —
 * a comparison the renderer cannot make any more, because it no longer holds the string.
 */
export interface InviteAccepted {
  nodeId: string;
  /** `ticket` or `endpoint_id`, which is what `connectionType` calls them. */
  connectionType: ConnectionType;
  existing: boolean;
  name?: string;
  domains: string[];
  relay?: string;
  totp?: InviteTotp;
  enrollment?: InviteEnrollment;
}

/**
 * The credential door, as a surface sees it. Mirrors `gate::Status` in `src-tauri/src/gate.rs`.
 *
 * `msRemaining` is what lets the UI run its own countdown: the window is a duration rather than a
 * flag, so the page that drew it has to be the one that watches it run out.
 */
export interface GateStatus {
  /** Whether credentials may be shown right now. */
  unlocked: boolean;
  /** Milliseconds left in the window; zero when it is shut. */
  msRemaining: number;
  /** Whether this machine can confirm the user at all. */
  canAuthenticate: boolean;
  /** Whether the UI has to collect a password before it can ask. */
  needsPassword: boolean;
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
