/**
 * The shapes the instance's `/api/*` answers with.
 *
 * These mirror the JSON the admin listener builds: the same builders that
 * answer `/v1/status`, `/v1/routes`, `/v1/clients`, `/v1/connections` and
 * `/v1/health` answer the console's API, so the two doors read the same
 * document. A field that is `null` here is `null` there — "no value", not
 * "no such field".
 *
 * The server owns the truth. When a field is added there, it is added here
 * too; nothing in the console derives a value the server did not send.
 */

/** The `[auth]` half of the status: whether 2FA is on, and how many clients. */
export interface AuthView {
  enabled: boolean;
  clients: number;
}

/** The counters the instance keeps about itself. */
export interface InstanceStatus {
  version: string;
  uptime_seconds: number;
  connections: {
    total: number;
    active: number;
    direct: number;
    relayed: number;
    unknown: number;
  };
  requests: { class: string; count: number }[];
  request_duration_ms: number;
  traffic: {
    sent_bytes: number;
    received_bytes: number;
  };
  l4_flows: { proto: string; class: string; count: number }[];
  backends: { up: number; down: number };
  in_flight: number;
  routes: number;
  peers: number;
  auth: AuthView;
}

/** One backend of a route, and whether the last probe found it answering. */
export interface RouteBackend {
  url: string;
  healthy: boolean;
}

/** One route, as the instance is serving it right now. */
export interface Route {
  /**
   * The stable id a write or a removal names this row by: the fingerprint of
   * this row's identity. The instance answers with it, and the console hands
   * it back unchanged: two routes may share a host and a path, and the id is
   * what keeps them apart. It is not a position, so other rows changing does
   * not change it.
   */
  id: string;
  host_pattern: string;
  path_pattern: string | null;
  modes: string[];
  priority: number;
  /**
   * Whether anything probes this route's backends. `false` is not "unhealthy":
   * a passthrough backend speaks TLS and an L4 one speaks whatever the route
   * points at, so nothing marks them down.
   */
  health_checked: boolean;
  backends: RouteBackend[];
}

/** One client, and never its secret. */
export interface Client {
  id: string;
  has_secret: boolean;
  created_at: string | null;
  allow_hosts: string[] | null;
  allow_ports: number[] | null;
  allow_ports_strict: boolean | null;
  last_used: string | null;
  failed_attempts: number | null;
  locked_until: string | null;
  enrollment_failed_attempts: number | null;
  enrollment_locked_until: string | null;
  enrollment_pending: boolean;
}

/** One device of a client. The id is the fingerprint of the key it proves itself with. */
export interface ClientDevice {
  id: string;
  has_secret: boolean;
  created_at: string | null;
  last_used: string | null;
}

/** One peer being served right now. */
export interface Connection {
  endpoint_id: string;
  client_id: string | null;
  device: string | null;
  connected_for_seconds: number;
  path: 'direct' | 'relayed' | 'unknown';
}

/** One route's backends, counted in and out of rotation. */
export interface HealthEntry {
  host_pattern: string;
  backends: RouteBackend[];
}

/** The answers, as the endpoints hand them over. */
export interface StatusAnswer {
  status: InstanceStatus;
}
export interface RoutesAnswer {
  routes: Route[];
}
export interface ClientsAnswer {
  enabled: boolean;
  clients: Client[];
}
export interface ConnectionsAnswer {
  peers: Connection[];
}
export interface HealthAnswer {
  health: HealthEntry[];
}

/** What a write asks for. */
export interface ClientRequest {
  client_id: string;
  device?: string;
  public_key?: string;
  force?: boolean;
}

/**
 * What a route write asks for.
 *
 * The keys are the configuration's own: a route is written in the
 * configuration's spelling, and the instance refuses a key that is not one of
 * them. The priority is not among them — the server derives it from the host
 * pattern — so the console does not offer it.
 */
export interface RouteRequest {
  host_pattern: string;
  path_pattern?: string | null;
  backends?: string[];
  modes?: string[];
  /** The stable id of the row this write replaces, when it is an edit of one
   * the route list already shows. Absent means an add. */
  replace?: string | null;
}
