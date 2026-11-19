/**
 * The one place the console talks to the instance.
 *
 * Three rules, and every request goes through here so that none of them can
 * be forgotten on one path:
 *
 *   1. **The admin token travels with every request.** The instance refuses a
 *      request to its API that carries none, so the console keeps the token
 *      the operator pasted and sends it as a bearer.
 *   2. **A write says it is a write.** The instance refuses a write that does
 *      not carry `X-NexaPipe-Admin: 1`, because a browser will not let a page
 *      on another origin add a custom header without asking the server first,
 *      and the server answers no such ask.
 *   3. **Nothing else is sent.** No cookies, no credentials of the page's own
 *      — the token is the whole of the authority, and the instance's own rule
 *      is that the request has to have been addressed to a loopback host.
 */
import { useTokenStore } from '../stores/token';

/** The header the instance requires on a write. */
export const WRITE_HEADER = 'X-NexaPipe-Admin';

/** The value the instance expects in that header. */
export const WRITE_HEADER_VALUE = '1';

/** A failure the instance answered with. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: string,
  ) {
    super(body.trim() || `HTTP ${status}`);
    this.name = 'ApiError';
  }

  /** Whether the instance said the token was missing or wrong. */
  get unauthorized(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const { token } = useTokenStore();
  const headers = new Headers(init.headers);
  if (token.value) {
    headers.set('Authorization', `Bearer ${token.value}`);
  }

  const response = await fetch(path, { ...init, headers });
  const text = await response.text();
  if (!response.ok) {
    throw new ApiError(response.status, text);
  }
  if (!text) {
    return undefined as T;
  }
  return JSON.parse(text) as T;
}

/** Asks the instance a question. */
export function apiGet<T>(path: string): Promise<T> {
  return request<T>(path, { method: 'GET' });
}

/**
 * Asks the instance to change something.
 *
 * The write header is set here rather than at the call sites, because a call
 * site that forgets it produces a refusal the operator cannot explain.
 */
export function apiWrite<T>(
  path: string,
  method: 'POST' | 'DELETE',
  body?: unknown,
): Promise<T> {
  const headers = new Headers();
  headers.set(WRITE_HEADER, WRITE_HEADER_VALUE);
  headers.set('Content-Type', 'application/json');
  return request<T>(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** The path of the console's API, relative to the page's own origin. */
export const API = {
  status: '/api/status',
  routes: '/api/routes',
  clients: '/api/clients',
  connections: '/api/connections',
  health: '/api/health',
} as const;
