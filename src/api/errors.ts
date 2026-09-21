/**
 * The frontend half of the error contract described in `src-tauri/src/error.rs`.
 *
 * Backend failures are structured `AppError` payloads (`{ code, detail? }`) rather than prose, so
 * the UI can translate them: `code` indexes `error.<code>` in the locale files, while `detail` is
 * a raw English diagnostic that belongs in the log (and, at most, behind a "technical details"
 * disclosure) — never in the headline message.
 *
 * Every constant in `src-tauri/src/error.rs` must appear in `ERROR_CODES` below and have a
 * matching `error.<code>` key in both locale files; `npm run lint:i18n` checks the key side, and
 * the plan's Phase 4 sweep covers the list side.
 */
import type { AppError } from '../types';

export const ERROR_CODES = [
  // proxy
  'proxy.no_nodes',
  'proxy.invalid_load_balancing',
  'proxy.start_failed',
  'proxy.no_reachable_backend',
  'proxy.two_factor_required',
  'proxy.not_running',
  'proxy.node_id_unavailable',
  'proxy.tun_unavailable',
  // service
  'service.unavailable',
  'service.io_error',
  'service.malformed_response',
  'service.legacy_failure',
  'service.failed',
  'service.command_failed',
  'service.install_failed',
  'service.uninstall_failed',
  'service.start_failed',
  'service.stop_failed',
  'service.definition_failed',
  'service.unsupported_platform',
  'service.exe_path',
  'service.elevation_denied',
  'service.elevation_incomplete',
  'service.elevation_unavailable',
  'service.elevation_failed',
  // IPC authentication
  'service.unauthorized',
  'service.ipc_token',
  'service.malformed_request',
  'service.local_addr_not_loopback',
  'service.dns_addr_outside_tun',
  // logs
  'logs.dir_unreadable',
  'logs.read_failed',
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

const KNOWN_CODES = new Set<string>(ERROR_CODES);

/**
 * Normalises anything a rejected `invoke()` can produce into an `AppError`.
 *
 * Tauri rejects with whatever the command returned, so in practice this is the structured
 * payload; older paths (and some plugin errors) still hand back a bare string, which is preserved
 * as `detail` with an unknown code so it at least reaches the log.
 */
export function toAppError(error: unknown): AppError | null {
  if (!error) return null;

  if (typeof error === 'string') {
    return { code: 'unknown', detail: error };
  }

  if (typeof error === 'object') {
    const candidate = error as Partial<AppError> & { message?: unknown };
    if (typeof candidate.code === 'string' && KNOWN_CODES.has(candidate.code)) {
      return {
        code: candidate.code,
        detail: typeof candidate.detail === 'string' ? candidate.detail : undefined,
      };
    }
    if (typeof candidate.message === 'string') {
      return {
        code: typeof candidate.code === 'string' ? candidate.code : 'unknown',
        detail: candidate.message,
      };
    }
  }

  return { code: 'unknown', detail: String(error) };
}

/**
 * The locale key to render for a failure. Known codes map onto `error.<code>`; anything else
 * falls back to the caller's key, which is the operation that failed ("starting the proxy") and
 * is always more useful than "unknown error".
 */
export function errorKey(error: unknown, fallbackKey = 'error.unknown'): string {
  const appError = toAppError(error);
  if (appError && KNOWN_CODES.has(appError.code)) {
    return `error.${appError.code}`;
  }
  return fallbackKey;
}

/** The raw diagnostic, for `console.error` and log lines. Empty when there is nothing to add. */
export function errorDetail(error: unknown): string {
  return toAppError(error)?.detail ?? '';
}
