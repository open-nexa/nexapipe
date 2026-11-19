/**
 * How a number is shown.
 *
 * The instance sends counts and byte totals; an operator reads them as
 * "12.3 MB" and "2 h 14 m". The formatting lives here so that every page
 * shows the same number the same way.
 */

/** A byte total, in the unit a human reads it in. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const rounded = unit === 0 ? String(Math.round(value)) : value.toFixed(1);
  return `${rounded} ${units[unit]}`;
}

/** A duration in seconds, as hours, minutes and seconds. */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const whole = Math.floor(seconds);
  const days = Math.floor(whole / 86_400);
  const hours = Math.floor((whole % 86_400) / 3_600);
  const minutes = Math.floor((whole % 3_600) / 60);
  const rest = whole % 60;

  if (days > 0) return `${days} d ${hours} h`;
  if (hours > 0) return `${hours} h ${minutes} m`;
  if (minutes > 0) return `${minutes} m ${rest} s`;
  return `${rest} s`;
}

/** A millisecond figure, in the unit a human reads it in. */
export function formatMilliseconds(milliseconds: number): string {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return '—';
  if (milliseconds < 1000) return `${Math.round(milliseconds)} ms`;
  return `${(milliseconds / 1000).toFixed(2)} s`;
}

/**
 * A timestamp, in the browser's own locale.
 *
 * The instance sends what it has — an RFC 3339 string or nothing — and the
 * console shows it as the browser reads it. A value that is not a date is
 * shown as it came, rather than as "Invalid Date".
 */
export function formatTimestamp(value: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}
