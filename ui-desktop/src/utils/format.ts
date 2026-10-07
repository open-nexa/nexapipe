/**
 * Byte counts and byte rates, as every screen in the app prints them.
 *
 * One implementation rather than one per page: a figure that is formatted two ways is a figure
 * the two pages will eventually disagree about, and "12.4 MiB" next to "13.0 MB" looks like two
 * different transfers.
 *
 * Binary units and not decimal ones — this is memory-and-wire arithmetic, and a KiB is what both
 * ends of the tunnel mean by it.
 */

/**
 * Bytes, at the largest unit that still leaves something to say.
 *
 * Three digits before the point is enough: a figure nobody is going to compare byte for byte does
 * not need five significant ones, and a row that has room for `3.4 MiB` has none for
 * `34.5678 MiB`.
 *
 * A rate can be asked for a number that is not one — nothing has been sampled yet, or the two
 * samples went backwards — and that is answered with a dash rather than with `NaN`, which is a
 * claim nobody made.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';

  if (bytes < 1024) return `${Math.floor(bytes)} B`;

  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }

  // One decimal while the number is small enough for it to mean something, whole otherwise.
  const scaled = value < 100 ? value.toFixed(1) : Math.round(value).toString();
  return `${scaled} ${units[unit]}`;
}

/** `formatBytes` with the per-second mark, for a rate rather than a total. */
export function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}
