/**
 * Start-up timing.
 *
 * The window is created hidden and shown by [`showWindow`] in `main.ts`, so the time a user
 * waits before anything appears is exactly the time the code before that point takes — and
 * which of those steps it is spent on is not something anyone can guess from the outside.
 * This measures it: `mark` records a moment, `flushStartupTiming` hands the whole series to
 * the backend, which writes it to the log file next to its own timings.
 *
 * Two clocks have to be read together to say where the time went, because neither side sees
 * the other's start:
 *
 *   - the webview's, which begins at the document navigation and is what every `ms` here is
 *     measured from — `performance.now()` is already relative to it
 *   - the backend's, which begins when the Rust process does and is logged as
 *     `process start -> report received`
 *
 * The difference between the last mark and that backend figure is the part neither clock
 * covers: process start up to the document navigation, which is the binary loading, the
 * runtime coming up and the webview being created.
 *
 * Marks are collected and sent once, after the window is up: nothing here is on the path to
 * the first paint, and a backend that cannot be reached — `vite dev` in a plain browser —
 * costs a console warning and nothing else.
 */
import { invoke } from '@tauri-apps/api/core';

export interface StartupMark {
  label: string;
  ms: number;
}

const marks: StartupMark[] = [];

/**
 * Records `label` as having been reached now.
 *
 * Ordered by insertion rather than by `ms`: two marks taken in the same millisecond still
 * happened in the order they were recorded, and sorting by value would let them swap.
 */
export function mark(label: string): void {
  marks.push({ label, ms: performance.now() });
}

/**
 * The moments no `mark` call can capture, because they pass before any of our code runs:
 * when the document finished arriving and when the parser reached an interactive DOM. Both
 * come from the navigation entry, whose timestamps share `performance.now()`'s origin.
 */
function navigationMarks(): StartupMark[] {
  const entry = performance.getEntriesByType('navigation')[0] as
    | PerformanceNavigationTiming
    | undefined;
  if (!entry) return [];

  return [
    { label: 'response-end', ms: entry.responseEnd },
    { label: 'dom-interactive', ms: entry.domInteractive },
    { label: 'dom-content-loaded', ms: entry.domContentLoadedEventEnd },
  ].filter((candidate) => Number.isFinite(candidate.ms) && candidate.ms >= 0);
}

/**
 * Sends the series to the backend to be logged, once.
 *
 * The navigation marks are merged in here rather than collected upfront because
 * `domContentLoadedEventEnd` is only filled in once that event has fired, which is after
 * `mount` — reading it at import time would report it as zero.
 */
export async function flushStartupTiming(): Promise<void> {
  const series = [...navigationMarks(), ...marks].sort((a, b) => a.ms - b.ms);

  try {
    await invoke('log_startup_timing', {
      marks: series.map((entry) => [entry.label, entry.ms]),
    });
  } catch (error) {
    // Not fatal, and not only the error case: `vite dev` has no backend to answer. A missing
    // timing is a missing measurement, not a broken start-up.
    console.warn('[startup] the start-up timings could not be logged:', error);
  }
}
