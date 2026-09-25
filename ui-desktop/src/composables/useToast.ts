/**
 * Toast singleton (docs/ui-refactor-plan.md §5.6, fixes D2).
 *
 * Module-level state rather than a provide/inject tree, because the callers are not components:
 * the proxy store reports a failed `invoke()` from inside an action, and it must not have to
 * know whether a toast host is mounted.
 *
 * Guards against the two ways a toast layer misbehaves in this app: a 2-second log poll cannot
 * stack fifty copies of the same error (de-duplication), and the stack cannot grow without bound
 * (max four visible, oldest evicted).
 */
import { readonly, ref } from 'vue';
import { translate } from '../i18n';
import { errorDetail, errorKey } from '../api/errors';

export type ToastTone = 'success' | 'error' | 'warning' | 'info';

export interface ToastItem {
  id: number;
  tone: ToastTone;
  message: string;
}

const MAX_VISIBLE = 4;

const DURATION: Record<ToastTone, number> = {
  success: 4000,
  info: 4000,
  warning: 8000,
  error: 8000,
};

const items = ref<ToastItem[]>([]);
const timers = new Map<number, ReturnType<typeof setTimeout>>();
let nextId = 1;

function scheduleDismiss(id: number, tone: ToastTone): void {
  const existing = timers.get(id);
  if (existing) clearTimeout(existing);
  timers.set(
    id,
    setTimeout(() => dismiss(id), DURATION[tone]),
  );
}

/** Dismisses one toast. Also the click-to-dismiss path from the host. */
export function dismiss(id: number): void {
  const timer = timers.get(id);
  if (timer) {
    clearTimeout(timer);
    timers.delete(id);
  }
  items.value = items.value.filter((item) => item.id !== id);
}

export function dismissAll(): void {
  for (const id of [...timers.keys()]) dismiss(id);
  items.value = [];
}

function push(tone: ToastTone, message: string): number {
  // Same tone + same text = the same problem being reported again; restart its clock instead of
  // adding a row (R8).
  const existing = items.value.find((item) => item.tone === tone && item.message === message);
  if (existing) {
    scheduleDismiss(existing.id, tone);
    return existing.id;
  }

  const id = nextId++;
  items.value.push({ id, tone, message });

  while (items.value.length > MAX_VISIBLE) {
    const oldest = items.value[0];
    if (!oldest) break;
    dismiss(oldest.id);
  }

  scheduleDismiss(id, tone);
  return id;
}

export function useToast() {
  return {
    toasts: readonly(items),
    dismiss,
    dismissAll,

    success(message: string): number {
      return push('success', message);
    },

    info(message: string): number {
      return push('info', message);
    },

    warning(message: string): number {
      return push('warning', message);
    },

    /**
     * Reports a failure. `error` is whatever the rejected call produced — a structured
     * `AppError`, a string, an `Error` — and is normalised into a translatable key plus a raw
     * diagnostic that goes to the console (never into the headline, which may be Chinese).
     */
    error(error: unknown, fallbackKey = 'error.unknown'): number {
      const key = errorKey(error, fallbackKey);
      const detail = errorDetail(error);
      if (detail) {
        console.error(`[toast] ${key}: ${detail}`);
      } else {
        console.error(`[toast] ${key}`);
      }
      return push('error', translate(key));
    },

    /** A raw, already-localized message for cases with no error payload (e.g. copy failures). */
    fromKey(key: string): number {
      return push('error', translate(key));
    },
  };
}
