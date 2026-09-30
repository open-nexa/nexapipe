/**
 * Promise-based password prompt, for the one platform that needs one.
 *
 * macOS and Windows bring their own prompt — a keychain sheet, a Windows Hello dialog — so asking
 * is a single call that blocks on the system. Linux has nothing to borrow: PAM will ask for a
 * password and expects the application to have collected it, so this is the dialog that collects
 * it, in the shape `useConfirm` established (a module singleton and a promise, rather than a
 * `visible` prop somebody has to remember to set).
 *
 *   const password = await askPassword({ title, message })
 *   if (password === null) return   // dismissed
 *
 * The value is handed to Rust and zeroed there. It is never written to the config, never logged,
 * and never kept here a moment longer than the call that asked for it.
 */
import { readonly, ref } from 'vue';
import { translate } from '../i18n';

export interface PasswordOptions {
  title: string;
  message: string;
  confirmText?: string;
}

export interface PasswordRequest extends Required<PasswordOptions> {}

const request = ref<PasswordRequest | null>(null);
let resolver: ((password: string | null) => void) | null = null;

/**
 * Opens the dialog and resolves with what was typed, or `null` if it was dismissed.
 *
 * A second call while one is open resolves the first as `null`: the caller is awaiting a dialog
 * that will never be shown again, and "no password" is the safe answer.
 */
export function askPassword(options: PasswordOptions): Promise<string | null> {
  resolver?.(null);

  request.value = {
    title: options.title,
    message: options.message,
    confirmText: options.confirmText ?? translate('common.confirm'),
  };

  return new Promise<string | null>((resolve) => {
    resolver = resolve;
  });
}

/** Settles the open request. `Esc`, the close button and Cancel all call this with `null`. */
export function settlePassword(password: string | null): void {
  const pending = resolver;
  resolver = null;
  request.value = null;
  pending?.(password);
}

/** Read side for the dialog component. */
export function usePasswordState() {
  return {
    request: readonly(request),
    settle: settlePassword,
  };
}
