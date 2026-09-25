/**
 * Promise-based confirmation (docs/ui-refactor-plan.md §5.6, fixes D2).
 *
 *   const ok = await confirm({ title: t('settings.uninstallService'), tone: 'danger' })
 *   if (!ok) return
 *
 * The dialog itself is `components/base/AppDialog.vue`, driven by the request ref this module
 * owns. No component has to thread a `visible` prop down from the app root — which is how the
 * previous dialog ended up never being opened.
 */
import { readonly, ref } from 'vue';
import { translate } from '../i18n';

export type ConfirmTone = 'info' | 'warning' | 'danger';

export interface ConfirmOptions {
  title: string;
  message: string;
  tone?: ConfirmTone;
  confirmText?: string;
  cancelText?: string;
  /** Raw diagnostic for the optional "technical details" disclosure. */
  detail?: string;
}

export interface ConfirmRequest extends Required<Omit<ConfirmOptions, 'detail'>> {
  detail?: string;
}

const request = ref<ConfirmRequest | null>(null);
let resolver: ((ok: boolean) => void) | null = null;

/**
 * Opens the dialog and resolves once the user answers. Calling it while another request is open
 * resolves the previous one as `false` instead of leaving its caller awaiting a dialog that will
 * never be shown.
 */
export function confirm(options: ConfirmOptions): Promise<boolean> {
  resolver?.(false);

  request.value = {
    title: options.title,
    message: options.message,
    tone: options.tone ?? 'info',
    confirmText: options.confirmText ?? translate('common.confirm'),
    cancelText: options.cancelText ?? translate('common.cancel'),
    detail: options.detail,
  };

  return new Promise<boolean>((resolve) => {
    resolver = resolve;
  });
}

/** Settles the open request. `Esc` and the close button both call this with `false`. */
export function settleConfirm(ok: boolean): void {
  const pending = resolver;
  resolver = null;
  request.value = null;
  pending?.(ok);
}

/** Read side for the dialog component. */
export function useConfirmState() {
  return {
    request: readonly(request),
    settle: settleConfirm,
  };
}
