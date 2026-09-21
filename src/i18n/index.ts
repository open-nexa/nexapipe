/**
 * i18n bootstrap (docs/ui-refactor-plan.md §5.5).
 *
 * `en` is the source of truth and the fallback; `zh-CN` mirrors it. `legacy: false` gives the
 * composition API surface (`useI18n`, `globalInjection` for `$t` in templates).
 *
 * Locale resolution: stored preference → `navigator.language` → `en`. Every `zh-*` tag collapses
 * to `zh-CN` — distributions commonly report `zh-Hans`, and treating that as "unsupported" would
 * silently give a Chinese user an English UI. Traditional Chinese is a future locale file, not a
 * mapping change (non-goal, see §1 and §5.5).
 */
import { createI18n } from 'vue-i18n';
import en from './locales/en.json';
import zhCN from './locales/zh-CN.json';

/** The locale tags this app ships. Typed, because vue-i18n's `locale` ref is a union of them. */
export type SupportedLocale = 'en' | 'zh-CN';

export const SUPPORTED_LOCALES: readonly { value: SupportedLocale; label: string }[] = [
  { value: 'en', label: 'English' },
  { value: 'zh-CN', label: '简体中文' },
];

export const DEFAULT_LOCALE: SupportedLocale = 'en';
export const FALLBACK_LOCALE: SupportedLocale = 'en';

export function isSupportedLocale(locale: string): locale is SupportedLocale {
  return SUPPORTED_LOCALES.some((entry) => entry.value === locale);
}

export function resolveLocale(preference?: string): SupportedLocale {
  const candidate = (preference || '').trim() || navigator.language || DEFAULT_LOCALE;
  const lowered = candidate.toLowerCase();

  if (lowered.startsWith('zh')) return 'zh-CN';
  if (lowered.startsWith('en')) return 'en';

  return DEFAULT_LOCALE;
}

const i18n = createI18n({
  legacy: false,
  globalInjection: true,
  locale: resolveLocale(),
  fallbackLocale: FALLBACK_LOCALE,
  messages: {
    en,
    'zh-CN': zhCN,
  },
  // Unknown keys must be impossible to ship, and `lint:i18n` already fails the build over a key
  // that does not exist. The warnings stay on in dev to catch dynamic keys the linter cannot see.
  missingWarn: import.meta.env.DEV,
  fallbackWarn: import.meta.env.DEV,
});

/**
 * Keeps the document in step with the active locale: `<html lang>` drives screen readers,
 * `Intl`, and the WebView's font selection; the title stays the untranslated product name (D14).
 */
export function applyDocumentLocale(locale: string): void {
  document.documentElement.lang = locale;
  document.title = i18n.global.t('app.windowTitle');
}

/** Switches locale at runtime. Live — no reload, no remount. */
export function setI18nLocale(locale: string): void {
  const resolved: SupportedLocale = isSupportedLocale(locale) ? locale : resolveLocale(locale);
  i18n.global.locale.value = resolved;
  applyDocumentLocale(resolved);
}

/**
 * Translation outside a component: stores, composables and the toast singleton all need to
 * produce user-facing text without a setup context. Reads the same global composer the templates
 * use, so a live locale switch applies everywhere at once.
 */
export function translate(key: string, named?: Record<string, unknown>): string {
  const t = i18n.global.t as unknown as (
    k: string,
    values?: Record<string, unknown>,
  ) => string;
  return named ? t(key, named) : t(key);
}

/** The currently active locale tag. */
export function currentLocale(): string {
  return i18n.global.locale.value;
}

export default i18n;
