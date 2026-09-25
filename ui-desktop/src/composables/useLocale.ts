/**
 * Language selection (docs/ui-refactor-plan.md §5.5).
 *
 * `prefs.locale` is the single source of truth; a module-level watcher pushes it into the
 * vue-i18n composer, so switching languages is live everywhere — components, stores, and text
 * produced outside a setup context — without a reload or a remount.
 */
import { computed, watch } from 'vue';
import { usePrefsStore } from '../stores/prefs';
import {
  SUPPORTED_LOCALES,
  currentLocale,
  resolveLocale,
  setI18nLocale,
} from '../i18n';

const { prefs, setLocale: persistLocale } = usePrefsStore();

/** Pending preference: empty means "never chosen", which resolves from the browser. */
const resolved = computed(() => {
  const stored = prefs.locale;
  return stored && SUPPORTED_LOCALES.some((entry) => entry.value === stored)
    ? stored
    : resolveLocale(stored);
});

watch(
  resolved,
  (locale) => setI18nLocale(locale),
  { immediate: true },
);

export function useLocale() {
  function setLocale(locale: string): void {
    persistLocale(locale);
  }

  return {
    locale: computed(() => currentLocale()),
    options: SUPPORTED_LOCALES,
    setLocale,
  };
}
