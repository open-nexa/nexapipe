/**
 * UI preferences: theme, language, sidebar state (docs/ui-refactor-plan.md §5.7).
 *
 * Separate from the user's proxy configuration on purpose — losing a theme choice is a shrug,
 * losing node configuration is not, and the two have different migration stories.
 */
import { reactive, watch } from 'vue';

export type ThemePreference = 'system' | 'light' | 'dark';

export interface Prefs {
  theme: ThemePreference;
  /** Resolved locale tag, e.g. `en` or `zh-CN`. */
  locale: string;
  sidebarCollapsed: boolean;
}

const STORAGE_KEY = 'nexapipe.prefs';

const defaultPrefs: Prefs = {
  theme: 'system',
  locale: '',
  sidebarCollapsed: false,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function loadPrefs(): Prefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...defaultPrefs };
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) return { ...defaultPrefs };

    const theme: ThemePreference =
      parsed.theme === 'light' || parsed.theme === 'dark' || parsed.theme === 'system'
        ? parsed.theme
        : defaultPrefs.theme;

    return {
      theme,
      locale: typeof parsed.locale === 'string' ? parsed.locale : defaultPrefs.locale,
      sidebarCollapsed:
        typeof parsed.sidebarCollapsed === 'boolean'
          ? parsed.sidebarCollapsed
          : defaultPrefs.sidebarCollapsed,
    };
  } catch (error) {
    console.error('[prefs] failed to load:', error);
    return { ...defaultPrefs };
  }
}

const prefs = reactive<Prefs>(loadPrefs());

watch(
  () => ({ ...prefs }),
  (next) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch (error) {
      console.error('[prefs] failed to save:', error);
    }
  },
  { deep: true },
);

export function usePrefsStore() {
  function setTheme(theme: ThemePreference): void {
    prefs.theme = theme;
  }

  function setLocale(locale: string): void {
    prefs.locale = locale;
  }

  function setSidebarCollapsed(collapsed: boolean): void {
    prefs.sidebarCollapsed = collapsed;
  }

  function toggleSidebar(): void {
    prefs.sidebarCollapsed = !prefs.sidebarCollapsed;
  }

  return {
    prefs,
    setTheme,
    setLocale,
    setSidebarCollapsed,
    toggleSidebar,
  };
}

/**
 * Synchronous read used before the app mounts, so the first paint already has the right theme
 * and no flash of the wrong one occurs (§5.4).
 */
export function readStoredTheme(): ThemePreference {
  return prefs.theme;
}

export function readStoredLocale(): string {
  return prefs.locale;
}
