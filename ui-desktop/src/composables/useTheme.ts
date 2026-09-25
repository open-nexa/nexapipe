/**
 * Theme resolution (docs/ui-refactor-plan.md §5.4).
 *
 * Three preferences — `system`, `light`, `dark` — resolved to a concrete theme and written to
 * `<html data-theme>`, which is what all theme CSS keys off. A `matchMedia` listener keeps
 * `system` live while the app is open, and the OS-level window chrome follows via
 * `setTheme` so native context menus match.
 *
 * `applyStoredTheme()` exists for `main.ts`: it must run *before* `app.mount()` so the first
 * paint is already the right theme (no flash of the wrong one).
 */
import { computed, ref, watch } from 'vue';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { usePrefsStore, type ThemePreference } from '../stores/prefs';

export type ResolvedTheme = 'light' | 'dark';

const darkQuery =
  typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-color-scheme: dark)')
    : null;

const systemPrefersDark = ref(darkQuery?.matches ?? false);

darkQuery?.addEventListener('change', (event) => {
  systemPrefersDark.value = event.matches;
});

const { prefs, setTheme } = usePrefsStore();

export function resolveTheme(preference: ThemePreference): ResolvedTheme {
  if (preference === 'system') return systemPrefersDark.value ? 'dark' : 'light';
  return preference;
}

const resolvedTheme = computed<ResolvedTheme>(() => resolveTheme(prefs.theme));

function applyThemeAttribute(theme: ResolvedTheme): void {
  document.documentElement.dataset.theme = theme;
}

/** Follows the app theme at the OS level (title bar, native menus). Failure is not fatal. */
async function syncNativeTheme(theme: ResolvedTheme): Promise<void> {
  try {
    await getCurrentWindow().setTheme(theme);
  } catch (error) {
    // Expected outside a Tauri window (plain `vite dev`) or if the permission is missing.
    console.debug('[theme] native setTheme unavailable:', error);
  }
}

watch(
  resolvedTheme,
  (theme) => {
    applyThemeAttribute(theme);
    void syncNativeTheme(theme);
  },
  { immediate: true },
);

/** Pre-mount initialisation: set the attribute synchronously, before the first paint. */
export function applyStoredTheme(): void {
  applyThemeAttribute(resolveTheme(prefs.theme));
}

export function useTheme() {
  return {
    preference: computed(() => prefs.theme),
    resolved: resolvedTheme,
    setTheme,
  };
}
