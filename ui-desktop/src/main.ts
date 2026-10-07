/**
 * Application entry (§3.2, §5.4, §5.11 rule 1).
 *
 * Order is the whole point of this file:
 *
 *   1. styles, in dependency order — raw tokens, then the semantic theme mapping, then the reset
 *   2. the theme attribute, *before* mount, so the first paint is already the right theme and no
 *      white flash happens on a dark-mode machine (§5.4)
 *   3. the platform flag, also before mount: the shell decides whether to draw its own window
 *      controls from it, and resolving it after mount would show Linux users a set of buttons that
 *      then disappear
 *   4. `<html lang>` and the document title from the resolved locale (D14)
 *   5. mount
 *   6. show the window, which the backend created hidden
 *
 * Runtime proxy state is deliberately last and not awaited: it needs the backend, and the shell
 * renders `stopped` until the first status arrives.
 */
import { createApp } from 'vue';
import { getCurrentWindow } from '@tauri-apps/api/window';
import App from './App.vue';
import router from './router';
import i18n, { resolveLocale, setI18nLocale } from './i18n';
import { applyStoredTheme } from './composables/useTheme';
import { initPlatform } from './composables/useWindowControls';
import { readStoredLocale } from './stores/prefs';
import { initProxyState, onAppFocused } from './stores/proxy';
import { initGate, refreshGate } from './stores/gate';
import { initConfigStore, initConfigStoreDeferred } from './stores/config';

import './styles/tokens.css';
import './styles/themes.css';
import './styles/base.css';
// Temporary: the token names the not-yet-migrated pages still use. Removed with them (§7).
import './styles/legacy.css';

applyStoredTheme();

/**
 * Shows the window the backend created hidden.
 *
 * Everything above this line runs before anything is on screen, so a slow start — a cold
 * WebView2, an awaited credential read — used to leave the user looking at an empty frame with
 * the app's own background filling it. Waiting until the app has mounted and painted means the
 * window appears already drawn instead.
 *
 * A frame is asked for first so the paint being *finished* is what the user sees, not merely
 * scheduled: showing on the same tick as `mount()` would put a window up that still has nothing
 * in it, which is the thing this is here to avoid.
 *
 * Failure is not fatal and neither is a plain browser: `vite dev` has no Tauri window and the
 * call rejects, which is expected and says nothing about the app.
 */
async function showWindow(): Promise<void> {
  try {
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    await getCurrentWindow().show();
  } catch (error) {
    console.warn('[window] could not show the window:', error);
  }
}

async function bootstrap(): Promise<void> {
  await initPlatform();

  // Credentials are read from the encrypted store, which is asynchronous, so this is awaited
  // before mount: a page must never render a node's 2FA as absent and then fill it in.
  await initConfigStore();

  // The composition root owns the *initial* locale; `useLocale` owns every later change, so the
  // two cannot fight over the value — both resolve it the same way.
  setI18nLocale(resolveLocale(readStoredLocale()));

  const app = createApp(App);
  app.use(i18n);
  app.use(router);
  app.mount('#app');

  // The window exists from the start but is not shown until there is something in it.
  void showWindow();

  // Everything from here on is a projection no first screen renders, so it must not sit between
  // the mount and the paint: the display masks cost two IPC round-trips per configured node.
  void initConfigStoreDeferred();

  // The door is read before the first paint too, so a page cannot draw an open
  // lock and then shut it.
  void initGate();

  void initProxyState();

  // The status poll keeps running in the background, but a machine that was just asleep has been
  // showing the status it had before it slept — read immediately instead of waiting the interval.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') return;
    onAppFocused();
    // The one moment worth asking the machine again whether it can still confirm
    // anybody: a password removed or a fingerprint deleted while the app was in
    // the background must not leave a window open nobody can answer for.
    void refreshGate();
  });
}

void bootstrap();
