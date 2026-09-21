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
 *
 * Runtime proxy state is deliberately last and not awaited: it needs the backend, and the shell
 * renders `stopped` until the first status arrives.
 */
import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import i18n, { resolveLocale, setI18nLocale } from './i18n';
import { applyStoredTheme } from './composables/useTheme';
import { initPlatform } from './composables/useWindowControls';
import { readStoredLocale } from './stores/prefs';
import { initProxyState } from './stores/proxy';

import './styles/tokens.css';
import './styles/themes.css';
import './styles/base.css';
// Temporary: the token names the not-yet-migrated pages still use. Removed with them (§7).
import './styles/legacy.css';

applyStoredTheme();

async function bootstrap(): Promise<void> {
  await initPlatform();

  // The composition root owns the *initial* locale; `useLocale` owns every later change, so the
  // two cannot fight over the value — both resolve it the same way.
  setI18nLocale(resolveLocale(readStoredLocale()));

  const app = createApp(App);
  app.use(i18n);
  app.use(router);
  app.mount('#app');

  void initProxyState();
}

void bootstrap();
