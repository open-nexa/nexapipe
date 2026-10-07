/**
 * What to do with a running proxy when the app is asked to go away.
 *
 * Two things can ask: the window's close request (title-bar button, Alt+F4, the macOS red
 * light) and the Quit item we install for macOS instead of Tauri's predefined one. They reach the
 * same question, because leaving by either door ends this process — there is no tray it could go
 * back to, so a closed window is a quit.
 *
 * What makes the two branches different is where the proxy lives:
 *   - **in this process** — it dies with the window, so "keep it running" can only mean staying
 *     here, and saying so is the honest thing to offer;
 *   - **in the system service** — it outlives the window on purpose, so closing can leave it up.
 *
 * Registering the close listener is itself the interception: Tauri holds the window open whenever
 * the renderer is listening, which is why closing for real goes through `destroy()` and not
 * `close()` — the latter would ask again, forever.
 */
import { getCurrentWindow } from '@tauri-apps/api/window';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import { useProxyStore } from '../stores/proxy';
import { useConfigStore } from '../stores/config';
import { confirm } from './useConfirm';
import { translate } from '../i18n';
import { useToast } from './useToast';

/** Emitted by the Rust side when our own Quit menu item is activated. */
const QUIT_REQUESTED_EVENT = 'nexa://quit-requested';

/** One question at a time: both this module's listeners can fire while an answer is pending. */
let deciding = false;

/**
 * Whether the proxy outlives this process.
 *
 * Read rather than taken from the store, whose service poll runs every ten seconds and is
 * therefore allowed to be a whole interval out of date by the time someone asks to quit.
 */
async function proxyOutlivesApp(): Promise<boolean> {
  const { serviceRunning, refreshServiceRunning } = useProxyStore();
  const { config } = useConfigStore();

  await refreshServiceRunning();

  // Installed is not the same as running: the settings switch decides which process carries the
  // proxy, and only the service one survives the window.
  return config.useService && serviceRunning.value;
}

/**
 * Puts the question, and acts on the answer.
 *
 * Resolves `true` when the app may go away, `false` when it may not. Quitting is never the only
 * outcome the caller has to handle: a proxy running in this process keeps the window open, and
 * "keep" is what `Esc` and the overlay click resolve to — losing the proxy is the one answer this
 * refuses to reach without being told.
 */
async function decide(): Promise<boolean> {
  const { isRunning, stop } = useProxyStore();
  const toast = useToast();

  if (!isRunning.value) return true;

  const outlives = await proxyOutlivesApp();
  const disconnect = await confirm({
    title: outlives ? translate('quit.titleService') : translate('quit.titleProcess'),
    message: outlives ? translate('quit.messageService') : translate('quit.messageProcess'),
    tone: 'warning',
    confirmText: translate('quit.disconnect'),
    cancelText: translate('quit.keep'),
  });

  if (!disconnect) {
    // Nothing visible happens when the app stays — a Cmd+Q that does nothing otherwise looks
    // like a broken shortcut, which is its own kind of answer.
    if (!outlives) toast.info(translate('quit.kept'));
    return outlives;
  }

  await stop();
  return true;
}

async function handleCloseRequested(): Promise<void> {
  if (deciding) return;
  deciding = true;
  try {
    if (!(await decide())) return;
    await getCurrentWindow().destroy();
  } catch (error) {
    console.error('[quit] could not close the window:', error);
  } finally {
    deciding = false;
  }
}

async function handleQuitRequested(): Promise<void> {
  if (deciding) return;
  deciding = true;
  try {
    if (!(await decide())) return;
    // The reply may never arrive: `finish_quit` exits, and an exit takes the invoke channel with
    // it. Rejecting here is expected and has nobody left to report it to.
    await invoke('finish_quit').catch(() => undefined);
  } catch (error) {
    console.error('[quit] could not quit:', error);
  } finally {
    deciding = false;
  }
}

/**
 * Hooks both asks up, once, for the lifetime of the app.
 *
 * Returns its own teardown. Either listener being unavailable is not fatal — the renderer runs in
 * a browser in development, where there is no window to hold open and no menu to answer.
 */
export async function initQuitGuard(): Promise<() => void> {
  const cleanup: Array<() => void> = [];

  try {
    cleanup.push(
      await getCurrentWindow().onCloseRequested(() => {
        void handleCloseRequested();
      }),
    );
  } catch (error) {
    console.debug('[quit] close listener unavailable:', error);
  }

  try {
    cleanup.push(
      await listen(QUIT_REQUESTED_EVENT, () => {
        void handleQuitRequested();
      }),
    );
  } catch (error) {
    console.debug('[quit] quit listener unavailable:', error);
  }

  return () => {
    for (const dispose of cleanup) dispose();
  };
}
