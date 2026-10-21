/**
 * What to do with a running proxy when the app is asked to go away.
 *
 * Two things can ask to leave: the window's close request (title-bar button, Alt+F4, the macOS
 * red light) and the Quit item we install for macOS instead of Tauri's predefined one. The tray
 * menu has a Quit of its own, and it asks the same question.
 *
 * Whether a closed window is a quit is a setting, not a fact: with "minimize on close" on, the
 * window goes to the tray and the app keeps running, so there is nothing to ask about the tunnel.
 * With it off — or with no tray to hide into — a closed window ends the process, and the tunnel
 * is worth a question first.
 *
 * What makes the two branches different is where the proxy lives:
 *   - **in this process** — it dies with the window, so "keep it running" can only mean staying
 *     here, and saying so is the honest thing to offer;
 *   - **in the system service** — it outlives the window on purpose, so closing can leave it up.
 *
 * Holding the window is two separate things, and both are needed. Rust keeps the native close
 * from going through, but only for as long as the renderer is listening; the JS wrapper then
 * destroys the window itself once the handler resolves, unless the event says otherwise. So the
 * listener says no every time and leaving for real goes through `destroy()` — not `close()`, which
 * would ask again, forever.
 */
import { getCurrentWindow } from '@tauri-apps/api/window';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import { useProxyStore } from '../stores/proxy';
import { useConfigStore } from '../stores/config';
import { usePrefsStore } from '../stores/prefs';
import { confirm } from './useConfirm';
import { translate } from '../i18n';
import { useToast } from './useToast';

/** Emitted by the Rust side when our own Quit menu item is activated. */
const QUIT_REQUESTED_EVENT = 'nexa://quit-requested';

/** One question at a time: both this module's listeners can fire while an answer is pending. */
let deciding = false;

/**
 * A quit asked for while another question was open.
 *
 * Kept rather than dropped: a Quit that does nothing is a Quit the app never
 * registered, and the user has no way of telling that from one that was
 * ignored.
 */
let pendingQuit = false;

/**
 * Whether the tray icon exists, remembered after the first answer.
 *
 * Asked once and kept, because it cannot change while the app runs: the tray is built at
 * start-up and nothing rebuilds it. `undefined` means "not asked yet".
 */
let trayAvailable: boolean | undefined;

/**
 * Whether there is a tray to hide the window into.
 *
 * A window that hides with no tray to bring it back is an app nobody can reach again, so a
 * missing tray means the close button keeps ending the app. The answer is a failure by default:
 * a tray that could not be built must not be assumed into existence.
 */
async function hasTray(): Promise<boolean> {
  if (trayAvailable === undefined) {
    trayAvailable = await invoke<boolean>('is_tray_available').catch(() => false);
  }
  return trayAvailable;
}

/**
 * Whether closing the window should hide it rather than end the app.
 *
 * Both have to be true: the user asked for it, and there is somewhere for the window to go.
 */
async function shouldMinimizeOnClose(): Promise<boolean> {
  const { prefs } = usePrefsStore();
  if (!prefs.minimizeOnClose) return false;
  return hasTray();
}

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
  const { isRunning, stop, refresh } = useProxyStore();
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

  // Not what `stop()` says — it reports a failure with a toast and then resolves like nothing
  // happened, and while another start or stop is in flight it skips the work entirely. Only what
  // actually stopped earns the quit: leaving now would abandon a proxy that is still forwarding,
  // right after promising to disconnect it.
  await refresh();
  if (isRunning.value) {
    toast.fromKey('error.proxy.stop_failed');
    return false;
  }

  return true;
}

/**
 * Asks the quit that could not be asked while another question was open.
 *
 * Called when a question is answered: a quit asked for in the meantime is
 * asked then, rather than dropped.
 */
function askPendingQuit(): void {
  if (!pendingQuit) return;
  pendingQuit = false;
  void handleQuitRequested();
}

async function handleCloseRequested(): Promise<void> {
  if (deciding) return;
  deciding = true;
  try {
    // A close that only hides the window is not a quit, so it does not ask about the tunnel:
    // the tunnel keeps running, which is the whole point of hiding instead of closing.
    if (await shouldMinimizeOnClose()) {
      // A quit is waiting to be asked, and it is asked in the window: hiding it now would put
      // the question where nobody can see it, and the window would flash up and vanish.
      if (!pendingQuit) await getCurrentWindow().hide();
      return;
    }
    if (!(await decide())) return;
    await getCurrentWindow().destroy();
  } catch (error) {
    console.error('[quit] could not close the window:', error);
  } finally {
    deciding = false;
    askPendingQuit();
  }
}

async function handleQuitRequested(): Promise<void> {
  if (deciding) {
    // A question is already open, and a second one cannot be answered while
    // the first is. The request is kept for when that one is answered.
    pendingQuit = true;
    return;
  }
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
    askPendingQuit();
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
      await getCurrentWindow().onCloseRequested((event) => {
        // Answering takes a promise, and the wrapper destroys the window the moment this handler
        // resolves otherwise — so the close is refused outright and `destroy()` below decides.
        event.preventDefault();
        void handleCloseRequested();
      }),
    );
  } catch (error) {
    console.debug('[quit] close listener unavailable:', error);
  }

  let listening = false;
  try {
    cleanup.push(
      await listen(QUIT_REQUESTED_EVENT, () => {
        void handleQuitRequested();
      }),
    );
    listening = true;
  } catch (error) {
    console.debug('[quit] quit listener unavailable:', error);
  }

  if (listening) {
    // The Rust side cannot tell whether anybody is listening: Tauri delivers an
    // event to the webviews that have a listener for it and does not mention
    // the ones that do not, so an emit to nobody still succeeds and the emit
    // cannot be asked whether the question arrived. The listener says so
    // itself.
    try {
      await invoke('quit_guard_ready');
    } catch (error) {
      console.debug('[quit] could not announce the quit listener:', error);
    }
  }

  return () => {
    for (const dispose of cleanup) dispose();
  };
}
