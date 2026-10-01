/**
 * The credential door, as the UI drives it (docs/ui-refactor-plan.md §5.7).
 *
 * The door is the question the encrypted store and the masks cannot ask: whether the person at the
 * keyboard is the person whose credentials these are. It is answered by the operating system and
 * stays open for two minutes; everything here is about asking at the right moment and never
 * claiming an answer that has not been given.
 *
 * Two things are deliberately kept apart:
 *   - **the state**, which is the backend's. The window is a duration rather than a flag, so this
 *     store runs a countdown against it and treats a lapsed window as shut even before the backend
 *     is asked again.
 *   - **the asking**, which is [`ensureUnlocked`]. A surface that is about to show a value calls
 *     it and stops if it says no; it is what collects a password on the platforms that need one,
 *     and what says out loud when the machine has nothing to ask with.
 */
import { computed, ref } from 'vue';
import { gateStatus, lockCredentials, unlockCredentials } from '../api/gate';
import { errorDetail, errorKey } from '../api/errors';
import { confirm } from '../composables/useConfirm';
import { askPassword } from '../composables/usePassword';
import { useToast } from '../composables/useToast';
import { translate } from '../i18n';
import type { GateStatus } from '../types';

/**
 * The last answer the backend gave. Null until it has been asked, which is not
 * the same as shut: a surface must not claim the machine cannot authenticate
 * before the machine has been asked.
 */
const status = ref<GateStatus | null>(null);

/** When the window ends, as a wall-clock timestamp. Zero when the door is shut. */
let endsAt = 0;

/** Moves only while the window is open: a countdown is the one thing that needs it. */
const now = ref(Date.now());
let ticker: ReturnType<typeof setInterval> | null = null;

const toast = useToast();

/**
 * Why the last attempt to open the door did not open it, in the user's language.
 *
 * `null` is not "nobody has tried": it is "the last thing that happened was not
 * a refusal". A refusal is worth keeping because the alternative is silence —
 * the user pressed a button, the operating system said no, and a page that then
 * looks exactly as it did before is a page that has swallowed the answer.
 *
 * Cleared when the next attempt starts, so it describes that attempt's
 * predecessor and nothing older: a message from five minutes ago is not news
 * about the button that was just pressed.
 */
const refusal = ref<string | null>(null);

/**
 * Whether a confirmation is being waited on right now.
 *
 * The operating system takes as long as it takes, and on Linux a password it
 * refuses costs seconds more than one it accepts — which it spends on purpose,
 * to make guessing slow. A button that looks exactly as it did before the
 * press reads as a button that did nothing, so the waiting is a state of its
 * own: the press is answered at once even though the answer is not.
 */
const pending = ref(false);

/** How much of the window is left. Zero the moment it lapses, shut or open. */
const msRemaining = computed(() => (endsAt > now.value ? endsAt - now.value : 0));

/**
 * Whether a credential may be shown right now.
 *
 * Read off the clock rather than off the last answer: a window that has run out
 * is shut whether or not anything has noticed yet.
 */
const unlocked = computed(() => status.value?.unlocked === true && msRemaining.value > 0);

function startTicker(): void {
  if (ticker !== null) return;
  ticker = setInterval(() => {
    now.value = Date.now();
    if (msRemaining.value === 0) {
      stopTicker();
      // Let the backend confirm it is shut instead of assuming it: the window is
      // its state, and this timer is only what watches it run out.
      void refreshGate();
    }
  }, 1_000);
}

function stopTicker(): void {
  if (ticker !== null) {
    clearInterval(ticker);
    ticker = null;
  }
}

/** Adopts an answer, and starts or stops the countdown to match. */
function apply(next: GateStatus): void {
  status.value = next;
  endsAt = next.unlocked ? Date.now() + next.msRemaining : 0;
  now.value = Date.now();
  if (endsAt > 0) {
    startTicker();
  } else {
    stopTicker();
  }
}

/**
 * Re-reads the door.
 *
 * Also the moment the machine is asked whether it can still confirm anybody: a
 * window is two minutes of memory and nothing checks it while it runs, so a
 * machine that lost what it asked with — a password removed, a fingerprint
 * deleted — is found out here, and the backend shuts the door itself.
 */
export async function refreshGate(): Promise<void> {
  try {
    apply(await gateStatus());
  } catch (error) {
    // Not worth a message: nothing was being disclosed, and the next attempt to
    // show one will ask again.
    console.error('[gate] the door could not be read:', errorDetail(error));
  }
}

/** Shuts the door without waiting for the window to lapse. */
async function lock(): Promise<void> {
  stopTicker();
  try {
    apply(await lockCredentials());
  } catch (error) {
    console.error('[gate] the door could not be shut:', errorDetail(error));
    // The window is still open as far as the backend is concerned, so it is read
    // back rather than left looking shut here and open there.
    await refreshGate();
  }
}

/**
 * Says that the machine has nothing to confirm the user with.
 *
 * A dialog rather than a toast, because refusing is only half the job: the
 * credential is unreachable until the machine can ask, and that is worth
 * explaining rather than flashing past.
 */
async function sayUnavailable(): Promise<void> {
  await confirm({
    title: translate('gate.unavailableTitle'),
    message: translate('gate.unavailableBody'),
    tone: 'warning',
    hideCancel: true,
  });
}

/**
 * Asks the operating system to open the door, and reports what came back.
 *
 * Resolves with `null` when it opened, and with why it did not, in the user's
 * language, otherwise. The reason is returned as well as kept in [`refusal`]
 * because the caller is sometimes the password dialog, which has to say it
 * where the password was typed rather than on the page behind.
 *
 * `pending` is true for as long as this takes, which is the whole point of it:
 * the operating system answers in its own time, and on Linux a password it
 * refuses costs seconds more than one it accepts.
 */
async function attempt(reason: string, password: string | undefined): Promise<string | null> {
  pending.value = true;
  try {
    apply(await unlockCredentials(reason, password));
    return null;
  } catch (error) {
    console.error('[gate] the door did not open:', errorDetail(error));

    const key = errorKey(error, 'error.credentials.gate_failed');
    if (key === 'error.credentials.gate_unavailable') {
      // The machine has stopped having anything to ask with, which is worth
      // explaining rather than flashing past — but it is still a no.
      refusal.value = translate('gate.notConfirmed');
      await sayUnavailable();
      return refusal.value;
    }
    if (key === 'error.credentials.locked') {
      // The operating system was asked and the answer was no. Which no it was
      // is something only this call knows: a password typed here and refused is
      // a wrong password, while a system prompt that was dismissed is a user who
      // changed their mind — and both leave the door shut with nothing said
      // unless the page behind it is told why.
      refusal.value =
        password === undefined ? translate('gate.notConfirmed') : translate('gate.wrongPassword');
      return refusal.value;
    }
    // Anything else is the operating system failing, and its own words go in
    // the details rather than in the headline.
    toast.error(error, 'error.credentials.gate_failed');
    refusal.value = translate('gate.notConfirmed');
    return refusal.value;
  } finally {
    pending.value = false;
  }
}

/**
 * Whether a credential may be shown, asking the operating system if it cannot.
 *
 * `reason` is what the prompt says it is for — which credential is about to be
 * shown — in the user's language. Returns false whenever the answer was no, or
 * there was nothing to ask, and every caller treats false as "do not show it".
 */
async function ensureUnlocked(reason: string): Promise<boolean> {
  // What the previous attempt came back with, kept for one more attempt so the
  // password dialog can open with it on the field the user is about to fill in.
  const previous = refusal.value;
  refusal.value = null;

  if (status.value === null) await refreshGate();
  if (unlocked.value) return true;

  if (status.value?.canAuthenticate === false) {
    await sayUnavailable();
    return false;
  }

  if (status.value?.needsPassword) {
    // Checked while the dialog is still open, so the wait and the answer both
    // happen where the password was typed: see `PasswordOptions.verify`.
    let opened = false;
    await askPassword({
      title: translate('gate.passwordTitle'),
      message: reason,
      error: previous ?? undefined,
      verify: async (password) => {
        const why = await attempt(reason, password);
        opened = why === null;
        return why;
      },
    });
    return opened;
  }

  return (await attempt(reason, undefined)) === null;
}

/** Forgets what the last refusal said. A page that has been left and reopened has nothing to report. */
export function clearRefusal(): void {
  refusal.value = null;
}

export function useCredentialGate() {
  return {
    /** Whether a credential may be shown right now. */
    unlocked,
    /**
     * Whether the operating system is being asked right now. True from the
     * press until the answer — several seconds on a Linux password that is
     * refused — so a surface can say it is waiting instead of looking idle.
     */
    pending: computed(() => pending.value),
    /** Milliseconds left in the window; zero when it is shut. */
    msRemaining,
    /**
     * Why the last attempt to open the door did not open it, or `null` when the
     * last attempt is not what the page is looking at.
     */
    refusal: computed(() => refusal.value),
    /** Whether the door has been read at all. Nothing is claimed before it has. */
    ready: computed(() => status.value !== null),
    /**
     * Whether this machine can confirm the user. Assumed yes until asked, so a
     * surface that opens before the first read does not say otherwise.
     */
    canAuthenticate: computed(() => status.value?.canAuthenticate ?? true),
    ensureUnlocked,
    lock,
    refresh: refreshGate,
  };
}

/** Called once at startup, before any surface can be asked to show a credential. */
export async function initGate(): Promise<void> {
  await refreshGate();
}
