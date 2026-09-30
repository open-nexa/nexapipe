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
 * Whether a credential may be shown, asking the operating system if it cannot.
 *
 * `reason` is what the prompt says it is for — which credential is about to be
 * shown — in the user's language. Returns false whenever the answer was no, or
 * there was nothing to ask, and every caller treats false as "do not show it".
 */
async function ensureUnlocked(reason: string): Promise<boolean> {
  if (status.value === null) await refreshGate();
  if (unlocked.value) return true;

  if (status.value?.canAuthenticate === false) {
    await sayUnavailable();
    return false;
  }

  let password: string | undefined;
  if (status.value?.needsPassword) {
    const typed = await askPassword({
      title: translate('gate.passwordTitle'),
      message: reason,
    });
    // Dismissed, or left empty: the user did not ask for this after all.
    if (typed === null) return false;
    password = typed;
  }

  try {
    apply(await unlockCredentials(reason, password));
  } catch (error) {
    const key = errorKey(error, 'error.credentials.gate_failed');
    if (key === 'error.credentials.gate_unavailable') {
      await sayUnavailable();
      return false;
    }
    // Asked and refused: the user said no, and there is nothing to add to that.
    // Anything else is the operating system failing, and its own words go in the
    // details rather than in the headline.
    if (key !== 'error.credentials.locked') {
      toast.error(error, 'error.credentials.gate_failed');
    }
    console.error('[gate] the door did not open:', errorDetail(error));
    return false;
  }

  return unlocked.value;
}

export function useCredentialGate() {
  return {
    /** Whether a credential may be shown right now. */
    unlocked,
    /** Milliseconds left in the window; zero when it is shut. */
    msRemaining,
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
