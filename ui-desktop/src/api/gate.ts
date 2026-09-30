/**
 * The frontend half of the credential door (`src-tauri/src/gate.rs`).
 *
 * The door is the question the store and the masks cannot ask: whether the person at the keyboard
 * is the person whose credentials these are. It is answered by the operating system — Touch ID or
 * the account password on macOS, Windows Hello or the account password on Windows, PAM on Linux —
 * and it stays open for two minutes once it has been.
 *
 * Nothing here decides anything. What a surface does is ask [`ensureUnlocked`] in `stores/gate.ts`
 * before it shows a value, and let that decide whether the OS has to be asked first.
 */
import { invoke } from '@tauri-apps/api/core';
import type { GateStatus } from '../types';

/** Reads the door: whether it is open, how long it has left, and what the machine can answer. */
export async function gateStatus(): Promise<GateStatus> {
  return await invoke<GateStatus>('gate_status');
}

/**
 * Asks the operating system to confirm the user.
 *
 * `reason` is what the prompt says it is for, already in the user's language — the caller knows
 * which credential is about to be shown and the door does not, and on macOS there is no way to put
 * it on the system prompt at all. `password` is only wanted where
 * [`GateStatus.needsPassword`] said so: PAM has no dialog of its own.
 *
 * Rejects with `credentials.locked` when the user was asked and the answer was no — a password
 * that was not accepted, or a prompt that was dismissed. Not a failure of the machine's, and not
 * silence either: `ensureUnlocked` turns it into the one line the page behind it prints.
 */
export async function unlockCredentials(reason: string, password?: string): Promise<GateStatus> {
  return await invoke<GateStatus>('unlock_credentials', {
    reason,
    password: password ?? null,
  });
}

/** Shuts the door again, without waiting for the window to lapse. */
export async function lockCredentials(): Promise<GateStatus> {
  return await invoke<GateStatus>('lock_credentials');
}
