/**
 * The frontend half of the `parse_invite` command.
 *
 * An invite is parsed in Rust, never here: the grammar lives in
 * `crates/nexapipe-client/src/provisioning.rs`, and it is the same parser the server uses to
 * print a code and Android uses to read one off a camera. Re-implementing it in TypeScript would
 * be a third copy to keep in step, and the Android client already carries a second one.
 *
 * The call is pure — nothing is started and no config is written — so the UI can show what a code
 * carries before the user accepts it.
 */
import { invoke } from '@tauri-apps/api/core';
import type { InvitePayload } from '../types';

/** Whether a pasted string looks like an invite rather than a bare ticket or Node ID. */
export function isInviteLink(value: string): boolean {
  return value.trim().toLowerCase().startsWith('nexapipe://');
}

/**
 * Reads an invite link.
 *
 * Rejects with a structured `AppError` (`invite.parse_failed` plus the parser's reason as
 * `detail`), which the caller renders through `errorKey` / `errorDetail` — see `api/errors.ts`.
 */
export async function parseInvite(uri: string): Promise<InvitePayload> {
  return await invoke<InvitePayload>('parse_invite', { uri });
}
