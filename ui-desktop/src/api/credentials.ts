/**
 * The frontend half of the credential store (`src-tauri/src/credentials.rs`).
 *
 * A node's TOTP secret, its enrollment token, the relay bearer and its connection string live in
 * an encrypted store whose master key the OS keychain holds — not in `localStorage`, which is an
 * unencrypted SQLite file inside the WebKit data directory and one `localStorage.getItem` away
 * from anything the user runs. What the config store persists is the *shape* of a node's
 * credentials; the values come from here.
 *
 * Every call rejects with a structured `AppError` (`credentials.store_failed`), rendered through
 * `errorKey` / `errorDetail` like every other backend failure.
 */
import { invoke } from '@tauri-apps/api/core';

/**
 * What a stored value is. `totp`, `enrollment`, `ticket` and `endpoint` belong to a node;
 * `relay` is global.
 *
 * `ticket` and `endpoint` are the two spellings of a node's connection string, which is a
 * credential rather than configuration: a ticket names an endpoint and carries how to reach
 * it, so anyone holding one can connect.
 */
export type CredentialKind = 'totp' | 'enrollment' | 'relay' | 'ticket' | 'endpoint';

/** Reads one credential. `null` when it was never stored. */
export async function getCredential(
  kind: CredentialKind,
  nodeId?: string,
): Promise<string | null> {
  return await invoke<string | null>('get_credential', { kind, nodeId });
}

/**
 * One credential as a surface may show it: masked in Rust, so the renderer is handed a projection
 * and never the value.
 *
 * Every surface that prints a credential asks for this. `getCredential` is the plumbing that
 * reads one back into the config — or hands a connection string to the proxy — and is never what
 * a page renders.
 */
export async function credentialDisplay(
  kind: CredentialKind,
  nodeId?: string,
): Promise<string | null> {
  return await invoke<string | null>('credential_display', { kind, nodeId });
}

/**
 * One credential in full, for the user to copy.
 *
 * The only path from the store to a surface, and the one the OS lock goes in front of: everything
 * else the UI can ask for is a mask or a shape.
 */
export async function revealCredential(
  kind: CredentialKind,
  nodeId?: string,
): Promise<string | null> {
  return await invoke<string | null>('reveal_credential', { kind, nodeId });
}

/** Writes one credential, replacing whatever was there. */
export async function putCredential(
  kind: CredentialKind,
  value: string,
  nodeId?: string,
): Promise<void> {
  await invoke<void>('put_credential', { kind, value, nodeId });
}

/** Forgets one credential. Absent is not an error: there is nothing to forget. */
export async function deleteCredential(kind: CredentialKind, nodeId?: string): Promise<void> {
  await invoke<void>('delete_credential', { kind, nodeId });
}

/** Forgets every credential, for a reset that also forgets the nodes they belonged to. */
export async function clearCredentials(): Promise<void> {
  await invoke<void>('clear_credentials');
}

/**
 * Where the master key ended up: `"keychain"`, or `"file"` when no keychain would take it —
 * a headless Linux session with no Secret Service, a locked keychain. The credentials are
 * encrypted either way; only the key is then a private file, which is worth saying out loud
 * rather than leaving to look identical to the keychain case.
 */
export async function credentialStoreStatus(): Promise<string> {
  return await invoke<string>('credential_store_status');
}
