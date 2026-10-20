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
export type CredentialKind = 'totp' | 'enrollment' | 'devicekey' | 'relay' | 'ticket' | 'endpoint';

/**
 * One node's credentials, in full.
 *
 * Not a display shape: this is what the config store fills itself in with at start-up, because
 * `start_proxy` still takes a connection string and a TOTP secret as arguments. Nothing renders
 * it — a page asks `credentialDisplay`, or `revealCredential` once the door is open.
 */
export interface NodeCredentials {
  totp: string | null;
  enrollment: string | null;
  /**
   * The private half of this node's device key, when it has one.
   *
   * A credential like the secret beside it, and it crosses this boundary for the same reason: the
   * proxy needs it to sign, and in the service mode the service is a separate process with no
   * store of its own.
   */
  deviceKey: string | null;
  /**
   * The public half of that key, as 64 hex characters.
   *
   * Derived by the backend from the private half, so the two cannot disagree about which key this
   * is. Not a secret — the server holds the same one.
   */
  publicKey?: string | null;
  ticket: string | null;
  endpoint: string | null;
}

/** Everything the app runs on: the relay bearer, and one entry per node id. */
export interface RuntimeCredentials {
  relay: string | null;
  nodes: Record<string, NodeCredentials | undefined>;
}

/**
 * Reads every credential the app runs on. Once.
 *
 * The door in front of `revealCredential` is worth nothing while a general read sits beside it:
 * anything that can reach this process could ask for a TOTP secret and the operating system would
 * never be consulted. So this is asked by the config store while it fills itself in, before the
 * app mounts, and the backend refuses every ask after the first.
 *
 * Rejects with `credentials.store_failed` when it has already been read.
 */
export async function takeRuntimeCredentials(nodeIds: string[]): Promise<RuntimeCredentials> {
  return await invoke<RuntimeCredentials>('take_runtime_credentials', { nodeIds });
}

/**
 * One node's credentials, for a node an invite has just filed them under.
 *
 * The backend answers this only for nodes `accept_invite` imported in this run, and only once
 * each, so it cannot be pointed at a node whose credentials the renderer has no business holding.
 */
export async function takeInvitedNodeCredentials(nodeId: string): Promise<NodeCredentials> {
  return await invoke<NodeCredentials>('take_invited_node_credentials', { nodeId });
}

/**
 * One credential as a surface may show it: masked in Rust, so the renderer is handed a projection
 * and never the value.
 *
 * Every surface that prints a credential asks for this. `takeRuntimeCredentials` and
 * `takeInvitedNodeCredentials` are the plumbing that reads one back into the config — which then
 * hands a connection string to the proxy — and neither is what a page renders.
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
