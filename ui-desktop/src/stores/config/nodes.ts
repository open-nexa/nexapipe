/**
 * The nodes of the configuration.
 *
 * A node is one server: how it is reached, which domains it answers for, and
 * which credentials it authenticates with. This module is what adds one,
 * changes one and removes one — and a removed node takes its credentials with
 * it, because this is the only place a node stops existing.
 */
import { deleteCredential } from '../../api/credentials';
import type {
  ConnectionType,
  IssuedCredential,
  NodeConfig,
  NodeTwoFactor,
} from '../../types';
import { refreshConnectionMasks } from './credentials';
import { generateNodeId } from './schema';
import { config } from './state';

/**
 * Creates a node. Private on purpose: a node is something an invite brings, so there is no
 * longer any code path that can add an empty one (the old `addNode()` used to be wired to a
 * button on the Config page).
 *
 * What it hands back is the node *as the configuration holds it* — the proxy the array hands
 * out — and not the object that was pushed into it. A caller that writes to the raw object
 * writes straight past Vue: nothing is notified, and the page keeps rendering what it had.
 * That is not a detail: the Config page shows a node only once it has a connection string, so
 * a node whose string was filled in on the raw object stayed invisible — the import had
 * worked, and the page had not been told.
 */
export function createNode(
  node: Partial<NodeConfig> & { connectionType: ConnectionType },
): NodeConfig {
  const created: NodeConfig = {
    id: node.id || generateNodeId(),
    connectionType: node.connectionType,
    ticket: node.ticket ?? '',
    endpointId: node.endpointId ?? '',
    domains: node.domains ? [...node.domains] : [],
    ...(node.name ? { name: node.name } : {}),
    ...(node.twoFactor ? { twoFactor: node.twoFactor } : {}),
    ...(node.enrollment ? { enrollment: node.enrollment } : {}),
    ...(node.deviceKey ? { deviceKey: node.deviceKey } : {}),
    ...(node.publicKey ? { publicKey: node.publicKey } : {}),
  };
  config.nodes.push(created);
  // Read back out of the array, so what the caller gets is the proxy: the same node, and the
  // one whose changes reach the page.
  return config.nodes[config.nodes.length - 1];
}

/**
 * Writes the credential a server issued for an enrollment token onto the node that spent it,
 * and clears the token.
 *
 * A token can only be spent once, so this is the only moment the secret exists on this side:
 * without it a restart falls back to the invite, which the server has already forgotten.
 * Returns the node it landed on, or `null` when no node was waiting for one — the credential
 * is then dropped rather than attached somewhere it does not belong.
 */
export function completeEnrollment(credential: IssuedCredential): NodeConfig | null {
  const node =
    config.nodes.find(
      (candidate) => candidate.enrollment?.clientId === credential.clientId,
    ) ?? config.nodes.find((candidate) => candidate.enrollment);
  if (!node) return null;

  // What the server filed this secret under, and not what was asked for: they differ when
  // the server answered an enrollment that named no device, and writing a name it does not
  // have would make every later handshake answer with the wrong secret.
  const device = credential.device?.trim();
  node.twoFactor = {
    clientId: credential.clientId,
    secret: credential.secret,
    algorithm: credential.algorithm,
    ...(device ? { device } : {}),
  };
  // A key credential has no secret at all: the public half is what says which key this
  // is, and the private one is already in the store — `accept_invite` put it there when
  // the invite was imported, and it is what the enrollment offered.
  const publicKey = credential.publicKey?.trim();
  if (publicKey) {
    node.publicKey = publicKey;
  } else {
    // The server ignored the offer and issued a secret — an older server does exactly
    // that. The key was never recorded there, so it is not a credential this node
    // answers with, and keeping it would make the page present a TOTP node as a key node
    // on every launch: `node_credentials` re-derives the public half from the stored
    // private one, so nothing but deleting both makes the display match the handshake
    // (`manager.rs` answers with the secret whenever there is one).
    delete node.publicKey;
    delete node.deviceKey;
    void deleteCredential('devicekey', node.id).catch((error: unknown) => {
      console.error('[config] failed to delete the device key the server ignored:', error);
    });
  }
  delete node.enrollment;
  return node;
}

/** Sets or replaces one node's 2FA credentials, leaving every other node alone. */
export function setNodeTwoFactor(nodeId: string, patch: Partial<NodeTwoFactor>): void {
  const node = config.nodes.find((candidate) => candidate.id === nodeId);
  if (!node) return;
  // A name belongs to the credential it was filed under, so it survives an edit that leaves that
  // credential alone — an algorithm change, a secret retyped as the one already on file — and
  // goes when the credential itself changes: what this field accepts is the client's shared
  // secret, not one device's, and answering with it under a device's name asks the server for
  // a key it has no entry for under that name.
  const clientId = patch.clientId ?? node.twoFactor?.clientId ?? '';
  const secret = patch.secret ?? node.twoFactor?.secret ?? '';
  const sameCredential =
    clientId === node.twoFactor?.clientId && secret === node.twoFactor?.secret;
  const device = sameCredential ? (patch.device ?? node.twoFactor?.device) : patch.device;
  node.twoFactor = {
    clientId,
    secret,
    algorithm: patch.algorithm ?? node.twoFactor?.algorithm ?? 'sha1',
    // Kept only when there is a name to keep: an unnamed credential is not one with an
    // empty device, it is one the server has no entry for.
    ...(device?.trim() ? { device } : {}),
  };
}

/** Drops a node's credentials, which is what "this server has no 2FA" looks like. */
export function clearNodeTwoFactor(nodeId: string): void {
  const node = config.nodes.find((candidate) => candidate.id === nodeId);
  if (node) {
    delete node.twoFactor;
    // The key goes with the credential that proved itself with it: the
    // private half belongs to that credential, and leaving it on disk would
    // hand it to whatever node reuses this id next.
    delete node.deviceKey;
    delete node.publicKey;
  }
  // The store is told as well: what is dropped here must not survive there.
  void deleteCredential('totp', nodeId).catch((error: unknown) => {
    console.error('[config] failed to delete the stored secret:', error);
  });
  void deleteCredential('devicekey', nodeId).catch((error: unknown) => {
    console.error('[config] failed to delete the stored device key:', error);
  });
}

/**
 * Whether a node would perform a handshake.
 *
 * A credential is a secret or a key: a key node stores no seed at all, so an
 * empty secret there is not a missing credential. A node that is still
 * waiting to enroll has neither yet — it has a token, not a credential.
 */
export function hasTwoFactor(node: NodeConfig): boolean {
  if (!node.twoFactor) return false;
  return node.twoFactor.secret.trim() !== '' || !!node.deviceKey?.trim();
}

export function removeNode(nodeId: string): void {
  const index = config.nodes.findIndex((node) => node.id === nodeId);
  if (index !== -1) config.nodes.splice(index, 1);

  // A removed node takes its credentials with it. Done here rather than by sweeping the store
  // for orphans, because this is the only place a node stops existing.
  // The connection string goes too, from this change on: it is a credential here, so a node
  // that stops existing must not leave one behind under its id.
  void Promise.all([
    deleteCredential('totp', nodeId),
    deleteCredential('enrollment', nodeId),
    deleteCredential('devicekey', nodeId),
    deleteCredential('ticket', nodeId),
    deleteCredential('endpoint', nodeId),
  ]).catch((error: unknown) => {
    console.error('[config] failed to delete the credentials of a removed node:', error);
  });
  void refreshConnectionMasks(config.nodes).catch((error: unknown) => {
    console.error('[config] failed to refresh the connection masks:', error);
  });
}

export function updateNode(nodeId: string, updates: Partial<NodeConfig>): void {
  const node = config.nodes.find((candidate) => candidate.id === nodeId);
  if (node) Object.assign(node, updates);
}

/**
 * Deliberately absent: `updateConnectionString`.
 *
 * A node's target is whatever its invite named, and there is no longer a UI that retypes one —
 * the connection string is displayed with a reveal/copy affordance instead of edited. Keeping a
 * setter around would only invite the old free-text field back.
 */

export function updateNodeDomains(nodeId: string, domains: string[]): void {
  updateNode(nodeId, { domains });
}
