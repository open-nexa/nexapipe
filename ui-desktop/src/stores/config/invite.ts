/**
 * The invite import.
 *
 * An invite names a server, the domains it answers for and — unless it is a
 * registration invite — the credentials to reach it. The credentials are
 * filed in the encrypted store by the backend, and what comes back is the
 * *shape* of the node: a node is born complete, because a node in the
 * configuration without a connection string is invisible on the page and
 * indistinguishable from one whose credential was cleared.
 */
import { acceptInvite } from '../../api/invite';
import { takeInvitedNodeCredentials } from '../../api/credentials';
import type { NodeConfig } from '../../types';
import { refreshConnectionMasks } from './credentials';
import { ensureDeviceIdFor } from './device';
import { createNode } from './nodes';
import { writeRelayUrl } from './relay';
import { config } from './state';

/**
 * Applies a parsed invite: one node carrying its target and domains, plus the two settings an
 * invite reaches that are *not* per-node — the relay and the 2FA credentials.
 *
 * An endpoint already in the list is reused instead of duplicated: a second node pointing at
 * the same backend would only split traffic between two identical entries, and importing the
 * same invite twice (or a newer one for the same server) is meant to top up its domains.
 *
 * The invite's relay is *not* applied unless the caller opts in: the relay is a global setting,
 * so adopting it silently would repoint every other node's home relay on the strength of one
 * invite. It says how that endpoint is reachable, not what this machine should use.
 *
 * Returns which of the two happened, so the caller can say so.
 */
export async function applyInvite(
  uri: string,
  options: { applyRelay?: boolean } = {},
): Promise<'added' | 'merged'> {
  // The credentials go into the store before this returns, and the call answers which node they
  // were filed under: a parsed invite no longer carries a connection string or a secret, so the
  // comparison that decides "new node or an existing one" is made where the values are.
  const accepted = await acceptInvite(uri);

  // Read back the one credential the renderer still has to hold: `start_proxy` takes the
  // connection string as an argument, and the mirror below has to agree with the store or the
  // next save would delete what was just filed. This answers only for the node the invite
  // was accepted for, and only once, so it is not a way back into the store.
  //
  // Read *before* the node is in the configuration, not after. A node that is in the
  // configuration without a connection string looks exactly like a node whose credential was
  // cleared, and the mirror that answers that question would take the credential the invite
  // had just filed back out of the store.
  const stored = await takeInvitedNodeCredentials(accepted.nodeId);

  // The name this machine answers as, asked for before the node is in the configuration. It is
  // what makes the credential that comes back this machine's and nobody else's, and asking for
  // it writes the configuration when the name had to be generated — a save that ran while the
  // node was in the configuration but had no enrollment on it yet would take the pending token
  // back out of the store.
  const device = accepted.enrollment ? await ensureDeviceIdFor(config) : '';

  const name = accepted.name?.trim() || undefined;

  // The credentials belong to the server this invite came from, so they land on its node and
  // nowhere else — a second server keeps whatever it was given before. What is set here is the
  // *shape*: the secret and the token are already in the store, and keeping them out of this
  // object is the whole point of `accept_invite`.
  // No `device` on this branch, on purpose: what a plain invite carries is the client's own
  // secret, which the server files under the client and not under any device. Claiming a
  // name while answering with that secret would make the server look up a device's secret
  // and refuse, for a reason no side would name. A per-device credential is what a
  // *registration* invite issues, and only that.
  const twoFactor = accepted.totp
    ? {
        clientId: accepted.totp.clientId,
        secret: '',
        algorithm: accepted.totp.algorithm,
      }
    : undefined;

  // A registration invite carries a token instead: it is spent on the next connection, which
  // answers with the secret this node is to keep. Stored on the node rather than applied to
  // `twoFactor` because a token is not a credential — writing it there would make the node
  // present the token as its TOTP secret and be refused.
  const enrollment = accepted.enrollment
    ? {
        clientId: accepted.enrollment.clientId,
        // The token the backend filed, read back from the store. It has to
        // cross this boundary for the same reason the device key does: the
        // proxy is what spends it, and in the service mode the proxy is
        // another process with no credential store of its own. Left here,
        // the token stayed in the store and the node opened no auth stream
        // at all — the server answered every connection with "2FA
        // required" and nothing was proxied.
        token: stored.enrollment ?? '',
        device,
        // The public half of the key the backend minted for this enrollment. The
        // private one never comes here — it is in the store, and the enrollment
        // offers it from there.
        ...(accepted.publicKey ? { publicKey: accepted.publicKey } : {}),
      }
    : undefined;

  const ticket = stored.ticket ?? '';
  const endpointId = stored.endpoint ?? '';
  const deviceKey = stored.deviceKey ?? '';
  const publicKey = stored.publicKey ?? accepted.publicKey ?? '';

  let outcome: 'added' | 'merged';
  let node: NodeConfig | undefined = config.nodes.find((n) => n.id === accepted.nodeId);

  if (node) {
    outcome = 'merged';
    // A name already typed here wins: it is the label the user chose for this endpoint.
    if (name && !node.name) node.name = name;

    // The connection string the node reaches its server by, and the device key the backend
    // minted for this enrollment, with the public half of it. The private half is a credential
    // like the connection string: it lives in the store, and the proxy reads it back from
    // there.
    node.ticket = ticket;
    node.endpointId = endpointId;
    node.deviceKey = deviceKey;
    node.publicKey = publicKey;

    if (twoFactor) {
      node.twoFactor = twoFactor;
      delete node.enrollment;
    } else if (enrollment) {
      node.enrollment = enrollment;
      delete node.twoFactor;
    }
  } else {
    node = createNode({
      id: accepted.nodeId,
      connectionType: accepted.connectionType,
      // The node is born complete: a node that is in the configuration without its
      // connection string is invisible on the page, and is indistinguishable from one whose
      // credential was cleared. A node that is born half-made is a node the page has to be
      // told about later — and a write that does not reach the page is a write that did not
      // happen as far as the page is concerned.
      ticket,
      endpointId,
      domains: [],
      ...(name ? { name } : {}),
      ...(twoFactor ? { twoFactor } : {}),
      ...(enrollment ? { enrollment } : {}),
      ...(deviceKey ? { deviceKey } : {}),
      ...(publicKey ? { publicKey } : {}),
    });
    outcome = 'added';
  }

  const domains = [...node.domains];
  for (const domain of accepted.domains) {
    if (!domains.includes(domain)) domains.push(domain);
  }
  node.domains = domains;

  if (accepted.relay && options.applyRelay) {
    config.relayMode = 'custom';
    // The invite names a relay and carries no token for it, so the token
    // this machine holds does not travel to the relay the invite names: it
    // is dropped, unless it was issued for that relay in the first place.
    writeRelayUrl(config, accepted.relay);
  }

  await refreshConnectionMasks(config.nodes);
  return outcome;
}
