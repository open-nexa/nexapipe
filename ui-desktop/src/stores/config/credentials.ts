/**
 * The credential store, from this side.
 *
 * A node's TOTP secret, its enrollment token, the relay bearer and its
 * connection string live in an encrypted store whose master key the OS
 * keychain holds — not in `localStorage`. What the configuration persists is
 * the *shape* of a node's credentials; the values come from here, and they are
 * mirrored back the other way when the configuration changes.
 *
 * Three directions, and each of them is careful about the one thing it must
 * not do: the mirror must not delete a credential the user never cleared, the
 * hydration must not write a half-read configuration, and the display must
 * only ever hand out a mask.
 */
import { reactive } from 'vue';
import {
  credentialDisplay,
  deleteCredential,
  putCredential,
  takeRuntimeCredentials,
} from '../../api/credentials';
import type { NodeConfig, ProxyConfig } from '../../types';
import { isKeyNode } from './keys';
import { relayTokenRelayFor } from './relay';

/**
 * Whether `hydrateCredentials` has finished.
 *
 * Until it has, every secret in the config is empty — not because the user cleared it, but because
 * nothing has read the store back yet. A mirror that ran inside that window would read the
 * emptiness as a deletion and drop credentials it has not read, and the store is the only copy.
 */
let credentialsHydrated = false;

/** Whether the credential store has been read back into the configuration. */
export function hasHydratedCredentials(): boolean {
  return credentialsHydrated;
}

/** Says that the credential store has been read back into the configuration. */
export function markCredentialsHydrated(): void {
  credentialsHydrated = true;
}

/**
 * Mirrors the credentials into the encrypted store: written when a node has them, deleted when it
 * does not, so a credential that was cleared here is not left behind there.
 *
 * Gated on `credentialsHydrated`, because "cleared here" and "not read back yet" look the same in
 * `config` and only one of them is something the user did.
 */
export async function persistCredentials(config: ProxyConfig): Promise<void> {
  if (!credentialsHydrated) {
    return;
  }

  if (config.relayAuthToken.trim()) {
    await putCredential('relay', config.relayAuthToken);
  } else {
    await deleteCredential('relay');
  }

  for (const node of config.nodes) {
    // An object that is present with an empty value is not the same as one that
    // is absent, and treating the two alike deletes a credential that is filed
    // and deliberate. `applyInvite` is the case: it puts the secret in the store
    // itself and builds the shape here with the value left out on purpose, so
    // that the renderer never holds it. Reading that as "the user cleared it"
    // removed what had just been filed, and the node started with no
    // authentication. Clearing is `clearNodeTwoFactor`, which removes the
    // object; an object with an empty value now leaves the store alone.
    if (!node.twoFactor) {
      await deleteCredential('totp', node.id);
    } else if (node.twoFactor.secret.trim()) {
      await putCredential('totp', node.twoFactor.secret, node.id);
    } else if (isKeyNode(node)) {
      // A key node stores no seed: a secret left in the store would be a
      // credential the server never issued this device, and the one thing
      // that store is for is answering with what the server holds.
      //
      // **The node's own key, not the one it answers with.** Every node of a
      // machine that has a key carries it, so a node whose credential is a
      // secret carries one too — and asking "does this node have a key?" of
      // that would have deleted the seed the invite had just filed, leaving
      // the node with no credential at all.
      await deleteCredential('totp', node.id);
    }

    // A device key is not mirrored here.
    //
    // It belongs to the machine rather than to the node: the store holds the
    // machine's key, and a node's own key is the one the server holds under
    // this machine's name — which outlives every server the machine comes
    // back to. So the backend owns it: `accept_invite` files the key it is
    // about to offer, and a node that no longer has one has it dropped
    // there. Writing it back from here would file the machine's key under
    // every node, and a node would then look like it had enrolled with a key
    // of its own when it had not.
    //
    // What is left is the deletion: a node whose key was cleared here must
    // not leave one behind in the store. And "whose key was cleared" is
    // about the node's own key: the machine's is not this node's to drop,
    // and a node that never had one of its own has nothing of its own
    // filed here.
    if (!isKeyNode(node) && !node.enrollment) {
      await deleteCredential('devicekey', node.id);
    }

    if (!node.enrollment) {
      await deleteCredential('enrollment', node.id);
    } else if (node.enrollment.token.trim()) {
      await putCredential('enrollment', node.enrollment.token, node.id);
    }

    // Both spellings are mirrored, not just the one `connectionType` names: the
    // other one is what a node that was re-imported the other way round would
    // otherwise find still sitting in the store, and a stale connection string is
    // worse than none because it looks like the one to use.
    if (node.ticket.trim()) {
      await putCredential('ticket', node.ticket, node.id);
    } else {
      await deleteCredential('ticket', node.id);
    }

    if (node.endpointId.trim()) {
      await putCredential('endpoint', node.endpointId, node.id);
    } else {
      await deleteCredential('endpoint', node.id);
    }
  }
}

/**
 * Reads the credentials back into `config`, migrating anything `localStorage` still holds.
 *
 * A payload written before version 2 carries its secrets in the clear. This is where they leave:
 * the store wins when it has a value, and when it does not but the payload does, the payload's
 * value is *written* to the store rather than merely trusted — so the migration happens once and
 * the cleartext copy is gone on the next save.
 *
 * Returns a copy rather than filling `config` in place: the config watcher is live while this
 * runs, so a node-by-node fill would expose a config whose first node has been read and whose
 * second has not — and a save started there deletes the second node's credentials as if the user
 * had cleared them. The read itself is one call rather than one per credential, which is what
 * lets the backend answer it once and never again.
 */
export async function hydrateCredentials(source: ProxyConfig): Promise<ProxyConfig> {
  const hydrated: ProxyConfig = {
    ...source,
    nodes: source.nodes.map((node) => ({ ...node })),
  };

  const bundle = await takeRuntimeCredentials(hydrated.nodes.map((node) => node.id));

  const relay = bundle.relay;
  if (relay) {
    hydrated.relayAuthToken = relay;
    // The token and the relay it was issued for travel together; see
    // `relayTokenRelayFor` for the token that has no recorded relay.
    hydrated.relayAuthTokenRelay = relayTokenRelayFor(
      hydrated.relayUrl,
      hydrated.relayAuthTokenRelay,
    );
  } else if (hydrated.relayAuthToken.trim()) {
    await putCredential('relay', hydrated.relayAuthToken);
    hydrated.relayAuthTokenRelay = relayTokenRelayFor(
      hydrated.relayUrl,
      hydrated.relayAuthTokenRelay,
    );
  }

  for (const node of hydrated.nodes) {
    const stored = bundle.nodes[node.id];

    const secret = stored?.totp ?? null;
    if (secret) {
      node.twoFactor = {
        clientId: node.twoFactor?.clientId ?? '',
        secret,
        algorithm: node.twoFactor?.algorithm ?? 'sha1',
        // The device the secret was issued to travels with it: a credential
        // kept without its name is one that no longer answers, because the
        // server looks it up by that name.
        ...(node.twoFactor?.device ? { device: node.twoFactor.device } : {}),
      };
    } else if (node.twoFactor?.secret.trim()) {
      await putCredential('totp', node.twoFactor.secret, node.id);
    }

    // A device key, when this node has one. The private half is the credential
    // and lives in the store like the secret beside it; the public half is
    // derived by the backend from that same key, so the two can never
    // disagree about which key this is.
    //
    // The key the store answers with is the machine's: the backend falls back
    // to the machine's key for a node that has none of its own, so a node
    // without one still signs with the key the server holds under this
    // machine's name.
    const deviceKey = stored?.deviceKey ?? null;
    if (deviceKey) {
      node.deviceKey = deviceKey;
    } else if (node.deviceKey?.trim()) {
      // A payload from before the store held the secrets: the key is in the
      // clear there, and this is where it leaves.
      await putCredential('devicekey', node.deviceKey, node.id);
    }
    if (stored?.publicKey) {
      node.publicKey = stored.publicKey;
    }

    const token = stored?.enrollment ?? null;
    if (token) {
      node.enrollment = {
        clientId: node.enrollment?.clientId ?? '',
        token,
        // The device the enrollment names travels with it. Dropping it here
        // enrolls without a name, and enrolling without a name answers with
        // the client's own secret — which is what makes a revocation rotate
        // every other device that shares it.
        ...(node.enrollment?.device ? { device: node.enrollment.device } : {}),
      };
    } else if (node.enrollment?.token.trim()) {
      await putCredential('enrollment', node.enrollment.token, node.id);
    }

    // The store wins, and a payload that still carries the connection string has it
    // written rather than merely trusted — that is the version 3 migration, and it
    // is the reason a node's connection string is empty in the payload from now on.
    const ticket = stored?.ticket ?? null;
    if (ticket) {
      node.ticket = ticket;
    } else if (node.ticket.trim()) {
      await putCredential('ticket', node.ticket, node.id);
    }

    const endpointId = stored?.endpoint ?? null;
    if (endpointId) {
      node.endpointId = endpointId;
    } else if (node.endpointId.trim()) {
      await putCredential('endpoint', node.endpointId, node.id);
    }
  }

  return hydrated;
}

/**
 * Drops nodes that have nothing to connect with, once the credential store has answered.
 *
 * This used to happen while the payload was being read, which cannot work from version 3: the
 * connection string is in the store, so every node looks empty at that point and the second
 * launch would delete all of them. It happens here instead — after `hydrateCredentials`, and
 * only on the path where that succeeded, because a store that could not be read must not look
 * like a user who deleted every node.
 */
export function dropNodesWithoutAConnectionString(nodes: NodeConfig[]): NodeConfig[] {
  return nodes.filter((node) => {
    if (node.ticket.trim() !== '' || node.endpointId.trim() !== '') return true;
    console.warn(
      '[config] dropping a node with no connection string in the payload or the credential store:',
      node.id,
    );
    return false;
  });
}

/**
 * Where the credential store's master key ended up: `"keychain"`, or `"file"` when no keychain
 * would take it — a headless Linux session with no Secret Service, a keychain that refused the
 * app. The credentials are encrypted either way, so this is information rather than a warning:
 * what changes is who holds the key, and the user is the one who should know.
 *
 * `null` until startup has asked. Read once there, because it cannot change while the app runs.
 */
export const credentialProtection = reactive<{ level: string | null }>({ level: null });

/**
 * What a surface may print for a node's connection string: the mask Rust produced, keyed by node.
 *
 * The value itself is here too — `start_proxy` takes it as an argument, so the renderer has not
 * stopped holding it — but nothing renders it. Asking Rust for the mask rather than shortening
 * what is already in memory is the difference: a mask the renderer computes is not one, because
 * the thing it computed it from is one devtools panel away.
 *
 * Empty until the store has been asked, which is why a page falling back to it shows nothing
 * rather than a value of its own.
 */
export const connectionMasks = reactive<Record<string, string>>({});

/** The same, for the TOTP secret a node authenticates with. */
export const secretMasks = reactive<Record<string, string>>({});

/**
 * Asks the store for the masks of the nodes it knows about.
 *
 * The node list is the caller's: this runs after a node has come or gone, and
 * the mask of a node that no longer exists is dropped below.
 */
export async function refreshConnectionMasks(nodes: NodeConfig[]): Promise<void> {
  const shown = await Promise.all(
    nodes.map(async (node) => {
      const connection = node.connectionType === 'ticket' ? 'ticket' : 'endpoint';
      const [target, secret] = await Promise.all([
        credentialDisplay(connection, node.id).catch((error: unknown) => {
          console.error('[config] failed to read a connection string for display:', error);
          return null;
        }),
        credentialDisplay('totp', node.id).catch((error: unknown) => {
          console.error('[config] failed to read a secret for display:', error);
          return null;
        }),
      ]);
      return [node.id, target ?? '', secret ?? ''] as const;
    }),
  );

  for (const [id, target, secret] of shown) {
    connectionMasks[id] = target;
    secretMasks[id] = secret;
  }
  // A node that is gone takes its masks: leaving them would keep a projection of
  // credentials nothing is connecting to any more.
  for (const id of Object.keys(connectionMasks)) {
    if (!nodes.some((node) => node.id === id)) delete connectionMasks[id];
  }
  for (const id of Object.keys(secretMasks)) {
    if (!nodes.some((node) => node.id === id)) delete secretMasks[id];
  }
}
