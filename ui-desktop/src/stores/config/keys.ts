/**
 * The two keys, and which of them a rule is about.
 *
 * A key belongs to the *machine*, not to the node: the server files a
 * credential under a device name, and that name is the machine's, so every
 * node of a machine that has a key answers with it — including the nodes that
 * never enrolled with one.
 *
 * So `deviceKey` on a node is the key the node *answers with*, and the public
 * half of it (`publicKey`) is the key the node *has of its own*: the one it
 * enrolled with, the one the server holds under this machine's name. A node
 * without one of its own carries the machine's key all the same.
 *
 * The distinction matters wherever a rule asks "does this node have a key?".
 * Asked of `deviceKey`, the answer is yes for every node of a machine that
 * has one — and a rule that means "this node's credential is a key" then
 * fires for a node whose credential is a secret, and takes the secret away.
 */
import type { NodeConfig } from '../../types';

/**
 * Whether a node has a key of its own — the one it enrolled with.
 *
 * The public half is what names it: a node that enrolled with a key has one,
 * and a node that never did has none to name. It is derived by the backend
 * from the private half beside it, so the two cannot disagree about which key
 * this is.
 */
export function isKeyNode(node: Pick<NodeConfig, 'publicKey'>): boolean {
  return !!node.publicKey?.trim();
}
