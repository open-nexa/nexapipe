/**
 * A node's credentials: the connection string it is reached by, and the secret it answers with.
 *
 * Neither is ever on the screen by accident. Both are fetched one at a time, behind the
 * credential door, and both are held only while the door is open: a reveal is a value the screen
 * keeps for as long as somebody asked for it, and the window is how long that somebody is known
 * to be at the keyboard. Once it closes — by the two minutes running out, or by the lock button —
 * the values have to go with it, because a screen still showing a secret it fetched under a
 * window that has since shut is showing it to whoever replaced the user.
 *
 * The plain-text caches live here rather than in the card that shows them, because they belong
 * to the credential and not to the card: the door closing has to empty them wherever they are
 * held, and a card is replaced whenever the list around it is.
 */
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import type { NodeConfig } from "../types";
import { useConfigStore } from "../stores/config";
import { useCredentialGate } from "../stores/gate";
import { useToast } from "./useToast";
import { revealCredential } from "../api/credentials";
import { writeClipboardText } from "../utils/clipboard";

export function useNodeCredentials() {
  const { connectionMask, secretMask, setNodeTwoFactor } = useConfigStore();
  const { ensureUnlocked, unlocked } = useCredentialGate();
  const { t } = useI18n();
  const toast = useToast();

  /**
   * The connection strings that have been revealed, by node.
   *
   * `revealed` holds the whole value for a node only while its reveal is open, and only after the
   * reveal command returned it: the screen never shortens a string it already has, which is what a
   * mask computed in the renderer was. A short value used to be printed whole; it is not any more,
   * because a 16-character TOTP secret shortened by four characters is still a working secret on
   * screen.
   */
  const revealed = ref<Record<string, string>>({});
  const revealedSecrets = ref<Record<string, string>>({});

  /** What a node connects by, or the mask for it when its reveal is closed. */
  function connectionDisplay(node: NodeConfig): string {
    const open = revealed.value[node.id];
    if (open !== undefined) return open;
    return connectionMask(node.id) || "—";
  }

  /** Which credential a node's connection string is filed under. */
  function connectionKind(node: NodeConfig): "ticket" | "endpoint" {
    return node.connectionType === "ticket" ? "ticket" : "endpoint";
  }

  function isRevealed(nodeId: string): boolean {
    return revealed.value[nodeId] !== undefined;
  }

  async function toggleReveal(node: NodeConfig): Promise<void> {
    if (isRevealed(node.id)) {
      delete revealed.value[node.id];
      return;
    }
    // Closing a reveal needs nothing, opening one needs the door: hiding what is
    // already on the screen is not a disclosure.
    if (!(await ensureUnlocked(t("gate.reasonConnection")))) return;
    const value = await revealCredential(connectionKind(node), node.id);
    if (value === null || value === "") return;
    // The window can close while the command is in flight — two minutes is not
    // long, and this is an `await`. Storing the answer afterwards would put a
    // whole value on the page under a window that no longer exists.
    if (!unlocked.value) return;
    revealed.value[node.id] = value;
  }

  async function copyConnection(node: NodeConfig): Promise<void> {
    // Asked for here rather than read off the page: the copy button is a surface
    // too, and the value it puts on the clipboard comes from the store.
    if (!(await ensureUnlocked(t("gate.reasonConnection")))) return;
    const value = revealed.value[node.id] ?? (await revealCredential(connectionKind(node), node.id));
    if (!value) return;
    // The same writer every copy in the app uses: the plain async clipboard call
    // is refused by WebKit once the document is not focused, and the door that
    // stands in front of this value takes long enough to lose it.
    if (await writeClipboardText(value)) {
      toast.success(t("common.copied"));
    } else {
      toast.error(t("common.copyFailed"));
    }
  }

  /** The secret field shows the mask; what the user types into it is what gets stored. */
  function secretDisplay(node: NodeConfig): string {
    return revealedSecrets.value[node.id] ?? secretMask(node.id);
  }

  function secretInputType(node: NodeConfig): "text" | "password" {
    return revealedSecrets.value[node.id] === undefined ? "password" : "text";
  }

  /**
   * Stores what the user typed, and refuses what the field was showing instead.
   *
   * A mask is a shape, not a secret. The field holds one until a reveal opens it,
   * so a change that arrives while it does — one character typed, or the same
   * string touched and blurred — carries bullets with it, and filing those as the
   * TOTP secret would make every later handshake fail for a reason the UI cannot
   * see. Anything still carrying the mask character was not typed by anybody.
   */
  function onSecretChange(node: NodeConfig, event: Event): void {
    const value = (event.target as HTMLInputElement).value.trim();
    if (value.includes("•")) return;
    setNodeTwoFactor(node.id, { secret: value });
  }

  async function toggleSecret(node: NodeConfig): Promise<void> {
    if (revealedSecrets.value[node.id] !== undefined) {
      delete revealedSecrets.value[node.id];
      return;
    }
    if (!(await ensureUnlocked(t("gate.reasonSecret")))) return;
    const value = await revealCredential("totp", node.id);
    if (value === null || value === "") return;
    // As above: the window may have closed while the value was being fetched.
    if (!unlocked.value) return;
    revealedSecrets.value[node.id] = value;
  }

  /** Both plaintext caches die with the window that opened them. */
  watch(unlocked, (isUnlocked) => {
    if (isUnlocked) return;
    revealed.value = {};
    revealedSecrets.value = {};
  });

  return {
    revealedSecrets,
    /** The mask the secret is printed as, for a node whose secret is not revealed. */
    secretMask,
    connectionDisplay,
    connectionKind,
    isRevealed,
    toggleReveal,
    copyConnection,
    secretDisplay,
    secretInputType,
    onSecretChange,
    toggleSecret,
  };
}
