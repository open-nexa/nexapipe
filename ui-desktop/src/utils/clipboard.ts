/**
 * Clipboard primitives for the application's own context menu (docs/ui-refactor-plan.md §5.11).
 *
 * Two APIs are in play, and the order matters:
 *
 *   1. `navigator.clipboard` — asynchronous, promise-based, the only way to *read*. It needs a
 *      secure context, which the WebView gives us (`http://tauri.localhost` / `tauri://` are both
 *      treated as trustworthy), and it is already what the invite dialog and the log view use.
 *   2. `document.execCommand` — deprecated, synchronous, and the only way to *write* into a
 *      focused field while keeping its undo history. It is the fallback, never the first choice.
 *
 * Every function here reports success or failure instead of throwing: a clipboard call that
 * rejects mid-menu would otherwise leave the user with a menu that silently did nothing.
 */

/** Writes `text` to the system clipboard. Resolves false when neither path worked. */
export async function writeClipboardText(text: string): Promise<boolean> {
  if (!text) return false;

  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through: a WebView without the async API, or one that refused the write (no
      // transient activation). `execCommand` needs a live selection, which the menu deliberately
      // preserves — see `ContextMenu.vue`.
    }
  }

  try {
    return document.execCommand('copy');
  } catch {
    return false;
  }
}

/**
 * Reads text from the system clipboard, or `null` when the WebView refuses the read.
 *
 * Chrome-derived WebViews (WebView2, and WebKitGTK 2.30+) ask for clipboard-read permission the
 * first time; WebKitGTK below that has no async clipboard at all. Either way the paste item
 * reports the failure rather than inserting an empty string.
 */
export async function readClipboardText(): Promise<string | null> {
  if (navigator.clipboard?.readText) {
    try {
      return await navigator.clipboard.readText();
    } catch {
      // Fall through — there is no synchronous read API to fall back to.
    }
  }
  return null;
}

/**
 * Replaces the current selection in the focused field with `text`.
 *
 * `insertText` is the whole reason this is used instead of rewriting `value`: it goes through the
 * field's own editing pipeline, so the paste is a single undo step and the caret ends up after
 * the inserted text. Returns false on the input types that ignore it (see `writeIntoField`).
 */
export function insertTextAtCaret(text: string): boolean {
  try {
    return document.execCommand('insertText', false, text);
  } catch {
    return false;
  }
}

/**
 * Last-resort write for a field that refused `insertText`: splice the value by hand.
 *
 * Setting `value` directly drops the undo history, which is exactly why this is only reached
 * after `insertText` failed. The synthetic `input` event is not optional — without it Vue's
 * `v-model` never learns that the field changed, and the next write from the store would silently
 * restore the old text.
 */
export function writeIntoField(
  field: HTMLInputElement | HTMLTextAreaElement,
  text: string,
): boolean {
  try {
    const start = Math.min(field.selectionStart ?? field.value.length, field.value.length);
    const end = Math.min(field.selectionEnd ?? field.value.length, field.value.length);
    const from = Math.min(start, end);
    const to = Math.max(start, end);

    field.value = field.value.slice(0, from) + text + field.value.slice(to);
    field.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  } catch {
    // `selectionStart` throws on the input types that do not support selection (number, date…).
    return false;
  }
}
