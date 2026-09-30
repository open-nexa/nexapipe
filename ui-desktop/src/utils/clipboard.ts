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

/**
 * Writes through a throwaway textarea and the deprecated `execCommand` path.
 *
 * The async API is the right one to try first, and the only one that can *read*,
 * but WebKit refuses it unless the document is focused — which it is not while a
 * system sheet has just taken the window, and is not any more after the `await`
 * that fetched the value being copied. `execCommand` asks neither of those
 * things; what it wants is a selection, which is what the textarea is for.
 */
function copyThroughSelection(text: string): boolean {
  const previous = document.activeElement as HTMLElement | null;
  const selection = document.getSelection();
  const previousRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;

  const field = document.createElement('textarea');
  field.value = text;
  // Moved out of sight rather than hidden: a `display: none` field has no
  // selection, and no selection means nothing to copy.
  field.setAttribute('readonly', '');
  field.style.position = 'fixed';
  field.style.top = '0';
  field.style.left = '-9999px';
  document.body.appendChild(field);

  try {
    field.select();
    field.setSelectionRange(0, text.length);
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    field.remove();
    if (selection && previousRange) {
      selection.removeAllRanges();
      selection.addRange(previousRange);
    }
    // The caret goes back where it was: copying is not a reason to move it.
    if (previous) previous.focus({ preventScroll: true });
  }
}

/** Writes `text` to the system clipboard. Resolves false when neither path worked. */
export async function writeClipboardText(text: string): Promise<boolean> {
  if (!text) return false;

  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through: a WebView that refused the write, or one without the
      // async API to refuse it with. `execCommand` needs a live selection, which
      // `copyThroughSelection` brings of its own.
    }
  }

  return copyThroughSelection(text);
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
