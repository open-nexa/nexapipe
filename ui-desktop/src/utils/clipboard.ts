/**
 * Clipboard primitives for the application's own context menu (docs/ui-refactor-plan.md §5.11).
 *
 * Three APIs are in play, and the order matters:
 *
 *   1. the Tauri clipboard plugin — native, and the only path with no opinion
 *      about focus, schemes, or user gestures. It is tried first because the
 *      two below are both refused in exactly the situation a copy button here
 *      is used: several awaits (the gate's sheet, the IPC that fetched the
 *      value) sit between the click and the write.
 *   2. `navigator.clipboard` — asynchronous, promise-based, the only way to
 *      *read*. It needs a secure context, which the `tauri://` custom scheme
 *      is not, so on macOS it is simply absent.
 *   3. `document.execCommand` — deprecated, synchronous, and the only way to
 *      *write* into a focused field while keeping its undo history. WebKit
 *      also wants a live user gesture for `copy`, which the awaits above have
 *      spent. It stays as the last resort, never the first choice.
 *
 * Every function here reports success or failure instead of throwing: a clipboard call that
 * rejects mid-menu would otherwise leave the user with a menu that silently did nothing.
 */
import { writeText as writeNative } from '@tauri-apps/plugin-clipboard-manager';

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

  // Native first: the write survives a document that lost focus to the gate's
  // sheet and needs no gesture. A failure here is reported and fallen through,
  // because the WebView paths below are only ever worse, never impossible.
  try {
    await writeNative(text);
    return true;
  } catch (error) {
    console.error('[clipboard] the native write failed:', error);
  }

  // Whether the async API is even there is most of the diagnosis, so it is
  // reported: it needs a secure context, and Tauri serves macOS from
  // `tauri://localhost`, a custom scheme WebKit does not treat as trustworthy.
  const hasAsyncApi = Boolean(navigator.clipboard?.writeText);

  if (hasAsyncApi) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      // Present and refused: a document that is not focused, or a user gesture
      // the awaits in the caller spent before this ever ran.
      console.error('[clipboard] the async API refused the write:', error);
    }
  }

  if (copyThroughSelection(text)) return true;

  console.error(`[clipboard] no path took the write (async API present: ${hasAsyncApi})`);
  return false;
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
