/**
 * The WebView's right-click menu, taken over (docs/ui-refactor-plan.md §5.11).
 *
 * Every WebView ships its own context menu: English-only, unthemed, and — on Windows — happy to
 * offer "Reload", "Save as" and "Inspect element" inside what is supposed to be an application
 * window. This module suppresses it everywhere and opens the application's own menu instead, so
 * a right-click is either useful or silent, and never a pane of browser chrome.
 *
 * What the menu contains is decided by what was clicked, not by a fixed list:
 *
 *   - a text field  → cut / copy / paste / select all, each enabled only when it can do something
 *   - selected text → copy
 *   - a link        → open in the browser / copy the address
 *   - anything else → nothing at all; the click is swallowed
 *
 * The state lives at module level like `useToast` and `useConfirm`: the trigger is a DOM event on
 * `window`, not a component, and it must not have to know whether a menu host is mounted.
 */
import { readonly, ref } from 'vue';
import { openUrl } from '@tauri-apps/plugin-opener';
import { translate } from '../i18n';
import {
  insertTextAtCaret,
  readClipboardText,
  writeClipboardText,
  writeIntoField,
} from '../utils/clipboard';
import { useToast } from './useToast';

export interface ContextMenuAction {
  kind: 'action';
  id: string;
  label: string;
  disabled: boolean;
  run: () => void;
}

export interface ContextMenuSeparator {
  kind: 'separator';
  id: string;
}

export type ContextMenuEntry = ContextMenuAction | ContextMenuSeparator;

interface MenuState {
  open: boolean;
  x: number;
  y: number;
  entries: ContextMenuEntry[];
}

/** An element the user can type into: `input`, `textarea`, or anything contenteditable. */
type EditableElement = HTMLInputElement | HTMLTextAreaElement | HTMLElement;

interface RightClickContext {
  editable: EditableElement | null;
  /** What a copy would put on the clipboard: the field's selection, or the document's. */
  selection: string;
  link: string | null;
  /** False for schemes the opener cannot hand to a browser (`javascript:`, `file:`…). */
  linkOpenable: boolean;
}

/**
 * Input types with no text to cut or paste. `closest()` matches them all, so they have to be
 * excluded rather than allow-listed: a `type` the app does not use yet still belongs in the
 * "not editable" bucket.
 */
const NON_TEXT_INPUT_TYPES = new Set([
  'button',
  'checkbox',
  'color',
  'file',
  'hidden',
  'image',
  'radio',
  'range',
  'reset',
  'submit',
]);

const OPENABLE_PROTOCOLS = new Set(['http:', 'https:', 'mailto:']);

const menu = ref<MenuState>({ open: false, x: 0, y: 0, entries: [] });

export function closeContextMenu(): void {
  if (!menu.value.open) return;
  // The entries stay put while the menu animates out; clearing them here would blank the panel
  // mid-transition.
  menu.value = { ...menu.value, open: false };
}

// -- context ------------------------------------------------------------------------------------

function editableAt(target: EventTarget | null): EditableElement | null {
  if (!(target instanceof Element)) return null;

  const candidate = target.closest('input, textarea, [contenteditable]');
  if (!candidate) return null;

  if (candidate instanceof HTMLTextAreaElement) return candidate;

  if (candidate instanceof HTMLInputElement) {
    return NON_TEXT_INPUT_TYPES.has(candidate.type) ? null : candidate;
  }

  // `[contenteditable]` matches `contenteditable="false"` too, and matches an editable ancestor
  // of a non-editable child — `isContentEditable` is what settles both.
  return (candidate as HTMLElement).isContentEditable ? (candidate as HTMLElement) : null;
}

function selectionText(editable: EditableElement | null): string {
  if (editable instanceof HTMLInputElement || editable instanceof HTMLTextAreaElement) {
    try {
      const start = editable.selectionStart ?? 0;
      const end = editable.selectionEnd ?? 0;
      return editable.value.slice(Math.min(start, end), Math.max(start, end));
    } catch {
      // `number`, `date` and friends throw on `selectionStart`; they have no text selection
      // either, so "no selection" is the honest answer.
      return '';
    }
  }

  return window.getSelection()?.toString() ?? '';
}

function linkAt(target: EventTarget | null): { href: string; openable: boolean } | null {
  if (!(target instanceof Element)) return null;

  const anchor = target.closest('a[href]');
  if (!(anchor instanceof HTMLAnchorElement)) return null;

  const raw = anchor.getAttribute('href');
  if (!raw) return null;

  try {
    const resolved = new URL(raw, document.baseURI);
    return { href: resolved.href, openable: OPENABLE_PROTOCOLS.has(resolved.protocol) };
  } catch {
    return { href: raw, openable: false };
  }
}

function inspect(target: EventTarget | null): RightClickContext {
  const editable = editableAt(target);
  const link = linkAt(target);

  return {
    editable,
    selection: selectionText(editable),
    link: link?.href ?? null,
    linkOpenable: link?.openable ?? false,
  };
}

// -- actions ------------------------------------------------------------------------------------

function reportFailure(key: string): void {
  useToast().fromKey(key);
}

function focusEditable(editable: EditableElement): void {
  if (document.activeElement !== editable) editable.focus();
}

function isReadOnly(editable: EditableElement): boolean {
  return (
    (editable instanceof HTMLInputElement || editable instanceof HTMLTextAreaElement) &&
    editable.readOnly
  );
}

async function copySelection(context: RightClickContext): Promise<void> {
  if (await writeClipboardText(context.selection)) return;
  reportFailure('contextMenu.clipboardFailed');
}

async function cutSelection(context: RightClickContext): Promise<void> {
  const editable = context.editable;
  if (!editable) return;

  focusEditable(editable);

  // One command, one undo step: the field keeps its history, which a copy-then-delete by hand
  // would not.
  if (document.execCommand('cut')) return;

  if (await writeClipboardText(context.selection)) {
    insertTextAtCaret('');
    return;
  }
  reportFailure('contextMenu.clipboardFailed');
}

async function pasteInto(context: RightClickContext): Promise<void> {
  const editable = context.editable;
  if (!editable) return;

  focusEditable(editable);

  const text = await readClipboardText();
  if (text === null) {
    reportFailure('contextMenu.clipboardFailed');
    return;
  }

  if (insertTextAtCaret(text)) return;

  if (
    (editable instanceof HTMLInputElement || editable instanceof HTMLTextAreaElement) &&
    writeIntoField(editable, text)
  ) {
    return;
  }

  reportFailure('contextMenu.clipboardFailed');
}

function selectAllIn(editable: EditableElement): void {
  focusEditable(editable);

  if (editable instanceof HTMLInputElement || editable instanceof HTMLTextAreaElement) {
    try {
      editable.select();
      return;
    } catch {
      // Same input types as above: fall back to the document-level command.
    }
  }

  document.execCommand('selectAll');
}

async function copyLink(url: string): Promise<void> {
  if (await writeClipboardText(url)) return;
  reportFailure('contextMenu.clipboardFailed');
}

async function openLink(url: string): Promise<void> {
  try {
    await openUrl(url);
  } catch (error) {
    useToast().error(error, 'contextMenu.openLinkFailed');
  }
}

// -- menu construction --------------------------------------------------------------------------

function action(
  id: string,
  label: string,
  handler: () => void | Promise<void>,
  disabled = false,
): ContextMenuAction {
  return {
    kind: 'action',
    id,
    label,
    disabled,
    // Deliberately fire-and-forget: the menu closes immediately, and an await here would only
    // delay the panel's removal.
    run: () => void handler(),
  };
}

function buildEntries(context: RightClickContext): ContextMenuEntry[] {
  const entries: ContextMenuEntry[] = [];
  const editable = context.editable;
  const hasSelection = context.selection.length > 0;

  if (editable) {
    // A password field is the one place the browser refuses copy and cut too, and for the same
    // reason: the text would land on a clipboard that any other process can read.
    const secret = editable instanceof HTMLInputElement && editable.type === 'password';
    const readOnly = isReadOnly(editable);

    if (!readOnly && !secret) {
      entries.push(
        action('cut', translate('contextMenu.cut'), () => cutSelection(context), !hasSelection),
      );
    }
    if (!secret) {
      entries.push(
        action('copy', translate('contextMenu.copy'), () => copySelection(context), !hasSelection),
      );
    }
    if (!readOnly) {
      entries.push(action('paste', translate('contextMenu.paste'), () => pasteInto(context)));
    }
    entries.push(
      action('selectAll', translate('contextMenu.selectAll'), () => selectAllIn(editable)),
    );
  } else if (hasSelection) {
    entries.push(
      action('copy', translate('contextMenu.copy'), () => copySelection(context)),
    );
  }

  const link = context.link;
  if (link) {
    if (entries.length > 0) entries.push({ kind: 'separator', id: 'link-separator' });
    if (context.linkOpenable) {
      entries.push(
        action('openLink', translate('contextMenu.openLink'), () => openLink(link)),
      );
    }
    entries.push(action('copyLink', translate('contextMenu.copyLink'), () => copyLink(link)));
  }

  return entries;
}

// -- entry point --------------------------------------------------------------------------------

/**
 * Handles a `contextmenu` event: swallows the WebView's menu and, when there is something to
 * offer, opens ours at the pointer.
 */
export function handleContextMenuEvent(event: MouseEvent): void {
  // `preventDefault` is what suppresses the native menu; it runs even when this builds nothing,
  // because "no menu" is the intended result for chrome, labels and blank space.
  event.preventDefault();

  const entries = buildEntries(inspect(event.target));
  if (entries.length === 0) {
    closeContextMenu();
    return;
  }

  menu.value = { open: true, x: event.clientX, y: event.clientY, entries };
}

export function useContextMenu() {
  return {
    menu: readonly(menu),
    close: closeContextMenu,
    handleContextMenuEvent,
  };
}
