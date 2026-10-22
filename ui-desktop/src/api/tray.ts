/**
 * The tray icon's half of the app: the menu's words and the state on the icon.
 *
 * Both are the renderer's to say. The tray lives in the backend and the
 * translations live here, so the words are handed over rather than looked up
 * there — the same arrangement the credential gate uses for its prompt.
 */
import { invoke } from '@tauri-apps/api/core';

/**
 * Writes the menu's labels.
 *
 * The words are already in the user's language; the backend only puts them on
 * the menu.
 */
export async function setTrayLabels(showLabel: string, quitLabel: string): Promise<void> {
  await invoke('set_tray_labels', { showLabel, quitLabel });
}

/**
 * Writes the connection state onto the tray icon.
 *
 * A word rather than a colour: the icon is the app's only always-on surface,
 * and a coloured dot would ask the user to learn what the colour means.
 */
export async function setTrayStatus(status: string): Promise<void> {
  await invoke('set_tray_status', { status });
}
