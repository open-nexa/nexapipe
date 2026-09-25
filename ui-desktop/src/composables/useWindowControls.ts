/**
 * Platform and window control (docs/ui-refactor-plan.md §5.1, §5.11 rule 1).
 *
 * The UI's only platform signal is the OS name, resolved once through the official OS plugin
 * before the first paint. Architecture is deliberately absent: nothing in the webview may branch
 * on it — per-arch differences are build-time concerns handled by the release pipeline.
 *
 * Capability flags rather than `if (platform === ...)` at every call site:
 *   - `isMacos`    — reserve room for the native traffic lights (§5.1)
 *   - `isLinux`    — keep native decorations, so the custom title bar buttons are hidden
 *   - `isFrameless`— whether the custom title bar is ours to draw
 */
import { computed, ref } from 'vue';
import { getCurrentWindow } from '@tauri-apps/api/window';

export type PlatformName = 'windows' | 'macos' | 'linux' | 'unknown';

const platformName = ref<PlatformName>('unknown');
const archName = ref<string>('');

/**
 * Resolves the platform once, before `app.mount()`, and mirrors it onto `<html data-platform>`
 * so CSS (traffic-light padding, resize affordances) can key off it without a Vue binding.
 * Failure is not fatal: an unknown platform simply behaves like Windows, which is the least
 * surprising default for a UI that draws its own chrome.
 */
export async function initPlatform(): Promise<void> {
  try {
    const { platform, arch } = await import('@tauri-apps/plugin-os');
    const resolved = await platform();
    archName.value = await arch();
    platformName.value =
      resolved === 'windows' || resolved === 'macos' || resolved === 'linux'
        ? resolved
        : 'unknown';
  } catch (error) {
    console.warn('[platform] OS detection unavailable, assuming unknown:', error);
    platformName.value = 'unknown';
  }

  document.documentElement.dataset.platform = platformName.value;
}

function currentWindow() {
  return getCurrentWindow();
}

export function useWindowControls() {
  const isMacos = computed(() => platformName.value === 'macos');
  const isWindows = computed(() => platformName.value === 'windows');
  const isLinux = computed(() => platformName.value === 'linux');

  /**
   * Linux keeps `decorations: true` in this phase (§5.1) — implementing eight edge-resize
   * handles is out of scope — so the native frame is present and our controls are not.
   */
  const isFrameless = computed(() => !isLinux.value);

  async function minimize(): Promise<void> {
    try {
      await currentWindow().minimize();
    } catch (error) {
      console.error('[window] minimize failed:', error);
    }
  }

  async function toggleMaximize(): Promise<void> {
    try {
      await currentWindow().toggleMaximize();
    } catch (error) {
      console.error('[window] toggleMaximize failed:', error);
    }
  }

  async function close(): Promise<void> {
    try {
      await currentWindow().close();
    } catch (error) {
      console.error('[window] close failed:', error);
    }
  }

  async function isMaximized(): Promise<boolean> {
    try {
      return await currentWindow().isMaximized();
    } catch {
      return false;
    }
  }

  /**
   * Double-click-to-maximize. `data-tauri-drag-region` does not provide it on every platform, so
   * the shell wires this to the drag surface explicitly (§5.2).
   */
  async function handleDragDoubleClick(): Promise<void> {
    await toggleMaximize();
  }

  return {
    platform: computed(() => platformName.value),
    arch: computed(() => archName.value),
    isMacos,
    isWindows,
    isLinux,
    isFrameless,
    minimize,
    toggleMaximize,
    close,
    isMaximized,
    handleDragDoubleClick,
  };
}
