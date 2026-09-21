/**
 * Sidebar collapse state (docs/ui-refactor-plan.md §3.1, R7).
 *
 * Two inputs, one result: the user's stored preference, and the window being too narrow for a
 * 200px sidebar. The narrow-window case is a `ResizeObserver` fed by the shell — not a media
 * query and not a container query, because the CSS baseline this project targets is WebKitGTK on
 * Ubuntu 22.04, which lags the other two engines (§5.11 rule 4).
 *
 * Auto-collapse never writes to the preference: widening the window again restores whatever the
 * user actually chose.
 */
import { computed, ref } from 'vue';
import { usePrefsStore } from '../stores/prefs';

/** Below this width the sidebar collapses on its own. */
export const AUTO_COLLAPSE_WIDTH = 860;

const viewportWidth = ref(typeof window === 'undefined' ? AUTO_COLLAPSE_WIDTH : window.innerWidth);

const { prefs, toggleSidebar, setSidebarCollapsed } = usePrefsStore();

const autoCollapsed = computed(() => viewportWidth.value < AUTO_COLLAPSE_WIDTH);

export function useSidebar() {
  return {
    /** What the shell should render: preference OR narrow-window auto-collapse. */
    collapsed: computed(() => prefs.sidebarCollapsed || autoCollapsed.value),
    /** Why it is collapsed, so the UI can explain itself (a disabled toggle, a hint). */
    collapsedByPreference: computed(() => prefs.sidebarCollapsed),
    autoCollapsed,
    breakpoint: AUTO_COLLAPSE_WIDTH,
    toggle: toggleSidebar,
    setCollapsed: setSidebarCollapsed,
    /** Called by the shell's ResizeObserver. */
    syncViewportWidth(width: number): void {
      viewportWidth.value = width;
    },
  };
}
