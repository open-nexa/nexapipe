/**
 * The connections the proxy has open right now (docs/ui-refactor-plan.md §5.7).
 *
 * Its own store rather than part of `stores/proxy.ts` because it is read for a different reason:
 * the proxy store polls to keep a status line honest whether or not anybody is looking, while
 * this one only has a reader while the Connections page is open. Polling a list of connections
 * nobody is drawing would be work with no audience — and the list is the one answer here that
 * grows with what the tunnel is doing.
 *
 * The poll therefore starts and stops with the page. Nothing else in the app needs it.
 */
import { computed, ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import type { ActiveFlow, ActiveFlowPage } from '../types';
import { useConfigStore } from './config';
import { translate } from '../i18n';
import { useToast } from '../composables/useToast';

/**
 * How often the list is re-read while the page is open.
 *
 * Faster than the status poll because this is the one reading that changes on its own every
 * second: a browser opens and closes connections constantly, and a list that lagged by ten
 * seconds would be a list of things that have already gone. Still slow enough that a page
 * sitting open is not hammering the backend — and each read is one `invoke`, not one per row.
 */
const POLL_MS = 2_000;

/** The last reading. `null` until the first read succeeds, so "never asked" stays visible. */
const page = ref<ActiveFlowPage | null>(null);
/** Whether a read is in flight, so the page can hold its shape instead of flickering. */
const reading = ref(false);
/** Which flow is being closed, so its row can say so and the rest stay clickable. */
const closing = ref<number | null>(null);
/** Which node is being closed, for the same reason. */
const closingNode = ref<string | null>(null);

const { config } = useConfigStore();
const toast = useToast();

async function refresh(): Promise<void> {
  reading.value = true;
  try {
    page.value = await invoke<ActiveFlowPage>('get_active_flows', {
      useService: config.useService,
    });
  } catch (error) {
    // A poll, so no toast: the page says it could not read the list rather than interrupting
    // whatever the user is doing with a red banner every two seconds.
    console.error('[connections] failed to read the active flows:', error);
  } finally {
    reading.value = false;
  }
}

/**
 * Ends one connection.
 *
 * Reports `false` honestly rather than as a failure: a list polled every two seconds will
 * sometimes be clicked on a row that has already gone, which is the ordinary case and not
 * something the user did wrong.
 */
async function closeFlow(id: number): Promise<void> {
  if (closing.value !== null) return;
  closing.value = id;
  try {
    const closed = await invoke<boolean>('close_flow', {
      id,
      useService: config.useService,
    });
    if (closed) {
      toast.success(translate('connections.closedOne'));
    } else {
      toast.info(translate('connections.alreadyGone'));
    }
  } catch (error) {
    toast.error(error, 'error.proxy.close_failed');
  } finally {
    closing.value = null;
    // Read straight away rather than waiting out the interval: the point of the click is the
    // row going away, and a list that took two seconds to notice would look like nothing
    // happened.
    await refresh();
  }
}

/**
 * Ends every connection reaching one node.
 *
 * `connection` is the ticket or endpoint ID exactly as the node was configured — the same key
 * the rest of the app keys nodes by. A `null` answer means this configuration does not resolve
 * it at all, which is not "closed zero"; the two say different things and only one of them is
 * worth saying out loud as a success.
 */
async function closeNodeFlows(connection: string): Promise<void> {
  if (closingNode.value !== null) return;
  closingNode.value = connection;
  try {
    const closed = await invoke<number | null>('close_node_flows', {
      connection,
      useService: config.useService,
    });
    if (closed === null) {
      toast.warning(translate('connections.nodeUnknown'));
    } else if (closed === 0) {
      toast.info(translate('connections.noneOpen'));
    } else {
      toast.success(translate('connections.closedMany', { count: closed }));
    }
  } catch (error) {
    toast.error(error, 'error.proxy.close_failed');
  } finally {
    closingNode.value = null;
    await refresh();
  }
}

/* -- polling --------------------------------------------------------------------------------- */

let pollTimer: ReturnType<typeof setTimeout> | null = null;

function schedulePoll(): void {
  if (pollTimer !== null) return;
  pollTimer = setTimeout(async () => {
    pollTimer = null;
    await refresh();
    schedulePoll();
  }, POLL_MS);
}

/** Called by the page when it opens. Reads immediately, then keeps reading. */
async function startPolling(): Promise<void> {
  await refresh();
  schedulePoll();
}

/** Called by the page when it closes: a list nobody is looking at is not worth asking for. */
function stopPolling(): void {
  if (pollTimer !== null) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
}

export function useConnectionsStore() {
  return {
    page,
    reading,
    closing,
    closingNode,
    /** The rows the backend handed over, which may be fewer than are open. */
    flows: computed<ActiveFlow[]>(() => page.value?.flows ?? []),
    /** How many are open in total. `null` until the first read, on the same terms as `page`. */
    total: computed<number | null>(() => page.value?.total ?? null),
    /** Whether the list was cropped, so the page can say so instead of looking complete. */
    cropped: computed(() => {
      const current = page.value;
      return current !== null && current.total > current.flows.length;
    }),
    refresh,
    closeFlow,
    closeNodeFlows,
    startPolling,
    stopPolling,
  };
}
