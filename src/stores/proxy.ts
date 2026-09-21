/**
 * Runtime proxy state and actions (docs/ui-refactor-plan.md §5.7, §5.12).
 *
 * This store owns the `invoke()` orchestration that used to live inside `ProxyStatusControl.vue`
 * (D12) — the component rendered state it did not own, and could only tell the store about a
 * status change after the fact.
 *
 * The two orthogonal concerns are kept apart and named explicitly:
 *   - **execution backend** (`config.useService`): in-process, or the installed system service
 *   - **forwarding mode** (`config.useTun`): TUN, or the local proxy
 *
 * TUN is gated on the service being installed (§5.12): without it the app runs the local proxy,
 * and asking for TUN anyway fails with `proxy.tun_unavailable` rather than quietly forwarding
 * traffic a different way.
 */
import { computed, ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import type { AppError, ProxyMode, ProxyStatus } from '../types';
import { useConfigStore } from './config';
import { translate } from '../i18n';
import { useToast } from '../composables/useToast';

/** How long a start may take before the UI calls it a failure. */
const START_TIMEOUT_MS = 25_000;
const POLL_INTERVAL_MS = 250;

const status = ref<ProxyStatus>({ running: false, mode: 'stopped' });
const nodeId = ref('');
const busy = ref(false);
const startupError = ref<AppError | null>(null);
const serviceRunning = ref(false);

/** What the last start asked for, so the mode that comes back can be checked against it. */
const requestedMode = ref<ProxyMode | null>(null);

const { config, updateConfig } = useConfigStore();
const toast = useToast();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isAppError(value: unknown): value is AppError {
  return typeof value === 'object' && value !== null && typeof (value as AppError).code === 'string';
}

async function refresh(): Promise<void> {
  try {
    const result = await invoke<ProxyStatus>('get_proxy_status', {
      useService: config.useService,
    });
    status.value = result;
    if (result.running) {
      await refreshNodeId();
    } else {
      nodeId.value = '';
    }
  } catch (error) {
    // A status read is a background poll; a toast on every failure would be noise. The start
    // path reports its own failures, and the console keeps the trail.
    console.error('[proxy] failed to read status:', error);
  }
}

async function refreshNodeId(): Promise<void> {
  try {
    nodeId.value = await invoke<string>('get_node_id', {
      useService: config.useService,
    });
  } catch (error) {
    // Not running, or the node has not published an ID yet — both are normal, not reportable.
    nodeId.value = '';
    console.debug('[proxy] node id unavailable:', error);
  }
}

/** Reads the failure `start_proxy` recorded after it had already returned, if any. */
async function readStartupError(): Promise<AppError | null> {
  try {
    const result = await invoke<AppError | null>('get_startup_error');
    return isAppError(result) ? result : null;
  } catch (error) {
    console.error('[proxy] failed to read startup error:', error);
    return null;
  }
}

/**
 * Waits for the start to settle: `starting` until the manager reaches a live mode, or back to
 * `stopped` when it gave up. Bounded, unlike the previous fixed 1s + 2s sleeps, so a slow start
 * (iroh endpoint bind + first route install) is no longer reported as a failure.
 */
async function waitForStart(): Promise<void> {
  const deadline = Date.now() + START_TIMEOUT_MS;
  let sawStarting = false;

  while (Date.now() < deadline) {
    await refresh();

    if (status.value.running) return;

    if (status.value.mode === 'starting') {
      sawStarting = true;
    } else if (sawStarting) {
      // It was starting and is not any more, without ever reporting a live mode: it failed.
      return;
    }

    await sleep(POLL_INTERVAL_MS);
  }
}

async function start(): Promise<void> {
  if (busy.value) return;

  busy.value = true;
  startupError.value = null;

  const backendNodes = config.nodes
    .filter((node) => node.ticket || node.endpointId)
    .map((node) => ({
      connection_type: node.connectionType,
      ticket: node.connectionType === 'ticket' ? node.ticket : '',
      endpoint_id: node.connectionType === 'endpoint_id' ? node.endpointId : '',
      domains: node.domains,
    }));

  const wantTun = config.useTun;
  requestedMode.value = wantTun ? 'tun' : 'local_proxy';

  try {
    await invoke('start_proxy', {
      nodes: backendNodes,
      domains: config.domains,
      localAddr: config.localAddr,
      dnsAddr: config.dnsAddr,
      upstreamDns: config.upstreamDns,
      loadBalancing: config.loadBalancing,
      tunName: config.tunName,
      useService: config.useService,
      useTun: wantTun,
      relayMode: config.relayMode,
      relayUrl: config.relayUrl,
      forceRelay: config.forceRelay,
      twoFactorEnabled: config.twoFactorEnabled,
      twoFactorClientId: config.twoFactorClientId,
      twoFactorSecret: config.twoFactorSecret,
      twoFactorAlgorithm: config.twoFactorAlgorithm,
    });

    await waitForStart();

    if (!status.value.running) {
      // Only read the recorded failure when the start did not succeed: it is never cleared, so a
      // stale entry from an earlier attempt must not be reported as this one's.
      const recorded = await readStartupError();
      startupError.value = recorded;
      toast.error(recorded ?? { code: 'proxy.start_failed' }, 'error.proxy.start_failed');
      return;
    }

    // The mode that actually came up must match what was asked for (§5.12 rule 4). A mismatch
    // means something downgraded the request — surface it instead of showing a green light.
    if (status.value.mode !== requestedMode.value) {
      toast.warning(
        translate('connect.modeMismatch', {
          mode: translate(`mode.${status.value.mode}`),
        }),
      );
      return;
    }

    toast.success(translate('connect.started'));
  } catch (error) {
    startupError.value = isAppError(error) ? error : null;
    toast.error(error, 'error.proxy.start_failed');
  } finally {
    busy.value = false;
  }
}

async function stop(): Promise<void> {
  if (busy.value) return;

  busy.value = true;
  try {
    await invoke('stop_proxy', { useService: config.useService });
    await refresh();
    toast.success(translate('connect.stopped'));
  } catch (error) {
    toast.error(error, 'error.proxy.stop_failed');
  } finally {
    busy.value = false;
  }
}

/**
 * Whether the system service is answering. Polled rather than assumed: it gates the TUN toggle
 * (§5.12 rule 3), and the answer changes when the service is installed, uninstalled, or dies.
 */
async function refreshServiceRunning(): Promise<void> {
  try {
    serviceRunning.value = await invoke<boolean>('is_service_running');
  } catch (error) {
    // Infallible on the backend side; reaching here means the invoke itself failed.
    serviceRunning.value = false;
    console.error('[proxy] failed to query the service:', error);
  }

  // TUN cannot run without the service, so an uninstalled service must not leave a latent
  // request behind (rule 3): the toggle flips back off and says why.
  if (!serviceRunning.value && config.useTun) {
    updateConfig({ useTun: false });
    toast.warning(translate('connect.tunUnavailableServiceGone'));
  }
}

/**
 * Sets the forwarding mode. Refuses to persist TUN while the service is not installed — the
 * toggle is disabled in that state, and a persisted request that cannot be honoured is worse
 * than none.
 */
function setUseTun(enabled: boolean): void {
  if (enabled && !serviceRunning.value) {
    toast.warning(translate('connect.tunRequiresService'));
    return;
  }
  updateConfig({ useTun: enabled });
}

export function useProxyStore() {
  return {
    status,
    nodeId,
    busy,
    startupError,
    serviceRunning,
    /** The mode the last start asked for; compared against what actually runs. */
    requestedMode,
    isRunning: computed(() => status.value.running),
    canStart: computed(() => config.nodes.some((node) => node.ticket || node.endpointId)),
    start,
    stop,
    refresh,
    refreshNodeId,
    refreshServiceRunning,
    setUseTun,
  };
}

/** Called once at startup by the shell, before the first status render. */
export async function initProxyState(): Promise<void> {
  await refreshServiceRunning();
  await refresh();
}
