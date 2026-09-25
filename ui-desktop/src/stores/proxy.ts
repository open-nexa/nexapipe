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
import type { AppError, EndpointLink, LinkKind, NodeConfig, ProxyMode, ProxyStatus } from '../types';
import { useConfigStore } from './config';
import { takeIssuedCredential } from '../api/invite';
import { translate } from '../i18n';
import { useToast } from '../composables/useToast';

/** How long a start may take before the UI calls it a failure. */
const START_TIMEOUT_MS = 25_000;
const POLL_INTERVAL_MS = 250;

/**
 * How often the status is re-read while nothing is being asked of the backend.
 *
 * Faster while starting (the first route install usually takes a second or two) and while
 * running, because that is when the answer can change without the user doing anything: the
 * service can die, and iroh can promote a relayed path to a direct one at any moment.
 */
const POLL_RUNNING_MS = 3_000;
const POLL_STARTING_MS = 1_000;
const POLL_STOPPED_MS = 5_000;
/** After this many consecutive failures the poll slows down instead of hammering a dead backend. */
const POLL_BACKOFF_MS = 10_000;
const FAILURES_BEFORE_BACKOFF = 3;

/**
 * How often the service gate is re-read on its own.
 *
 * `serviceRunning` decides whether TUN is offered at all, and installing from Settings changed it
 * without ever telling this store — the Connect page kept its "install service" button and a
 * disabled toggle until the app was restarted. It is slower than the status poll because asking
 * costs a process (`sc.exe query` / `systemctl is-active`) rather than a local IPC read, and
 * installation is a rare, deliberate act.
 */
const SERVICE_POLL_MS = 10_000;

const status = ref<ProxyStatus>({ running: false, mode: 'stopped' });
const nodeId = ref('');
const busy = ref(false);
const startupError = ref<AppError | null>(null);
const serviceRunning = ref(false);
const serviceInstalled = ref(false);

/**
 * How each node is currently reaching its backend, filled in from the Rust side while the proxy
 * is up. Empty whenever nothing is running, which is what keeps a stale icon off the screen.
 */
const endpointLinks = ref<EndpointLink[]>([]);

/**
 * Set when the last few status reads failed, so the UI can admit the numbers on screen may be
 * out of date rather than presenting them with the same confidence as a live reading.
 */
const stale = ref(false);

/** What the last start asked for, so the mode that comes back can be checked against it. */
const requestedMode = ref<ProxyMode | null>(null);

const { config, updateConfig, completeEnrollment } = useConfigStore();
const toast = useToast();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isAppError(value: unknown): value is AppError {
  return typeof value === 'object' && value !== null && typeof (value as AppError).code === 'string';
}

/** Reads the status (and, while running, the node ID). Returns whether the read succeeded. */
async function refresh(): Promise<boolean> {
  try {
    const result = await invoke<ProxyStatus>('get_proxy_status', {
      useService: config.useService,
    });
    status.value = result;
    if (result.running) {
      await refreshNodeId();
    } else {
      nodeId.value = '';
      endpointLinks.value = [];
    }
    return true;
  } catch (error) {
    // A status read is a background poll; a toast on every failure would be noise. The start
    // path reports its own failures, and the console keeps the trail.
    console.error('[proxy] failed to read status:', error);
    return false;
  }
}

/**
 * Reads how every node is currently reaching its backend.
 *
 * Infallible: an empty answer means "nothing is connected", which the UI renders by drawing no
 * link at all — a failure here must never become a red error over an otherwise healthy proxy.
 */
async function refreshEndpointLinks(): Promise<void> {
  try {
    endpointLinks.value = await invoke<EndpointLink[]>('get_endpoint_links', {
      useService: config.useService,
    });
  } catch (error) {
    console.debug('[proxy] endpoint links unavailable:', error);
    endpointLinks.value = [];
  }
}

/**
 * The runtime link kind of a node, or null when nothing is connected to it — the normal answer
 * before the proxy is started.
 *
 * Keyed on the connection string exactly as it was configured, which is what the backend echoes
 * back: a ticket is opaque here, so the resolved endpoint ID alone would not match.
 */
function linkKindFor(node: NodeConfig): LinkKind | null {
  const connection = node.connectionType === 'ticket' ? node.ticket : node.endpointId;
  if (!connection) return null;
  return endpointLinks.value.find((link) => link.connection === connection)?.link ?? null;
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
      // Per node, not per client: each server has its own [auth].clients entry.
      two_factor_client_id: node.twoFactor?.clientId ?? null,
      two_factor_secret: node.twoFactor?.secret ?? null,
      two_factor_algorithm: node.twoFactor?.algorithm ?? null,
      // A registration invite's token, spent on the first connection of this run.
      enrollment_client_id: node.enrollment?.clientId ?? null,
      enrollment_token: node.enrollment?.token ?? null,
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
      relayAuthToken: config.relayAuthToken,
    });

    await waitForStart();
    // A fresh session means fresh paths: read them now instead of waiting out the poll, which
    // otherwise leaves the link badges empty for the first few seconds after every start.
    if (status.value.running) await refreshEndpointLinks();

    if (!status.value.running) {
      // Only read the recorded failure when the start did not succeed: it is never cleared, so a
      // stale entry from an earlier attempt must not be reported as this one's.
      const recorded = await readStartupError();
      startupError.value = recorded;
      toast.error(recorded ?? { code: 'proxy.start_failed' }, 'error.proxy.start_failed');
      return;
    }

    // Read before anything else can fail the start: a spent token is gone, and the credential
    // it bought is the only copy this process will ever see.
    await collectIssuedCredential();

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

/**
 * Stores the credential the server issued for an enrollment token, if one was spent.
 *
 * A token is spent by the first connection that presents it, so this has to run right after a
 * successful start: without it the secret exists only in the backend process's memory, and the
 * next launch falls back to an invite the server has already forgotten.
 */
async function collectIssuedCredential(): Promise<void> {
  try {
    const credential = await takeIssuedCredential(config.useService);
    if (!credential) return;
    const node = completeEnrollment(credential);
    if (node) {
      toast.success(translate('invite.enrolled', { client: credential.clientId }));
    } else {
      // Nothing was waiting for it: dropping the credential is the safe outcome, but losing a
      // secret silently is not, so it is said out loud.
      console.warn('[proxy] a credential was issued but no node was enrolling');
    }
  } catch (error) {
    console.error('[proxy] failed to read the enrolled credential:', error);
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
  const [running, state] = await Promise.all([
    invoke<boolean>('is_service_running').catch((error) => {
      console.error('[proxy] failed to query the service:', error);
      return false;
    }),
    invoke<'not_installed' | 'stopped' | 'running'>('get_service_status').catch(() => {
      // The service manager is unavailable; treat the service as absent for install controls.
      return 'not_installed' as const;
    }),
  ]);
  serviceRunning.value = running;
  // Installed and answering are different facts: the install button disappears as soon as the
  // unit exists, while TUN stays gated on the IPC connection actually being usable.
  serviceInstalled.value = state !== 'not_installed';

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
 *
 * Turning TUN on also moves the proxy into the service. It is not a preference being fiddled
 * with behind the user's back: creating a virtual network card needs rights this app does not
 * ask for at startup, so the only process that can run TUN is the one that runs elevated, and a
 * TUN request left on the unprivileged backend fails with `proxy.tun_unavailable` every time.
 */
function setUseTun(enabled: boolean): void {
  if (enabled && !serviceRunning.value) {
    toast.warning(translate('connect.tunRequiresService'));
    return;
  }

  if (enabled && !config.useService) {
    updateConfig({ useService: true, useTun: true });
    toast.info(translate('connect.tunSwitchedBackend'));
    return;
  }

  updateConfig({ useTun: enabled });
}

/* -- polling --------------------------------------------------------------------------------- */

/**
 * Replaces the manual "Refresh Status" button: the status, the node ID and every node's link kind
 * are re-read on a timer, so a service that dies, or a path iroh promotes from relay to direct,
 * shows up on its own within a few seconds.
 *
 * The timer is a chain of `setTimeout`s rather than a fixed `setInterval`: the interval depends
 * on the state the previous read returned, and a slow backend must not have requests piled onto
 * it while one is still in flight.
 */
let pollTimer: ReturnType<typeof setTimeout> | null = null;
let servicePollTimer: ReturnType<typeof setTimeout> | null = null;
let inFlight = false;
let consecutiveFailures = 0;

function nextInterval(): number {
  if (consecutiveFailures >= FAILURES_BEFORE_BACKOFF) return POLL_BACKOFF_MS;
  if (status.value.mode === 'starting') return POLL_STARTING_MS;
  return status.value.running ? POLL_RUNNING_MS : POLL_STOPPED_MS;
}

async function pollOnce(): Promise<void> {
  if (inFlight) return;
  inFlight = true;
  try {
    const ok = await refresh();
    consecutiveFailures = ok ? 0 : consecutiveFailures + 1;
    stale.value = !ok && consecutiveFailures >= FAILURES_BEFORE_BACKOFF;
    if (status.value.running) await refreshEndpointLinks();
  } finally {
    inFlight = false;
  }
}

function schedulePoll(): void {
  if (pollTimer !== null) return;
  const wait = nextInterval();
  pollTimer = setTimeout(async () => {
    pollTimer = null;
    await pollOnce();
    schedulePoll();
  }, wait);
}

/**
 * The service gate has its own slow timer rather than riding the status poll: installing,
 * uninstalling or crashing the service is not something this store is told about, and a folded
 * laptop comes back to a different answer than the one it left with.
 */
function scheduleServicePoll(): void {
  if (servicePollTimer !== null) return;
  servicePollTimer = setTimeout(async () => {
    servicePollTimer = null;
    await refreshServiceRunning();
    scheduleServicePoll();
  }, SERVICE_POLL_MS);
}

/** Starts both polls. Idempotent: the shell calls it once, and so can a page. */
function startPolling(): void {
  schedulePoll();
  scheduleServicePoll();
}

function stopPolling(): void {
  if (pollTimer !== null) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
  if (servicePollTimer !== null) {
    clearTimeout(servicePollTimer);
    servicePollTimer = null;
  }
}

/**
 * Forces an immediate re-read and re-arms the timers.
 *
 * Used when the app regains focus: a laptop that just woke up has been showing whatever the
 * status was before it slept, and waiting out the interval to find out is the wrong default.
 */
async function refreshNow(): Promise<void> {
  // The service gate first: when the state it carries is stale, so is every button it enables.
  await refreshServiceRunning();
  await pollOnce();
  // Re-arm both timers: stopping clears the service poll too, and re-arming only the status one
  // would leave the TUN gate frozen at whatever it read last.
  stopPolling();
  startPolling();
}

export function useProxyStore() {
  return {
    status,
    nodeId,
    busy,
    startupError,
    serviceRunning,
    serviceInstalled,
    /** What each node's traffic is actually doing right now. */
    endpointLinks,
    /** The mode the last start asked for; compared against what actually runs. */
    requestedMode,
    /** True when the status could not be read for a while; the panel says so out loud. */
    stale,
    isRunning: computed(() => status.value.running),
    canStart: computed(() => config.nodes.some((node) => node.ticket || node.endpointId)),
    start,
    stop,
    refresh,
    refreshNow,
    refreshNodeId,
    refreshServiceRunning,
    setUseTun,
    linkKindFor,
    startPolling,
    stopPolling,
  };
}

/** Called once at startup by the shell, before the first status render. */
export async function initProxyState(): Promise<void> {
  await refreshServiceRunning();
  await refresh();
  // From here on the panel keeps itself up to date; nothing in the UI has to ask for a refresh.
  startPolling();
}

/**
 * Called by the shell when the window becomes visible again.
 *
 * The poll keeps running while the app is in the background, but a machine that has been asleep
 * answers differently the moment it wakes, so the first thing to do is read, not wait.
 */
export function onAppFocused(): void {
  void refreshNow();
}
