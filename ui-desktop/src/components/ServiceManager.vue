<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { useI18n } from "vue-i18n";
import { errorDetail, errorKey } from "../api/errors";
import type { ServiceState } from "../types";
import { useProxyStore } from "../stores/proxy";

const { t } = useI18n();

// Installing here changes whether the Connect page may offer TUN, and that gate lives in the
// proxy store. Nothing else refreshes it, so without this the TUN toggle stays switched off —
// and its "install service" button stays on screen — until the app is restarted.
// The same store also answers the question this panel cannot ask the service manager: whether
// something is *answering* on the IPC port. A registered service is up as far as the OS is
// concerned well before it listens, and a service that never answers anything cannot be read as
// one that is out of date.
const { refreshServiceRunning, serviceRunning } = useProxyStore();

const state = ref<ServiceState>("not_installed");
const isLoading = ref(false);
const busyWith = ref<"" | "install" | "upgrade" | "uninstall" | "start" | "stop">("");
const message = ref("");
const messageType = ref<"success" | "error" | "info">("info");

/// This build, which is what the service is compared against. Empty until the app has said,
/// and a comparison against nothing is one the panel does not draw.
const appVersion = ref("");
/// Which build the service says it is, once something on the IPC port is answering. `null` when
/// that answer did not come back — either nothing was reachable, which [`serviceRunning`] has
/// already ruled out by then, or the service predates the question and closes the connection
/// instead, which is the case the notice is for.
const serviceVersion = ref<string | null>(null);

/// A service can die on its own, so the panel re-reads the state instead of trusting the last
/// action it performed.
const POLL_INTERVAL_MS = 10_000;
let poll: number | undefined;

/// Spelled out rather than built from the state string, so the keys stay statically visible.
const stateLabel = computed(() => {
  switch (state.value) {
    case "running":
      return t("service.stateRunning");
    case "stopped":
      return t("service.stateStopped");
    default:
      return t("service.stateNotInstalled");
  }
});

async function refresh() {
  try {
    state.value = await invoke<ServiceState>("get_service_status");
  } catch (e) {
    console.error("[service] failed to read the service state:", errorDetail(e));
    state.value = "not_installed";
  }

  try {
    serviceVersion.value = await invoke<string | null>("get_service_version");
  } catch (e) {
    console.error("[service] failed to read the service version:", errorDetail(e));
    serviceVersion.value = null;
  }
}

/// A service answering the IPC port with a build other than this app's — or with none at all,
/// which is what a build predating the question does — is not running what installing would put
/// there. That is the drift worth reporting, and it is only ever the answer of a service we are
/// actually talking to.
///
/// Reachable is a different question from registered, and only the first one carries evidence.
/// A service that has just been started answers nothing yet, and neither does one whose socket
/// we failed to reach this time: both would otherwise be reported as stale builds for as long
/// as the panel's own poll takes. Nothing has to answer twice for this either — the proxy store
/// already polls whether something is on the IPC port, because TUN is gated on it.
const needsUpgrade = computed(
  () =>
    appVersion.value !== "" &&
    serviceRunning.value &&
    serviceVersion.value !== appVersion.value,
);

const needsUpgradeMessage = computed(() =>
  serviceVersion.value
    ? t("service.versionMismatch", { service: serviceVersion.value, app: appVersion.value })
    : t("service.versionUnknown", { app: appVersion.value }),
);

/**
 * Every one of these elevates through UAC / sudo / polkit when the process is not already
 * privileged, so the call can legitimately stay pending until the user answers the prompt.
 */
async function run(
  action: "install" | "upgrade" | "uninstall" | "start" | "stop",
  command: string,
  successKey: string,
  fallbackKey: string,
) {
  if (isLoading.value) return;

  isLoading.value = true;
  busyWith.value = action;

  try {
    await invoke<void>(command);
    message.value = t(successKey);
    messageType.value = "success";
  } catch (e) {
    message.value = t(errorKey(e, fallbackKey));
    messageType.value = "error";
    console.error(`[service] ${action} failed:`, errorDetail(e) || e);
  } finally {
    // The state is re-read even after a failure: an install that could not start the service, or
    // an uninstall that was refused, still leaves something behind to show.
    await refresh();
    // And so is every other surface that depends on the service existing — see the import note.
    void refreshServiceRunning();
    isLoading.value = false;
    busyWith.value = "";
    setTimeout(() => {
      message.value = "";
    }, 3000);
  }
}

function installService() {
  return run("install", "install_service", "service.installed", "error.service.install_failed");
}

/// Reinstalling *is* the upgrade: installing re-points the service at this build and restarts
/// it, so a service left behind by an earlier version of the app ends up running this one.
function upgradeService() {
  return run("upgrade", "install_service", "service.upgraded", "error.service.install_failed");
}

function uninstallService() {
  return run("uninstall", "uninstall_service", "service.uninstalled", "error.service.uninstall_failed");
}

function startService() {
  return run("start", "start_service", "service.started", "error.service.start_failed");
}

function stopService() {
  return run("stop", "stop_service", "service.stopped", "error.service.stop_failed");
}

onMounted(() => {
  // Read once: it is this build's own version, and outside a Tauri window there is none — in
  // which case the panel simply stops drawing the comparison.
  void getVersion()
    .then((value) => {
      appVersion.value = value;
    })
    .catch((e) => console.debug("[service] app version unavailable:", e));

  refresh();
  poll = window.setInterval(refresh, POLL_INTERVAL_MS);
});

onBeforeUnmount(() => {
  if (poll !== undefined) window.clearInterval(poll);
});
</script>

<template>
  <div class="service-manager">
    <div class="card-header">
      <h2>{{ t("service.title") }}</h2>
      <div class="card-header-decoration"></div>
    </div>
    
    <div class="service-status">
      <div class="status-row">
        <div class="status-left">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
          </svg>
          <span class="status-label">{{ t("service.status") }}</span>
        </div>
        <div class="status-right">
          <span class="status-value" :class="state">
            <span class="status-dot"></span>
            {{ stateLabel }}
          </span>
        </div>
      </div>
    </div>

    <div v-if="needsUpgrade" class="outdated">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      </svg>
      <div class="outdated-body">
        <span>{{ needsUpgradeMessage }}</span>
        <button
          class="btn btn-outline"
          :disabled="isLoading"
          @click="upgradeService"
        >
          <svg v-if="busyWith === 'upgrade'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
          </svg>
          <span>{{ busyWith === 'upgrade' ? t("service.upgrading") : t("service.upgrade") }}</span>
        </button>
      </div>
    </div>

    <div v-if="message" class="message" :class="messageType">
      <svg v-if="messageType === 'success'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polyline points="20 6 9 17 4 12"/>
      </svg>
      <svg v-else-if="messageType === 'error'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="16" x2="12" y2="12"/>
        <line x1="12" y1="8" x2="12.01" y2="8"/>
      </svg>
      <span>{{ message }}</span>
    </div>

    <div class="service-actions">
      <button
        class="btn btn-outline"
        :disabled="isLoading || state !== 'not_installed'"
        @click="installService"
      >
        <svg v-if="busyWith === 'install'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 5v14"/>
          <path d="M5 12h14"/>
        </svg>
        <span>{{ busyWith === 'install' ? t("service.installing") : t("service.install") }}</span>
      </button>

      <button
        class="btn btn-outline"
        :disabled="isLoading || state !== 'stopped'"
        @click="startService"
      >
        <svg v-if="busyWith === 'start'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
        <span>{{ busyWith === 'start' ? t("service.starting") : t("service.start") }}</span>
      </button>

      <button
        class="btn btn-outline"
        :disabled="isLoading || state !== 'running'"
        @click="stopService"
      >
        <svg v-if="busyWith === 'stop'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="6" y="6" width="12" height="12" rx="1"/>
        </svg>
        <span>{{ busyWith === 'stop' ? t("service.stopping") : t("service.stop") }}</span>
      </button>

      <button
        class="btn btn-outline btn-danger"
        :disabled="isLoading || state === 'not_installed'"
        @click="uninstallService"
      >
        <svg v-if="busyWith === 'uninstall'" class="btn-icon spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
        <span>{{ busyWith === 'uninstall' ? t("service.uninstalling") : t("service.uninstall") }}</span>
      </button>
    </div>

    <div class="service-hints">
      <div class="hint-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
        </svg>
        <span>{{ t("service.hintElevation") }}</span>
      </div>
      <div class="hint-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 8v4l3 3"/>
          <circle cx="12" cy="12" r="10"/>
        </svg>
        <span>{{ t("service.hintAutostart") }}</span>
      </div>
      <div class="hint-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
          <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
        <span>{{ t("service.hintProduction") }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.service-manager {
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 28px;
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
}

.card-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
}

.card-header-decoration {
  flex: 1;
  height: 3px;
  background: var(--gradient-primary);
  border-radius: 2px;
}

.service-status {
  background: var(--surface-2);
  border-radius: var(--radius-md);
  padding: 18px 20px;
  margin-bottom: 16px;
  border: 1px solid var(--border-light);
}

.status-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.status-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-left svg {
  width: 18px;
  height: 18px;
  color: var(--text-muted);
}

.status-label {
  font-size: 14px;
  color: var(--text-secondary);
  font-weight: 500;
}

.status-right {
  display: flex;
  align-items: center;
}

.status-value {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  padding: 6px 14px;
  border-radius: 14px;
  transition: all var(--transition-normal);
}

.status-value.running {
  color: var(--success-600);
  background: var(--success-50);
  border: 1px solid var(--success-200);
}

.status-value.stopped {
  color: var(--text-muted);
  background: var(--surface-3);
  border: 1px solid var(--border-color);
}

.status-value.not_installed {
  color: var(--text-muted);
  background: var(--surface-2);
  border: 1px dashed var(--border-color);
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.status-value.running .status-dot {
  background: var(--success-500);
  animation: pulse 2s ease-in-out infinite;
}

.status-value.stopped .status-dot,
.status-value.not_installed .status-dot {
  background: var(--text-muted);
}

@keyframes pulse {
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
}

.outdated {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 14px;
  border-radius: var(--radius-md);
  margin-bottom: 16px;
  font-size: 13px;
  background: var(--warning-subtle);
  color: var(--warning-text);
  border-left: 3px solid var(--warning);
}

.outdated svg {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  margin-top: 2px;
}

.outdated-body {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 10px;
}

.outdated-body .btn {
  padding: 8px 14px;
  font-size: 13px;
  border-color: var(--warning);
  color: var(--warning-text);
}

.outdated-body .btn:hover:not(:disabled) {
  background: var(--warning-subtle);
}

.message {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px;
  border-radius: var(--radius-md);
  margin-bottom: 16px;
  font-size: 13px;
  transition: all var(--transition-normal);
}

.message svg {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.message.success {
  background: var(--success-50);
  color: var(--success-700);
  border-left: 3px solid var(--success-500);
}

.message.error {
  background: var(--error-50);
  color: var(--error-700);
  border-left: 3px solid var(--error-500);
}

.message.info {
  background: var(--primary-50);
  color: var(--primary-700);
  border-left: 3px solid var(--primary-500);
}

.service-actions {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  border-radius: var(--radius-md);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition-normal);
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none !important;
}

.btn svg {
  width: 16px;
  height: 16px;
}

.btn-outline {
  background: transparent;
  border: 1.5px solid var(--border-color);
  color: var(--text-secondary);
}

.btn-outline:hover:not(:disabled) {
  background: var(--surface-2);
  border-color: var(--primary-400);
  color: var(--primary-600);
}

.btn-outline.btn-danger {
  border-color: var(--error-300);
  color: var(--error-600);
}

.btn-outline.btn-danger:hover:not(:disabled) {
  background: var(--error-50);
  border-color: var(--error-500);
}

.spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

/* A spinner reports an operation in flight, so the global reduced-motion stop
   in base.css is answered here the same way as in AppButton.vue. */
@media (prefers-reduced-motion: reduce) {
  .spinner {
    animation-duration: 1s !important;
    animation-iteration-count: infinite !important;
  }
}

.service-hints {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.hint-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 12px;
  background: var(--surface-2);
  border-radius: var(--radius-sm);
}

.hint-item svg {
  width: 14px;
  height: 14px;
  color: var(--text-muted);
  flex-shrink: 0;
  margin-top: 2px;
}

.hint-item span {
  font-size: 12px;
  color: var(--text-muted);
  line-height: 1.4;
}

@media (max-width: 480px) {
  .service-actions {
    flex-direction: column;
  }
  
  .btn {
    width: 100%;
    justify-content: center;
  }
}
</style>