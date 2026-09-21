<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "vue-i18n";
import { errorDetail, errorKey } from "../api/errors";
import type { ServiceState } from "../types";

const { t } = useI18n();

const state = ref<ServiceState>("not_installed");
const isLoading = ref(false);
const busyWith = ref<"" | "install" | "uninstall" | "start" | "stop">("");
const message = ref("");
const messageType = ref<"success" | "error" | "info">("info");

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
}

/**
 * Every one of these elevates through UAC / sudo / polkit when the process is not already
 * privileged, so the call can legitimately stay pending until the user answers the prompt.
 */
async function run(
  action: "install" | "uninstall" | "start" | "stop",
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