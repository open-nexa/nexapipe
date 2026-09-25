<script setup lang="ts">
import { ref, onMounted, onUnmounted } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "vue-i18n";
import { useToast } from "../composables/useToast";
import { writeClipboardText } from "../utils/clipboard";

const { t } = useI18n();
const toast = useToast();

interface LogEntry {
  id: number;
  timestamp: string;
  level: "trace" | "debug" | "info" | "warn" | "error";
  message: string;
}

/**
 * One `get_logs` answer. `fresh` marks a full tail read (first load, day roll-over, anything
 * that invalidates the backend's incremental cursor) and means the view must be *replaced*;
 * otherwise the lines are a continuation of what was already delivered.
 */
interface LogsPage {
  lines: string[];
  fresh: boolean;
}

const logs = ref<LogEntry[]>([]);
const filterLevel = ref<string>("all");
const autoScroll = ref(true);
const logContainer = ref<HTMLElement | null>(null);
let logId = 0;
const MAX_LOGS = 300; // Maximum number of log entries kept on the frontend

// Parse a Rust tracing log line:"2026-08-09T13:10:12.363812Z  INFO proxy::dns: msg"
function parseLogLine(line: string): LogEntry | null {
  if (!line.trim()) return null;
  const trimmed = line.replace(/\x1b\[[0-9;]*m/g, "").trim(); // Strip ANSI color codes
  const firstSpace = trimmed.indexOf(" ");
  const timestamp = firstSpace > 0 ? trimmed.slice(0, firstSpace) : "";
  const rest = firstSpace > 0 ? trimmed.slice(firstSpace).trim() : trimmed;

  const levelToken = rest.split(/\s+/)[0] || "";
  const level = levelToken.toUpperCase() as LogEntry["level"];
  const validLevels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
  if (!validLevels.includes(level)) {
    // Non-standard format (e.g. a plain text line); treat the whole line as the message
    return { id: ++logId, timestamp, level: "info", message: trimmed };
  }

  const message = rest.slice(levelToken.length).trim();
  return { id: ++logId, timestamp, level: level.toLowerCase() as LogEntry["level"], message };
}

async function loadLogs(append: boolean) {
  try {
    const page = await invoke<LogsPage>("get_logs", { limit: MAX_LOGS, append });
    const entries = page.lines
      .map(parseLogLine)
      .filter((l): l is LogEntry => l !== null);
    if (page.fresh) {
      logs.value = entries;
    } else {
      logs.value.push(...entries);
      if (logs.value.length > MAX_LOGS) {
        logs.value = logs.value.slice(-MAX_LOGS);
      }
    }
    scrollToBottom();
  } catch (e) {
    console.error("Failed to load logs:", e);
  }
}

function getLevelColor(level: string) {
  switch (level) {
    case "trace":
      return "#8b5cf6";
    case "debug":
      return "#3b82f6";
    case "info":
      return "#22c55e";
    case "warn":
      return "#f59e0b";
    case "error":
      return "#ef4444";
    default:
      return "#6b7280";
  }
}

/**
 * Log levels are technical tokens in the file, but they are also UI labels here (the filter and
 * the badge), so they go through i18n like any other label — uppercasing them would be a
 * `text-transform` by another name and does nothing in zh-CN.
 */
function getLevelLabel(level: string) {
  switch (level) {
    case "trace":
      return t("logs.levelTrace");
    case "debug":
      return t("logs.levelDebug");
    case "info":
      return t("logs.levelInfo");
    case "warn":
      return t("logs.levelWarn");
    case "error":
      return t("logs.levelError");
    default:
      return level;
  }
}

function filterLogs() {
  if (filterLevel.value === "all") return logs.value;
  return logs.value.filter(log => log.level === filterLevel.value);
}

function scrollToBottom() {
  if (logContainer.value && autoScroll.value) {
    logContainer.value.scrollTop = logContainer.value.scrollHeight;
  }
}

async function clearLogs() {
  try {
    // Tell the backend first: it marks the current file content as seen, so the next poll
    // delivers only lines written *after* the clear instead of replaying everything.
    await invoke("clear_logs");
    logs.value = [];
    toast.success(t("logs.cleared"));
  } catch (e) {
    toast.error(e);
  }
}

async function copyLogs() {
  if (logs.value.length === 0) return;
  const text = logs.value
    .map(log => `${log.timestamp} [${log.level.toUpperCase()}] ${log.message}`)
    .join("\n");
  if (await writeClipboardText(text)) {
    toast.success(t("common.copied"));
  } else {
    toast.error(t("common.copyFailed"));
  }
}

let intervalId: ReturnType<typeof setInterval> | null = null;

onMounted(async () => {
  await loadLogs(false);
  // Poll for new logs every 2 seconds (incremental)
  intervalId = setInterval(() => {
    loadLogs(true);
  }, 2000);
  scrollToBottom();
});

onUnmounted(() => {
  if (intervalId) {
    clearInterval(intervalId);
  }
});
</script>

<template>
  <div class="logs-page">
    <div class="logs-header">
      <div class="logs-filters">
        <select v-model="filterLevel" class="filter-select">
          <option value="all">{{ t('logs.levelAll') }}</option>
          <option value="trace">{{ t('logs.levelTrace') }}</option>
          <option value="debug">{{ t('logs.levelDebug') }}</option>
          <option value="info">{{ t('logs.levelInfo') }}</option>
          <option value="warn">{{ t('logs.levelWarn') }}</option>
          <option value="error">{{ t('logs.levelError') }}</option>
        </select>
        
        <label class="checkbox-label">
          <input type="checkbox" v-model="autoScroll" class="custom-checkbox" />
          <svg v-if="autoScroll" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <span>{{ t('logs.autoScroll') }}</span>
        </label>
      </div>
      
      <div class="logs-actions">
        <button class="btn btn-secondary" @click="copyLogs">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
          {{ t('logs.copy') }}
        </button>
        <button class="btn btn-outline" @click="clearLogs">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M3 6h18"/>
            <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
            <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>
          </svg>
          {{ t('logs.clear') }}
        </button>
      </div>
    </div>
    
    <div ref="logContainer" class="logs-container">
      <div v-if="logs.length === 0" class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14 2 14 8 20 8"/>
          <line x1="16" y1="13" x2="8" y2="13"/>
          <line x1="16" y1="17" x2="8" y2="17"/>
          <polyline points="10 9 9 9 8 9"/>
        </svg>
        <span>{{ t('logs.empty') }}</span>
      </div>
      
      <TransitionGroup name="log" tag="div" class="logs-list">
        <div 
          v-for="log in filterLogs()" 
          :key="log.id" 
          class="log-item"
          :class="log.level"
        >
          <span class="log-timestamp">{{ log.timestamp }}</span>
          <span class="log-level" :style="{ color: getLevelColor(log.level) }">
            {{ getLevelLabel(log.level) }}
          </span>
          <span class="log-message">{{ log.message }}</span>
        </div>
      </TransitionGroup>
    </div>
    
    <div class="logs-footer">
      <span class="logs-count">{{ t('logs.entryCount', { count: logs.length }) }}</span>
    </div>
  </div>
</template>

<style scoped>
.logs-page {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 180px);
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
  overflow: hidden;
}

.logs-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid var(--border-light);
  background: var(--surface-2);
}

.logs-filters {
  display: flex;
  align-items: center;
  gap: 16px;
}

.filter-select {
  padding: 8px 12px;
  border: 1.5px solid var(--border-color);
  border-radius: var(--radius-sm);
  font-size: 13px;
  background: var(--surface-1);
  color: var(--text-primary);
  cursor: pointer;
  transition: all var(--transition-normal);
}

.filter-select:focus {
  outline: none;
  border-color: var(--primary-500);
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 13px;
  color: var(--text-secondary);
}

.checkbox-label svg {
  width: 14px;
  height: 14px;
  color: var(--success-500);
}

.custom-checkbox {
  width: 16px;
  height: 16px;
  accent-color: var(--primary-500);
}

.logs-actions {
  display: flex;
  gap: 10px;
}

.btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 14px;
  border: none;
  border-radius: var(--radius-md);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition-normal);
}

.btn svg {
  width: 16px;
  height: 16px;
}

.btn-secondary {
  background: var(--surface-3);
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
}

.btn-secondary:hover {
  background: var(--surface-4);
}

.btn-outline {
  background: transparent;
  border: 1.5px solid var(--border-color);
  color: var(--text-secondary);
}

.btn-outline:hover {
  background: var(--surface-2);
  border-color: var(--error-400);
  color: var(--error-600);
}

.logs-container {
  flex: 1;
  overflow-y: auto;
  padding: 16px 20px;
  font-family: 'SF Mono', Monaco, 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.6;
}

.logs-container::-webkit-scrollbar {
  width: 6px;
}

.logs-container::-webkit-scrollbar-track {
  background: var(--surface-2);
}

.logs-container::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: 3px;
}

.logs-container::-webkit-scrollbar-thumb:hover {
  background: var(--text-muted);
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--text-muted);
  gap: 12px;
}

.empty-state svg {
  width: 48px;
  height: 48px;
  opacity: 0.5;
}

.logs-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.log-item {
  display: flex;
  gap: 12px;
  padding: 6px 10px;
  border-radius: var(--radius-sm);
  transition: background var(--transition-fast);
}

.log-item:hover {
  background: var(--surface-2);
}

.log-timestamp {
  color: var(--text-muted);
  flex-shrink: 0;
  min-width: 100px;
}

.log-level {
  font-weight: 600;
  flex-shrink: 0;
  min-width: 50px;
}

.log-message {
  color: var(--text-primary);
  word-break: break-all;
}

.log-item.error {
  background: var(--error-50);
}

.log-item.warn {
  background: var(--warning-50);
}

.logs-footer {
  padding: 12px 20px;
  border-top: 1px solid var(--border-light);
  background: var(--surface-2);
}

.logs-count {
  font-size: 12px;
  color: var(--text-muted);
}

.log-enter-active,
.log-leave-active {
  transition: all 0.3s ease;
}

.log-enter-from {
  opacity: 0;
  transform: translateY(-10px);
}

.log-leave-to {
  opacity: 0;
  transform: translateX(-20px);
}

@media (max-width: 600px) {
  .logs-header {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }
  
  .logs-filters {
    justify-content: space-between;
  }
  
  .logs-actions {
    justify-content: flex-end;
  }
  
  .log-item {
    flex-wrap: wrap;
  }
  
  .log-timestamp {
    min-width: auto;
  }
}
</style>