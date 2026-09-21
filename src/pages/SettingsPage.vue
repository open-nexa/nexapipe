<script setup lang="ts">
import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import ServiceManager from "../components/ServiceManager.vue";
import { useConfigStore } from "../composables/useConfigStore";

const { config, updateConfig } = useConfigStore();

const autoStart = ref(false);
const minimizeOnClose = ref(true);
const logLevel = ref("info");
const isLoading = ref(false);

async function loadSettings() {
  isLoading.value = true;
  try {
    autoStart.value = await invoke<boolean>("is_auto_start_enabled").catch(() => false);
  } catch {
    autoStart.value = false;
  }
  isLoading.value = false;
}

async function saveAutoStart() {
  try {
    await invoke<string>("set_auto_start", { enabled: autoStart.value });
  } catch (e) {
    console.error("Failed to set auto start:", e);
  }
}

function handleUseServiceChange() {
  updateConfig({ useService: !config.useService });
}

loadSettings();
</script>

<template>
  <div class="settings-page">
    <div class="settings-section">
      <div class="card-header">
        <h2>Service Management</h2>
        <div class="card-header-decoration"></div>
      </div>
      
      <ServiceManager />
    </div>

    <div class="settings-section">
      <div class="card-header">
        <h2>Proxy Mode</h2>
        <div class="card-header-decoration"></div>
      </div>
      
      <div class="mode-options">
        <div 
          class="mode-option" 
          :class="{ active: !config.useService }"
          @click="handleUseServiceChange"
        >
          <div class="mode-icon normal">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/>
            </svg>
          </div>
          <div class="mode-info">
            <span class="mode-title">Normal Mode</span>
            <span class="mode-desc">Runs with standard user privileges; suitable for daily use</span>
          </div>
          <div class="mode-radio">
            <div class="radio-inner"></div>
          </div>
        </div>
        
        <div 
          class="mode-option" 
          :class="{ active: config.useService }"
          @click="handleUseServiceChange"
        >
          <div class="mode-icon service">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
          </div>
          <div class="mode-info">
            <span class="mode-title">Service Mode</span>
            <span class="mode-desc">Runs as a system service; requires administrator privileges</span>
          </div>
          <div class="mode-radio">
            <div class="radio-inner"></div>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="card-header">
        <h2>TUN Settings</h2>
        <div class="card-header-decoration"></div>
      </div>

      <div class="settings-list">
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"/>
              <line x1="12" y1="22" x2="12" y2="15.5"/>
              <line x1="22" y1="8.5" x2="12" y2="15.5"/>
              <line x1="2" y1="8.5" x2="12" y2="15.5"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">TUN Device Name</span>
              <span class="setting-hint">Virtual network interface name (auto-assigned by macOS; ignored on that platform)</span>
            </div>
          </div>
          <div class="setting-right">
            <input
              v-model="config.tunName"
              class="text-input"
              placeholder="nexa-tun"
              maxlength="15"
              @change="updateConfig({ tunName: config.tunName.trim() || 'nexa-tun' })"
            />
          </div>
        </div>
      </div>
    </div>

    
    <div class="settings-section">
      <div class="card-header">
        <h2>Relay Settings</h2>
        <div class="card-header-decoration"></div>
      </div>

      <div class="settings-list">
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="2" y1="12" x2="22" y2="12"/>
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">Relay Mode</span>
              <span class="setting-hint">Configure the iroh relay forwarding mode</span>
            </div>
          </div>
          <div class="setting-right">
            <select
              v-model="config.relayMode"
              class="select-input"
              @change="updateConfig({ relayMode: config.relayMode })"
            >
              <option value="pinned">Pinned (aps1-1, stable)</option>
              <option value="default">Default (all N0 relays)</option>
              <option value="disabled">Disabled (direct only)</option>
              <option value="custom">Custom URL</option>
            </select>
          </div>
        </div>

        <div class="setting-item" v-if="config.relayMode === 'custom'">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">Relay URL</span>
              <span class="setting-hint">Custom relay server address</span>
            </div>
          </div>
          <div class="setting-right">
            <input
              v-model="config.relayUrl"
              class="text-input"
              placeholder="https://relay.example.com"
              @change="updateConfig({ relayUrl: config.relayUrl.trim() })"
            />
          </div>
        </div>

        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">Force Relay</span>
              <span class="setting-hint">Always route connections through the relay server (disable direct connections)</span>
            </div>
          </div>
          <div class="setting-right">
            <button
              class="toggle"
              :class="{ active: config.forceRelay }"
              @click="updateConfig({ forceRelay: !config.forceRelay })"
            >
              <div class="toggle-thumb"></div>
            </button>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="card-header">
        <h2>2FA Authentication</h2>
        <div class="card-header-decoration"></div>
      </div>

      <div class="settings-list">
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">Enable 2FA Authentication</span>
              <span class="setting-hint">Perform TOTP two-step verification when connecting to the server</span>
            </div>
          </div>
          <div class="setting-right">
            <button
              class="toggle"
              :class="{ active: config.twoFactorEnabled }"
              @click="updateConfig({ twoFactorEnabled: !config.twoFactorEnabled })"
            >
              <div class="toggle-thumb"></div>
            </button>
          </div>
        </div>

        <template v-if="config.twoFactorEnabled">
          <div class="setting-item">
            <div class="setting-left">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="8" r="4"/>
                <path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>
              </svg>
              <div class="setting-info">
                <span class="setting-label">Client ID</span>
                <span class="setting-hint">Must match the ID configured under [auth.clients] on the server</span>
              </div>
            </div>
            <div class="setting-right">
              <input
                v-model="config.twoFactorClientId"
                class="text-input"
                placeholder="client-001"
                @change="updateConfig({ twoFactorClientId: config.twoFactorClientId.trim() })"
              />
            </div>
          </div>

          <div class="setting-item">
            <div class="setting-left">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="11" width="18" height="11" rx="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              <div class="setting-info">
                <span class="setting-label">TOTP Secret</span>
                <span class="setting-hint">Base32 secret key, generated with nexapipe --generate-2fa</span>
              </div>
            </div>
            <div class="setting-right">
              <input
                v-model="config.twoFactorSecret"
                class="text-input"
                type="password"
                placeholder="JBSWY3DPEHPK3PXP"
                @change="updateConfig({ twoFactorSecret: config.twoFactorSecret.trim() })"
              />
            </div>
          </div>

          <div class="setting-item">
            <div class="setting-left">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="2" y1="12" x2="22" y2="12"/>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
              </svg>
              <div class="setting-info">
                <span class="setting-label">Algorithm</span>
                <span class="setting-hint">Must match the algorithm in [auth] on the server</span>
              </div>
            </div>
            <div class="setting-right">
              <select
                v-model="config.twoFactorAlgorithm"
                class="select-input"
                @change="updateConfig({ twoFactorAlgorithm: config.twoFactorAlgorithm })"
              >
                <option value="sha1">SHA1 (default)</option>
                <option value="sha256">SHA256</option>
                <option value="sha512">SHA512</option>
              </select>
            </div>
          </div>
        </template>
      </div>
    </div>

<div class="settings-section">
      <div class="card-header">
        <h2>App Settings</h2>
        <div class="card-header-decoration"></div>
      </div>
      
      <div class="settings-list">
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 8v4l3 3"/>
              <circle cx="12" cy="12" r="10"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">Launch at Startup</span>
              <span class="setting-hint">Automatically run the proxy when the app launches</span>
            </div>
          </div>
          <div class="setting-right">
            <button 
              class="toggle" 
              :class="{ active: autoStart }"
              @click="autoStart = !autoStart; saveAutoStart()"
            >
              <div class="toggle-thumb"></div>
            </button>
          </div>
        </div>
        
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M5 12h14M12 5l7 7-7 7"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">Minimize on Close</span>
              <span class="setting-hint">Minimize to the system tray when the close button is clicked</span>
            </div>
          </div>
          <div class="setting-right">
            <button 
              class="toggle" 
              :class="{ active: minimizeOnClose }"
              @click="minimizeOnClose = !minimizeOnClose"
            >
              <div class="toggle-thumb"></div>
            </button>
          </div>
        </div>
        
        <div class="setting-item">
          <div class="setting-left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
              <polyline points="14 2 14 8 20 8"/>
              <line x1="16" y1="13" x2="8" y2="13"/>
            </svg>
            <div class="setting-info">
              <span class="setting-label">Log Level</span>
              <span class="setting-hint">Controls the verbosity of log output</span>
            </div>
          </div>
          <div class="setting-right">
            <select v-model="logLevel" class="select-input">
              <option value="trace">Trace</option>
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warn">Warn</option>
              <option value="error">Error</option>
            </select>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-section">
      <div class="card-header">
        <h2>About</h2>
        <div class="card-header-decoration"></div>
      </div>
      
      <div class="about-info">
        <div class="about-item">
          <span class="about-label">Version</span>
          <span class="about-value">v0.1.0</span>
        </div>
        <div class="about-item">
          <span class="about-label">Built With</span>
          <span class="about-value">Tauri + Vue 3</span>
        </div>
        <div class="about-item">
          <span class="about-label">License</span>
          <span class="about-value">MIT License</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.settings-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.settings-page::-webkit-scrollbar {
  width: 4px;
}

.settings-page::-webkit-scrollbar-track {
  background: transparent;
}

.settings-page::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: 2px;
}

.settings-section {
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 20px;
  box-shadow: var(--shadow-card);
  border: 1px solid var(--border-light);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 16px;
}

.card-header h2 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
}

.card-header-decoration {
  flex: 1;
  height: 2px;
  background: var(--gradient-primary);
  border-radius: 1px;
}

.mode-options {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.mode-option {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px;
  background: var(--surface-2);
  border-radius: var(--radius-md);
  border: 2px solid transparent;
  cursor: pointer;
  transition: all var(--transition-normal);
}

.mode-option:hover {
  background: var(--surface-3);
  border-color: var(--primary-200);
}

.mode-option.active {
  background: var(--primary-50);
  border-color: var(--primary-400);
}

.mode-icon {
  width: 40px;
  height: 40px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.mode-icon svg {
  width: 20px;
  height: 20px;
}

.mode-icon.normal {
  background: var(--success-100);
  color: var(--success-600);
}

.mode-icon.service {
  background: var(--warning-100);
  color: var(--warning-600);
}

.mode-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.mode-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}

.mode-desc {
  font-size: 12px;
  color: var(--text-muted);
}

.mode-radio {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  border: 2px solid var(--border-color);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all var(--transition-normal);
}

.mode-option.active .mode-radio {
  border-color: var(--primary-500);
}

.radio-inner {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: transparent;
  transition: all var(--transition-normal);
}

.mode-option.active .radio-inner {
  background: var(--primary-500);
}

.settings-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.setting-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 0;
  border-bottom: 1px solid var(--border-light);
}

.setting-item:last-child {
  border-bottom: none;
}

.setting-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.setting-left svg {
  width: 18px;
  height: 18px;
  color: var(--text-muted);
}

.setting-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.setting-label {
  font-size: 14px;
  font-weight: 500;
  color: var(--text-primary);
}

.setting-hint {
  font-size: 12px;
  color: var(--text-muted);
}

.setting-right {
  flex-shrink: 0;
}

.toggle {
  width: 44px;
  height: 24px;
  background: var(--surface-4);
  border-radius: 12px;
  border: none;
  cursor: pointer;
  position: relative;
  transition: background var(--transition-normal);
}

.toggle.active {
  background: var(--primary-500);
}

.toggle-thumb {
  position: absolute;
  top: 3px;
  left: 3px;
  width: 18px;
  height: 18px;
  background: white;
  border-radius: 50%;
  transition: transform var(--transition-normal);
  box-shadow: var(--shadow-sm);
}

.toggle.active .toggle-thumb {
  transform: translateX(20px);
}

.select-input {
  padding: 8px 12px;
  border: 1.5px solid var(--border-color);
  border-radius: var(--radius-sm);
  font-size: 13px;
  background: var(--surface-1);
  color: var(--text-primary);
  cursor: pointer;
  transition: all var(--transition-normal);
}

.select-input:focus {
  outline: none;
  border-color: var(--primary-500);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.text-input {
  width: 160px;
  padding: 8px 12px;
  border: 1.5px solid var(--border-color);
  border-radius: var(--radius-sm);
  font-size: 13px;
  background: var(--surface-1);
  color: var(--text-primary);
  transition: all var(--transition-normal);
}

.text-input:focus {
  outline: none;
  border-color: var(--primary-500);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.about-info {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.about-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.about-label {
  font-size: 13px;
  color: var(--text-muted);
}

.about-value {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-primary);
}

@media (max-width: 600px) {
  .mode-option {
    flex-direction: column;
    align-items: flex-start;
  }
  
  .mode-radio {
    margin-left: auto;
  }
}
</style>
