<script setup lang="ts">
/**
 * The addresses this machine listens on, and what it does with the names it is given.
 *
 * The three addresses are the page's own fields — it writes them to the store and pulls them
 * back when the store changes — so they are handed in and written back through the model. The
 * DNS strategy belongs to the store, and the store is asked to change it.
 */
import { useI18n } from "vue-i18n";
import ConfigSection from "./ConfigSection.vue";
import { useConfigStore } from "../stores/config";

const localAddr = defineModel<string>("localAddr", { required: true });
const dnsAddr = defineModel<string>("dnsAddr", { required: true });
const upstreamDns = defineModel<string>("upstreamDns", { required: true });

const { t } = useI18n();
const { config, updateConfig } = useConfigStore();
</script>

<template>
  <ConfigSection :title="t('config.network')">
    <div class="form-grid">
      <div class="form-group">
        <label for="localAddr" class="form-label">{{ t('config.localAddr') }}</label>
        <div class="input-wrapper">
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2a10 10 0 0 0-10 10c0 4.42 2.87 8.17 6.84 9.49"/>
              <path d="M12 2a10 10 0 0 1 10 10c0 4.42-2.87 8.17-6.84 9.49"/>
              <path d="M12 12l4 4"/>
              <path d="M12 12l-4 4"/>
              <path d="M12 12l4-4"/>
              <path d="M12 12l-4-4"/>
            </svg>
          </div>
          <input
            id="localAddr"
            v-model="localAddr"
            type="text"
            placeholder="127.0.0.1:8080"
            class="form-input"
          />
        </div>
      </div>

      <div class="form-group">
        <label for="dnsAddr" class="form-label">{{ t('config.dnsAddr') }}</label>
        <div class="input-wrapper">
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <polyline points="12 6 12 12 16 14"/>
            </svg>
          </div>
          <input
            id="dnsAddr"
            v-model="dnsAddr"
            type="text"
            placeholder="198.18.0.254:53"
            class="form-input"
          />
        </div>
      </div>

      <div class="form-group">
        <label for="upstreamDns" class="form-label">{{ t('config.upstreamDns') }}</label>
        <div class="input-wrapper">
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
            </svg>
          </div>
          <input
            id="upstreamDns"
            v-model="upstreamDns"
            type="text"
            placeholder="223.5.5.5:53"
            class="form-input"
          />
        </div>
      </div>

      <div class="form-group">
        <label for="dnsStrategy" class="form-label">{{ t('config.dnsStrategy') }}</label>
        <!-- No leading icon, like the relay select: a native select paints its own
             control, so an icon laid over one sits on top of it. -->
        <select
          id="dnsStrategy"
          v-model="config.dnsStrategy"
          class="form-select"
          @change="updateConfig({ dnsStrategy: config.dnsStrategy })"
        >
          <option value="scoped">{{ t('config.dnsStrategyScoped') }}</option>
          <option value="global">{{ t('config.dnsStrategyGlobal') }}</option>
          <option value="none">{{ t('config.dnsStrategyNone') }}</option>
        </select>
        <p class="hint">{{ t('config.dnsStrategyHint') }}</p>
      </div>
    </div>
  </ConfigSection>
</template>
