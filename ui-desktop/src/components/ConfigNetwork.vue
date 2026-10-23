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
const { config } = useConfigStore();
</script>

<template>
  <ConfigSection :title="t('config.network')">
    <div class="form-grid">
      <div class="form-group">
        <label for="localAddr" class="form-label">{{ t("config.localAddr") }}</label>
        <input
          id="localAddr"
          v-model="localAddr"
          type="text"
          placeholder="127.0.0.1:8080"
          class="form-input"
        />
      </div>

      <div class="form-group">
        <label for="dnsAddr" class="form-label">{{ t("config.dnsAddr") }}</label>
        <input
          id="dnsAddr"
          v-model="dnsAddr"
          type="text"
          placeholder="198.18.0.254:53"
          class="form-input"
        />
      </div>

      <div class="form-group">
        <label for="upstreamDns" class="form-label">{{ t("config.upstreamDns") }}</label>
        <input
          id="upstreamDns"
          v-model="upstreamDns"
          type="text"
          placeholder="223.5.5.5:53"
          class="form-input"
        />
      </div>

      <div class="form-group form-group--wide">
        <label for="dnsStrategy" class="form-label">{{ t("config.dnsStrategy") }}</label>
        <!-- No second write on change: `v-model` has already put the choice into the
             configuration, and the store watches it. A second write through `updateConfig`
             would write whatever the field happened to hold at that moment, which is not
             the same thing when the browser fires a change of its own. -->
        <select id="dnsStrategy" v-model="config.dnsStrategy" class="form-select">
          <option value="scoped">{{ t("config.dnsStrategyScoped") }}</option>
          <option value="global">{{ t("config.dnsStrategyGlobal") }}</option>
          <option value="none">{{ t("config.dnsStrategyNone") }}</option>
        </select>
        <p class="hint">{{ t("config.dnsStrategyHint") }}</p>
      </div>
    </div>
  </ConfigSection>
</template>
