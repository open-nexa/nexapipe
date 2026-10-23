<script setup lang="ts">
/**
 * Which relay this machine dials.
 *
 * Moved here from the settings page because it is configuration, not a preference: which relay
 * this machine dials is part of how it connects, and a custom relay's bearer token is a
 * credential the door stands in front of.
 *
 * The values are the store's and are shown as they stand there. What is typed is reported to the
 * page, which keeps the raw text in the store while the field is being typed into, and asks the
 * store to take the URL or the token when the field is left: a token belongs to the relay it was
 * issued for, and that is a question only the store may answer.
 */
import { useI18n } from "vue-i18n";
import ConfigSection from "./ConfigSection.vue";
import type { RelayMode } from "../types";

defineProps<{
  /** Which relay is in use. */
  relayMode: RelayMode;
  /** The relay this machine dials. */
  relayUrl: string;
  /** The bearer token of a custom relay. */
  relayAuthToken: string;
  /** The relay the stored token was issued for, so the pairing is visible. */
  relayAuthTokenRelay: string;
}>();

const emit = defineEmits<{
  /** Another relay is in use. */
  (e: "update:relayMode", mode: RelayMode): void;
  /** The URL as it is typed. */
  (e: "update:relayUrl", url: string): void;
  /** The URL field was left: the store trims it and rebinds the token to it. */
  (e: "commit:relayUrl"): void;
  /** The token as it is typed. */
  (e: "update:relayAuthToken", token: string): void;
  /** The token field was left: the store trims it and binds it to the relay. */
  (e: "commit:relayAuthToken"): void;
}>();

const { t } = useI18n();
</script>

<template>
  <ConfigSection :title="t('config.relay')">
    <div class="form-grid">
      <div class="form-group">
        <label for="relayMode" class="form-label">{{ t('config.relayMode') }}</label>
        <!-- No leading icon, unlike the fields beside it. A native select
             paints its own control, so an icon laid over one sits on top of
             it — and takes the click that was meant to open it. The 2FA
             algorithm select further up is drawn the same way. -->
        <select
          id="relayMode"
          :value="relayMode"
          class="form-select"
          @change="emit('update:relayMode', ($event.target as HTMLSelectElement).value as RelayMode)"
        >
          <option value="pinned">{{ t('config.relayPinned') }}</option>
          <option value="default">{{ t('config.relayDefault') }}</option>
          <option value="disabled">{{ t('config.relayDisabled') }}</option>
          <option value="custom">{{ t('config.relayCustom') }}</option>
        </select>
        <p class="hint">{{ t('config.relayModeHint') }}</p>
      </div>

      <div v-if="relayMode === 'custom'" class="form-group">
        <label for="relayUrl" class="form-label">{{ t('config.relayUrl') }}</label>
        <div class="input-wrapper">
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
          </div>
          <input
            id="relayUrl"
            :value="relayUrl"
            type="text"
            placeholder="https://relay.example.com"
            class="form-input"
            @input="emit('update:relayUrl', ($event.target as HTMLInputElement).value)"
            @change="emit('commit:relayUrl')"
          />
        </div>
        <p class="hint">{{ t('config.relayUrlHint') }}</p>
      </div>

      <div v-if="relayMode === 'custom'" class="form-group">
        <label for="relayAuthToken" class="form-label">{{ t('config.relayAuthToken') }}</label>
        <div class="input-wrapper">
          <div class="input-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
          <!-- Typed but never echoed: a custom relay's bearer token is a credential, which is
               the other reason this section is behind the door. -->
          <input
            id="relayAuthToken"
            :value="relayAuthToken"
            type="password"
            :placeholder="t('common.optional')"
            class="form-input"
            @input="emit('update:relayAuthToken', ($event.target as HTMLInputElement).value)"
            @change="emit('commit:relayAuthToken')"
          />
        </div>
        <p class="hint">{{ t('config.relayAuthTokenHint') }}</p>
        <!-- Which relay the stored token was issued for, so the pairing is
             visible: a token belongs to one relay, and the field says
             which. Empty when there is no token to pair it with. -->
        <p v-if="relayAuthTokenRelay" class="hint">
          {{ t('config.relayAuthTokenBoundTo', { relay: relayAuthTokenRelay }) }}
        </p>
      </div>
    </div>
  </ConfigSection>
</template>
