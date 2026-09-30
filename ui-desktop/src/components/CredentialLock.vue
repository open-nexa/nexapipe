<script setup lang="ts">
/**
 * The credential door, as a line on a page.
 *
 * It answers the question a reveal button cannot: is the door open, how long has
 * it got, and can this machine be asked at all. Shut is the normal state and
 * says nothing beyond the button — an open door is the one worth reporting,
 * because that is the state that expires and that the user might want to end.
 *
 * The countdown is this component's own: the store hands over what is left of
 * the window, and counting it down here keeps a timer out of every surface that
 * merely wants to know whether it may show something.
 */
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';
import AppIcon from './base/AppIcon.vue';
import { useCredentialGate } from '../stores/gate';

const { t } = useI18n();
const { unlocked, msRemaining, ready, canAuthenticate, lock } = useCredentialGate();

/** mm:ss, which is all the precision a two-minute window needs. */
const remaining = computed(() => {
  const total = Math.ceil(msRemaining.value / 1_000);
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
});
</script>

<template>
  <div v-if="ready && !canAuthenticate" class="credential-lock credential-lock--warning">
    <AppIcon name="alert-triangle" :size="14" />
    <span>{{ t('gate.unavailableShort') }}</span>
  </div>

  <div v-else-if="ready && unlocked" class="credential-lock">
    <AppIcon name="unlock" :size="14" />
    <span>{{ t('gate.unlockedFor', { time: remaining }) }}</span>
    <button type="button" class="credential-lock__action" @click="lock()">
      {{ t('gate.lockNow') }}
    </button>
  </div>
</template>

<style scoped>
.credential-lock {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-1) var(--space-3);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-full);
  background: var(--bg-inset);
  color: var(--text-secondary);
  font-size: var(--font-size-12);
}

.credential-lock--warning {
  border-color: var(--warning);
  background: var(--warning-subtle);
  color: var(--warning-text);
}

.credential-lock__action {
  border: none;
  background: transparent;
  padding: 0;
  color: var(--accent-text);
  font-size: var(--font-size-12);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
}

.credential-lock__action:hover {
  text-decoration: underline;
}

.credential-lock__action:focus-visible {
  box-shadow: var(--focus-ring);
}
</style>
