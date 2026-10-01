<script setup lang="ts">
/**
 * The credential door, as the line that opens and shuts a page.
 *
 * It answers the question a reveal button cannot: is the door open, how long has
 * it got, and can this machine be asked at all — and it is the same line that
 * opens it, which is the difference between a page that says it is shut and a
 * page that lets you do something about it.
 *
 * `reason` is what the operating system is told it is being asked for, in the
 * user's language: the page knows what is behind the door and the door does not.
 *
 * The countdown is this component's own: the store hands over what is left of
 * the window, and counting it down here keeps a timer out of every surface that
 * merely wants to know whether it may show something.
 */
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';
import AppIcon from './base/AppIcon.vue';
import { useCredentialGate } from '../stores/gate';

const props = defineProps<{ reason: string }>();

const { t } = useI18n();
const { unlocked, msRemaining, ready, canAuthenticate, pending, lock, ensureUnlocked } =
  useCredentialGate();

/** mm:ss, which is all the precision a two-minute window needs. */
const remaining = computed(() => {
  const total = Math.ceil(msRemaining.value / 1_000);
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
});

/**
 * Shut until the machine has said otherwise.
 *
 * `ready` is false only until the first read, and a door that has not been read
 * is not one that has been opened — so the pending state is the shut one rather
 * than its own thing, which is also the answer a page should give before it
 * knows: showing less is the safe direction to be wrong in.
 */
const state = computed<'locked' | 'unlocked' | 'unavailable'>(() => {
  if (!ready.value) return 'locked';
  if (!canAuthenticate.value) return 'unavailable';
  return unlocked.value ? 'unlocked' : 'locked';
});

const text = computed(() => {
  switch (state.value) {
    case 'unavailable':
      return t('gate.unavailableShort');
    case 'unlocked':
      return t('gate.unlockedFor', { time: remaining.value });
    default:
      return t('gate.lockedTitle');
  }
});

/** Opens the door, or shuts it again without waiting for the window to lapse. */
async function toggle(): Promise<void> {
  if (unlocked.value) {
    await lock();
    return;
  }
  await ensureUnlocked(props.reason);
}
</script>

<template>
  <div class="credential-lock" :class="`credential-lock--${state}`">
    <AppIcon :name="state === 'unlocked' ? 'unlock' : 'lock'" :size="14" />
    <span class="credential-lock__text">{{ text }}</span>
    <!-- Nothing to press where there is nothing to ask: the page says why instead.
         While the machine is being asked, the button says so — a press that
         looks unanswered is a press that looks broken. -->
    <button
      v-if="state !== 'unavailable'"
      type="button"
      class="credential-lock__action"
      :disabled="pending"
      @click="toggle"
    >
      {{ pending ? t('gate.confirming') : unlocked ? t('gate.lockNow') : t('gate.unlock') }}
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

.credential-lock--unlocked {
  border-color: var(--accent-subtle);
  background: var(--accent-subtle);
  color: var(--accent-text);
}

.credential-lock--unavailable {
  border-color: var(--warning);
  background: var(--warning-subtle);
  color: var(--warning-text);
}

.credential-lock__text {
  white-space: nowrap;
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

.credential-lock--unlocked .credential-lock__action {
  color: inherit;
}

.credential-lock__action:hover {
  text-decoration: underline;
}

.credential-lock__action:disabled {
  cursor: default;
  text-decoration: none;
  opacity: 0.6;
}

.credential-lock__action:focus-visible {
  box-shadow: var(--focus-ring);
}
</style>
