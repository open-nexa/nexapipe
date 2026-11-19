<script setup lang="ts">
/**
 * The shell: the navigation, the language switch, and the poll.
 *
 * The poll is one timer for the whole console rather than one per page, so
 * that switching pages does not start a second reader of the same instance
 * and the three views never describe different moments.
 */
import { computed, onMounted, onUnmounted, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import { useTokenStore } from './stores/token';
import { useInstanceStore } from './stores/instance';
import { useRoutesStore } from './stores/routes';
import { useClientsStore } from './stores/clients';
import { SUPPORTED_LOCALES, currentLocale, setI18nLocale } from './i18n';
import TokenGate from './components/TokenGate.vue';

const { t } = useI18n();

const tokens = useTokenStore();
const instance = useInstanceStore();
const routes = useRoutesStore();
const clients = useClientsStore();

/** How often the instance is read while the console is open. */
const POLL_MS = 5000;

let timer: number | undefined;

async function refreshAll(): Promise<void> {
  await Promise.all([instance.refresh(), routes.refresh(), clients.refresh()]);
}

function startPolling(): void {
  stopPolling();
  timer = window.setInterval(() => void refreshAll(), POLL_MS);
}

function stopPolling(): void {
  if (timer !== undefined) {
    window.clearInterval(timer);
    timer = undefined;
  }
}

/** The one error the operator has to see: the instance is not answering. */
const unreachable = computed(() =>
  [instance.error, routes.error, clients.error].find((message) => Boolean(message)) ?? null,
);

onMounted(() => {
  if (tokens.hasToken()) {
    void refreshAll();
    startPolling();
  }
});

onUnmounted(stopPolling);

// A token that appears, or goes away, is the console opening or closing.
watch(
  () => tokens.token.value,
  (value) => {
    if (value) {
      void refreshAll();
      startPolling();
    } else {
      stopPolling();
    }
  },
);
</script>

<template>
  <TokenGate v-if="!tokens.hasToken()" />

  <div v-else class="shell">
    <header class="shell__header">
      <span class="shell__title">{{ t('app.title') }}</span>
      <nav class="shell__nav">
        <RouterLink to="/">{{ t('app.nav.overview') }}</RouterLink>
        <RouterLink to="/routes">{{ t('app.nav.routes') }}</RouterLink>
        <RouterLink to="/clients">{{ t('app.nav.clients') }}</RouterLink>
      </nav>
      <div class="shell__tools">
        <label class="shell__locale">
          <span class="visually-hidden">{{ t('app.language') }}</span>
          <select :value="currentLocale()" @change="setI18nLocale(($event.target as HTMLSelectElement).value)">
            <option v-for="entry in SUPPORTED_LOCALES" :key="entry.value" :value="entry.value">
              {{ entry.label }}
            </option>
          </select>
        </label>
        <button type="button" class="button button--quiet" @click="tokens.clearToken()">
          {{ t('app.signOut') }}
        </button>
      </div>
    </header>

    <p v-if="unreachable" class="banner banner--error">{{ unreachable }}</p>

    <main class="shell__main">
      <RouterView />
    </main>
  </div>
</template>
