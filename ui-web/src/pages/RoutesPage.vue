<script setup lang="ts">
/**
 * The route table, and the two ways it changes.
 *
 * A route the console writes goes through the instance's storage seam, so the
 * instance picks it up on its next reload — the same way a route written into
 * the configuration file is picked up. The console never writes the
 * configuration itself.
 */
import { ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRoutesStore } from '../stores/routes';

const { t } = useI18n();
const { routes, error, addRoute, removeRoute } = useRoutesStore();

const adding = ref(false);
const notice = ref<string | null>(null);

const hostPattern = ref('');
const pathPattern = ref('');
const backends = ref('');
const modes = ref('');

function reset(): void {
  hostPattern.value = '';
  pathPattern.value = '';
  backends.value = '';
  modes.value = '';
}

async function submit(): Promise<void> {
  try {
    await addRoute({
      host_pattern: hostPattern.value.trim(),
      path_pattern: pathPattern.value.trim() || null,
      backends: backends.value
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean),
      modes: modes.value
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean),
    });
    notice.value = t('routes.added');
    reset();
    adding.value = false;
  } catch {
    // The store has the reason; the banner shows it.
  }
}

async function remove(id: number, host: string, path: string | null): Promise<void> {
  if (!window.confirm(t('routes.confirmRemove', { host, path: path ?? '/' }))) return;
  try {
    await removeRoute(id);
    notice.value = t('routes.removed');
  } catch {
    // The store has the reason; the banner shows it.
  }
}
</script>

<template>
  <section class="page">
    <div class="page__head">
      <h1 class="page__title">{{ t('routes.title') }}</h1>
      <button class="button" type="button" @click="adding = !adding">
        {{ t('routes.add') }}
      </button>
    </div>

    <p v-if="error" class="banner banner--error">{{ error }}</p>
    <p v-if="notice" class="banner banner--ok">{{ notice }}</p>

    <form v-if="adding" class="form" @submit.prevent="submit">
      <label class="field">
        <span class="field__label">{{ t('routes.hostLabel') }}</span>
        <input v-model="hostPattern" class="field__input" required spellcheck="false" />
      </label>
      <label class="field">
        <span class="field__label">{{ t('routes.pathLabel') }}</span>
        <input v-model="pathPattern" class="field__input" spellcheck="false" />
      </label>
      <label class="field">
        <span class="field__label">{{ t('routes.backendsLabel') }}</span>
        <input v-model="backends" class="field__input" spellcheck="false" placeholder="http://127.0.0.1:8081" />
      </label>
      <label class="field">
        <span class="field__label">{{ t('routes.modesLabel') }}</span>
        <input v-model="modes" class="field__input" spellcheck="false" placeholder="http, tcp" />
      </label>
      <div class="form__actions">
        <button class="button" type="submit">{{ t('routes.add') }}</button>
        <button class="button button--quiet" type="button" @click="adding = false">
          {{ t('common.close') }}
        </button>
      </div>
    </form>

    <p v-if="!routes.length" class="page__empty">{{ t('routes.none') }}</p>

    <table v-else class="table">
      <thead>
        <tr>
          <th>{{ t('routes.host') }}</th>
          <th>{{ t('routes.path') }}</th>
          <th>{{ t('routes.modes') }}</th>
          <th>{{ t('routes.priority') }}</th>
          <th>{{ t('routes.backends') }}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="route in routes" :key="route.id">
          <td class="mono">{{ route.host_pattern }}</td>
          <td class="mono">{{ route.path_pattern ?? t('common.dash') }}</td>
          <td>{{ route.modes.join(', ') || t('common.dash') }}</td>
          <td>{{ route.priority }}</td>
          <td>
            <span v-for="backend in route.backends" :key="backend.url" class="backend">
              <span class="mono">{{ backend.url }}</span>
              <span v-if="route.health_checked" :class="backend.healthy ? 'tag tag--ok' : 'tag tag--bad'">
                {{ backend.healthy ? t('routes.healthy') : t('routes.unhealthy') }}
              </span>
              <span v-else class="tag">{{ t('routes.notProbed') }}</span>
            </span>
          </td>
          <td>
            <button
              class="button button--danger"
              type="button"
              @click="remove(route.id, route.host_pattern, route.path_pattern)"
            >
              {{ t('routes.remove') }}
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </section>
</template>
