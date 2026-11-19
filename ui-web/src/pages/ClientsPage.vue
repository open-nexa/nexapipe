<script setup lang="ts">
/**
 * The clients, and the two ways they change.
 *
 * A client is never shown with its secret: the instance does not send one,
 * and the console has nowhere to put it. Issuing a credential is a write the
 * instance answers with the new client table.
 */
import { ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useClientsStore } from '../stores/clients';
import { formatTimestamp } from '../utils/format';

const { t } = useI18n();
const { clients, enabled, error, addClient, revokeClient } = useClientsStore();

const issuing = ref(false);
const notice = ref<string | null>(null);

const clientId = ref('');
const deviceId = ref('');
const publicKey = ref('');
const force = ref(false);

function reset(): void {
  clientId.value = '';
  deviceId.value = '';
  publicKey.value = '';
  force.value = false;
}

async function submit(): Promise<void> {
  try {
    await addClient({
      client_id: clientId.value.trim(),
      device: deviceId.value.trim() || undefined,
      public_key: publicKey.value.trim() || undefined,
      force: force.value,
    });
    notice.value = t('clients.issued');
    reset();
    issuing.value = false;
  } catch {
    // The store has the reason; the banner shows it.
  }
}

async function revoke(id: string, device?: string): Promise<void> {
  if (!window.confirm(t('clients.confirmRevoke', { id }))) return;
  try {
    await revokeClient(id, device);
    notice.value = t('clients.revoked');
  } catch {
    // The store has the reason; the banner shows it.
  }
}
</script>

<template>
  <section class="page">
    <div class="page__head">
      <h1 class="page__title">{{ t('clients.title') }}</h1>
      <button class="button" type="button" @click="issuing = !issuing">
        {{ t('clients.add') }}
      </button>
    </div>

    <p class="page__lead">{{ enabled ? t('clients.enabled') : t('clients.disabled') }}</p>
    <p v-if="error" class="banner banner--error">{{ error }}</p>
    <p v-if="notice" class="banner banner--ok">{{ notice }}</p>

    <form v-if="issuing" class="form" @submit.prevent="submit">
      <label class="field">
        <span class="field__label">{{ t('clients.clientLabel') }}</span>
        <input v-model="clientId" class="field__input" required spellcheck="false" />
      </label>
      <label class="field">
        <span class="field__label">{{ t('clients.deviceLabel') }}</span>
        <input v-model="deviceId" class="field__input" spellcheck="false" />
      </label>
      <label class="field">
        <span class="field__label">{{ t('clients.publicKeyLabel') }}</span>
        <input v-model="publicKey" class="field__input" spellcheck="false" />
        <span class="field__hint">{{ t('clients.publicKeyHint') }}</span>
      </label>
      <label class="field field--check">
        <input v-model="force" type="checkbox" />
        <span class="field__label">{{ t('clients.force') }}</span>
      </label>
      <div class="form__actions">
        <button class="button" type="submit">{{ t('clients.add') }}</button>
        <button class="button button--quiet" type="button" @click="issuing = false">
          {{ t('common.close') }}
        </button>
      </div>
    </form>

    <p v-if="!clients.length" class="page__empty">{{ t('clients.none') }}</p>

    <table v-else class="table">
      <thead>
        <tr>
          <th>{{ t('clients.id') }}</th>
          <th>{{ t('clients.enrolled') }}</th>
          <th>{{ t('clients.created') }}</th>
          <th>{{ t('clients.lastUsed') }}</th>
          <th>{{ t('clients.failedAttempts') }}</th>
          <th>{{ t('clients.lockedUntil') }}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="client in clients" :key="client.id">
          <td class="mono">{{ client.id }}</td>
          <td>
            <span :class="client.has_secret ? 'tag tag--ok' : 'tag'">
              {{ client.has_secret ? t('clients.enrolled') : t('clients.notEnrolled') }}
            </span>
            <span v-if="client.enrollment_pending" class="tag tag--warn">
              {{ t('clients.enrollmentPending') }}
            </span>
          </td>
          <td>{{ formatTimestamp(client.created_at) }}</td>
          <td>{{ formatTimestamp(client.last_used) }}</td>
          <td>{{ client.failed_attempts ?? 0 }}</td>
          <td>{{ formatTimestamp(client.locked_until) }}</td>
          <td>
            <button class="button button--danger" type="button" @click="revoke(client.id)">
              {{ t('clients.revoke') }}
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </section>
</template>
