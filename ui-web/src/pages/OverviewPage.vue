<script setup lang="ts">
/**
 * The overview: what the instance is doing, who it is serving, and how its
 * backends are doing.
 *
 * Everything here is a read. The instance answers with three documents and
 * the console shows them side by side.
 */
import { useI18n } from 'vue-i18n';
import { useInstanceStore } from '../stores/instance';
import { formatBytes, formatDuration, formatMilliseconds } from '../utils/format';

const { t } = useI18n();
const { status, connections, health } = useInstanceStore();
</script>

<template>
  <section class="page">
    <h1 class="page__title">{{ t('overview.title') }}</h1>

    <p v-if="!status" class="page__empty">{{ t('common.loading') }}</p>

    <template v-else>
      <div class="cards">
        <div class="card">
          <span class="card__label">{{ t('overview.version') }}</span>
          <span class="card__value">{{ status.version }}</span>
        </div>
        <div class="card">
          <span class="card__label">{{ t('overview.uptime') }}</span>
          <span class="card__value">{{ formatDuration(status.uptime_seconds) }}</span>
        </div>
        <div class="card">
          <span class="card__label">{{ t('overview.connections') }}</span>
          <span class="card__value">{{ status.connections.active }}</span>
          <span class="card__note">
            {{ t('overview.direct') }} {{ status.connections.direct }} ·
            {{ t('overview.relayed') }} {{ status.connections.relayed }} ·
            {{ t('overview.unknown') }} {{ status.connections.unknown }}
          </span>
        </div>
        <div class="card">
          <span class="card__label">{{ t('overview.requests') }}</span>
          <span class="card__value">{{ status.requests.reduce((sum, row) => sum + row.count, 0) }}</span>
          <span class="card__note">{{ formatMilliseconds(status.request_duration_ms) }}</span>
        </div>
        <div class="card">
          <span class="card__label">{{ t('overview.traffic') }}</span>
          <span class="card__value">{{ formatBytes(status.traffic.sent_bytes) }}</span>
          <span class="card__note">{{ t('overview.received') }} {{ formatBytes(status.traffic.received_bytes) }}</span>
        </div>
        <div class="card">
          <span class="card__label">{{ t('overview.backends') }}</span>
          <span class="card__value">{{ status.backends.up }}</span>
          <span class="card__note">{{ t('overview.down') }} {{ status.backends.down }}</span>
        </div>
        <div class="card">
          <span class="card__label">{{ t('overview.inFlight') }}</span>
          <span class="card__value">{{ status.in_flight }}</span>
          <span class="card__note">{{ t('overview.routes') }} {{ status.routes }} · {{ t('overview.peers') }} {{ status.peers }}</span>
        </div>
        <div class="card">
          <span class="card__label">{{ t('overview.auth') }}</span>
          <span class="card__value">{{ status.auth.enabled ? t('overview.authEnabled') : t('overview.authDisabled') }}</span>
          <span class="card__note">{{ status.auth.clients }}</span>
        </div>
      </div>

      <h2 class="page__subtitle">{{ t('overview.connectionsTitle') }}</h2>
      <p v-if="!connections.length" class="page__empty">
        {{ t('overview.noConnections') }}
      </p>
      <table v-else class="table">
        <thead>
          <tr>
            <th>{{ t('overview.client') }}</th>
            <th>{{ t('overview.device') }}</th>
            <th>{{ t('overview.path') }}</th>
            <th>{{ t('overview.uptime') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="peer in connections" :key="peer.endpoint_id">
            <td>{{ peer.client_id ?? t('common.dash') }}</td>
            <td class="mono">{{ peer.device ?? t('common.dash') }}</td>
            <td>{{ peer.path }}</td>
            <td>{{ formatDuration(peer.connected_for_seconds) }}</td>
          </tr>
        </tbody>
      </table>

      <h2 class="page__subtitle">{{ t('overview.healthTitle') }}</h2>
      <p v-if="!health.length" class="page__empty">{{ t('overview.noHealth') }}</p>
      <table v-else class="table">
        <thead>
          <tr>
            <th>{{ t('routes.host') }}</th>
            <th>{{ t('routes.backends') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in health" :key="entry.host_pattern">
            <td class="mono">{{ entry.host_pattern }}</td>
            <td>
              <span v-for="backend in entry.backends" :key="backend.url" class="backend">
                <span class="mono">{{ backend.url }}</span>
                <span :class="backend.healthy ? 'tag tag--ok' : 'tag tag--bad'">
                  {{ backend.healthy ? t('routes.healthy') : t('routes.unhealthy') }}
                </span>
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </template>
  </section>
</template>
