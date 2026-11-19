/**
 * What the instance is doing right now: its counters, the peers it is
 * serving, and the health of its backends.
 *
 * Three reads, one refresh. They belong together because they are three views
 * of one moment, and a page that showed the counters from one second and the
 * peers from another would be describing an instance that does not exist.
 */
import { ref } from 'vue';
import { API, apiGet } from '../api/client';
import type { ConnectionsAnswer, HealthAnswer, HealthEntry, Connection, InstanceStatus } from '../api/types';

/** The instance's own answer, split into the three things it carries. */
const status = ref<InstanceStatus | null>(null);
const connections = ref<Connection[]>([]);
const health = ref<HealthEntry[]>([]);

/** What went wrong the last time a read was attempted. */
const error = ref<string | null>(null);

/** Whether a read is in flight. */
const loading = ref(false);

/**
 * Reads the three views.
 *
 * A failure is remembered rather than thrown: a console that cannot reach the
 * instance has to say so on the page, and the page is the only place the
 * operator will look.
 */
export async function refreshInstance(): Promise<void> {
  loading.value = true;
  try {
    const [statusAnswer, connectionsAnswer, healthAnswer] = await Promise.all([
      apiGet<{ status: InstanceStatus }>(API.status),
      apiGet<ConnectionsAnswer>(API.connections),
      apiGet<HealthAnswer>(API.health),
    ]);
    status.value = statusAnswer.status;
    connections.value = connectionsAnswer.peers ?? [];
    health.value = healthAnswer.health ?? [];
    error.value = null;
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    loading.value = false;
  }
}

export function useInstanceStore() {
  return {
    status,
    connections,
    health,
    error,
    loading,
    refresh: refreshInstance,
  };
}
