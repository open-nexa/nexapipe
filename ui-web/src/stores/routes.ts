/**
 * The route table, and the two ways the console changes it.
 *
 * A route the console writes goes through the instance's storage seam, so a
 * running instance picks it up on its next reload — the same way a route
 * written into the configuration file is picked up. The console never writes
 * the configuration itself.
 */
import { ref } from 'vue';
import { API, apiGet, apiWrite } from '../api/client';
import type { Route, RouteRequest, RoutesAnswer } from '../api/types';

const routes = ref<Route[]>([]);
const error = ref<string | null>(null);
const loading = ref(false);

export async function refreshRoutes(): Promise<void> {
  loading.value = true;
  try {
    const answer = await apiGet<RoutesAnswer>(API.routes);
    routes.value = answer.routes ?? [];
    error.value = null;
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    loading.value = false;
  }
}

/**
 * Adds a route.
 *
 * The instance answers with the new table, so the console shows what the
 * instance actually holds rather than what it asked for.
 */
export async function addRoute(request: RouteRequest): Promise<void> {
  try {
    const answer = await apiWrite<RoutesAnswer>(API.routes, 'POST', request);
    routes.value = answer.routes ?? [];
    error.value = null;
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
    throw cause;
  }
}

/**
 * Removes the route the list named by `id`.
 *
 * The id is the stable fingerprint the instance handed out, not a position:
 * it still names the same route after other rows have been added or removed.
 * Two routes may share a host and a path when their modes or backends differ,
 * and the id is what lets the instance remove exactly the row that was
 * selected.
 */
export async function removeRoute(id: string): Promise<void> {
  try {
    const answer = await apiWrite<RoutesAnswer>(`${API.routes}/${id}`, 'DELETE');
    routes.value = answer.routes ?? [];
    error.value = null;
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
    throw cause;
  }
}

export function useRoutesStore() {
  return {
    routes,
    error,
    loading,
    refresh: refreshRoutes,
    addRoute,
    removeRoute,
  };
}
