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
 * Removes a route.
 *
 * The route is named by its host pattern and its path pattern, which is how
 * the instance knows it: two routes on the same host are two routes, and
 * removing one of them leaves the other one alone.
 */
export async function removeRoute(
  hostPattern: string,
  pathPattern: string | null,
): Promise<void> {
  try {
    const answer = await apiWrite<RoutesAnswer>(
      `${API.routes}/${encodeURIComponent(hostPattern)}` +
        `?path_pattern=${encodeURIComponent(pathPattern ?? '/')}`,
      'DELETE',
    );
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
