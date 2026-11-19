/**
 * The clients, and the two ways the console changes them.
 *
 * A client is never shown with its secret: the instance does not send it, and
 * the console has nowhere to put one. Issuing a credential is a write the
 * instance answers with the new client table.
 *
 * The devices of a client are listed under it. Their ids are the fingerprints
 * of the keys the devices prove themselves with — not names the operator
 * picked — so a device is named by an id and cannot be renamed.
 */
import { ref } from 'vue';
import { API, apiGet, apiWrite } from '../api/client';
import type { Client, ClientRequest, ClientsAnswer } from '../api/types';

const clients = ref<Client[]>([]);
const enabled = ref(false);
const error = ref<string | null>(null);
const loading = ref(false);

export async function refreshClients(): Promise<void> {
  loading.value = true;
  try {
    const answer = await apiGet<ClientsAnswer>(API.clients);
    clients.value = answer.clients ?? [];
    enabled.value = answer.enabled ?? false;
    error.value = null;
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    loading.value = false;
  }
}

/**
 * Issues a credential to a client, or to one device of it.
 *
 * `force` replaces a credential that is already there. A device enrolled with
 * the old one stops authenticating the moment it changes, so the console asks
 * before it does.
 */
export async function addClient(request: ClientRequest): Promise<void> {
  try {
    const answer = await apiWrite<ClientsAnswer>(API.clients, 'POST', request);
    clients.value = answer.clients ?? [];
    enabled.value = answer.enabled ?? enabled.value;
    error.value = null;
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
    throw cause;
  }
}

/**
 * Drops a client's credential, or one device's.
 *
 * A device is named by its id. A client with no device named loses its own
 * credential and every device under it.
 */
export async function revokeClient(clientId: string, device?: string): Promise<void> {
  const query = device ? `?device=${encodeURIComponent(device)}` : '';
  try {
    const answer = await apiWrite<ClientsAnswer>(
      `${API.clients}/${encodeURIComponent(clientId)}${query}`,
      'DELETE',
    );
    clients.value = answer.clients ?? [];
    error.value = null;
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
    throw cause;
  }
}

export function useClientsStore() {
  return {
    clients,
    enabled,
    error,
    loading,
    refresh: refreshClients,
    addClient,
    revokeClient,
  };
}
