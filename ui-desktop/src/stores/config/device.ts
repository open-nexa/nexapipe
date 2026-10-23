/**
 * The name this machine answers as.
 *
 * A hostname is the obvious thing to name a machine after and the obvious way
 * to break the rule the server enforces, so the name is cleaned before it is
 * used and a random code goes on the end: two machines can easily share a
 * hostname, and a name that collides is a name the server cannot revoke one
 * of.
 *
 * Kept rather than regenerated, because a name that changed on every launch
 * would leave the server holding an entry for every device this machine has
 * ever claimed to be.
 */
import { hostname } from '@tauri-apps/plugin-os';
import type { ProxyConfig } from '../../types';
import { persist } from './persistence';

/** Longest device name the server accepts; mirrors `MAX_DEVICE_ID_LEN`. */
const DEVICE_ID_MAX = 255;

/** What a machine with no hostname to give is called. */
const DEVICE_ID_FALLBACK = 'nexa';

/** Eight hex characters, which is what goes after the hostname. */
function randomDeviceCode(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * A hostname, made into something the server will accept.
 *
 * Spaces become dashes rather than being dropped — "MacBook Pro" should read as
 * "MacBook-Pro" — and everything outside printable ASCII goes, because the name ends up as a
 * key in the server's config and in the log line for every handshake.
 */
function sanitizeDeviceName(raw: string): string {
  const printable = Array.from(raw.trim().replace(/\s+/g, '-'))
    .filter((char) => {
      const code = char.codePointAt(0) ?? 0;
      return code >= 0x21 && code <= 0x7e;
    })
    .join('');
  // Room has to be left for the code that goes after it, or a long hostname would be
  // truncated mid-name and the code lost — which is the part that keeps two machines apart.
  return printable.replace(/^-+|-+$/g, '').slice(0, DEVICE_ID_MAX - 9);
}

/** The server's own rule, mirrored so a refusal is caught here rather than at a handshake. */
function deviceIdIsUsable(id: string): boolean {
  return id.length > 0 && id.length <= DEVICE_ID_MAX && /^[\x21-\x7e]+$/.test(id);
}

/**
 * The name this machine answers as, generated once and kept.
 *
 * A hostname is the obvious thing to name a machine after and the obvious way to break the
 * rule the server enforces — printable ASCII with the space excluded, which "MacBook Pro" is
 * not — so it is cleaned before it is used, and a code goes on the end because two machines
 * can easily share a hostname and a name that collides is a name the server cannot revoke one
 * of. The code is random rather than read from the machine: there is no cross-platform
 * identifier in the tree that is not either a credential of its own or a different value after
 * a reinstall, and a random one is neither.
 *
 * Kept rather than regenerated, because a name that changed on every launch would leave the
 * server holding an entry for every device this machine has ever claimed to be. Module scope
 * rather than inside the store because `initConfigStore` needs it too, and it runs before any
 * component has asked the store for anything.
 */
export async function ensureDeviceIdFor(config: ProxyConfig): Promise<string> {
  if (deviceIdIsUsable(config.deviceId)) return config.deviceId;

  // A machine with nothing to say about its own name still gets one: an unnamed
  // device is the one that answers with the client's shared secret, which is
  // exactly the thing this is here to stop.
  const host = await hostname().catch(() => '');
  const name = sanitizeDeviceName(host ?? '') || DEVICE_ID_FALLBACK;
  config.deviceId = `${name}-${randomDeviceCode()}`.slice(0, DEVICE_ID_MAX);
  persist(config);
  return config.deviceId;
}
