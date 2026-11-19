/**
 * What this machine tells a server about itself when it enrolls.
 *
 * Four labels and no identity: the device is known by the fingerprint of its
 * key, worked out from the public half on both sides. A hostname is the
 * obvious label to give a machine, but hostnames repeat and can hold spaces,
 * so it travels as a label — where a repeat is fine — and never as an id.
 *
 * Nothing here is persisted. An enrollment carries these labels through to
 * the Rust side, which reports them alongside the credential it issues.
 */
import { getVersion } from '@tauri-apps/api/app';
import { hostname, platform, version as osVersion } from '@tauri-apps/plugin-os';
import type { DeviceInfo } from '../../types';

/**
 * The four labels this device reports, each read on its own.
 *
 * One failed lookup never drops the others: a platform without a version, or
 * a hostname without an app version, is still a useful description. A value
 * the platform could not provide is left out rather than sent as a blank.
 */
export async function deviceInfo(): Promise<DeviceInfo> {
  // Some lookups are synchronous, others return a promise. One that throws
  // must not drop the others, so each is read through the same guard.
  const read = (lookup: () => string | null | Promise<string | null>): Promise<string> => {
    try {
      return Promise.resolve(lookup())
        .then((value) => value ?? '')
        .catch(() => '');
    } catch {
      return Promise.resolve('');
    }
  };
  const [host, os, version, app] = await Promise.all([
    read(() => hostname()),
    read(() => platform()),
    read(() => osVersion()),
    read(() => getVersion()),
  ]);

  const info: DeviceInfo = {};
  const add = (key: keyof DeviceInfo, value: string): void => {
    const trimmed = value.trim();
    if (trimmed) info[key] = trimmed;
  };
  add('label', host);
  add('platform', os);
  add('model', version);
  add('appVersion', app);
  return info;
}
