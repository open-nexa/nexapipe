/**
 * The configuration itself.
 *
 * One reactive object, created while this module is imported: everything that
 * is not a credential is in here before the app mounts, and the credential
 * store is read into it afterwards by `initConfigStore`.
 *
 * It lives in a module of its own so that the pieces around it — the
 * persistence, the credential mirror, the node actions — all write to the same
 * object without any of them owning it.
 */
import { reactive } from 'vue';
import type { ProxyConfig } from '../../types';
import { loadConfig } from './persistence';

export const config = reactive<ProxyConfig>(loadConfig());
