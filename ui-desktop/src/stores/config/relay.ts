/**
 * The relay, and the bearer token that belongs to it.
 *
 * The rules are pure and are what they always were: a token is issued by one
 * relay and is good for that relay alone, so the token travels together with
 * the URL of the relay it was issued for, and a change of relay decides what
 * happens to it.
 *
 * The setters take the configuration they write into, rather than closing over
 * one: the store and the invite import both change the relay, and neither of
 * them may hold a second copy of the rules.
 */
import { translate } from '../../i18n';
import { useToast } from '../../composables/useToast';
import type { ProxyConfig, RelayMode } from '../../types';

/**
 * The bearer token of a custom relay, and the relay it was issued for.
 *
 * A token is issued by one relay and is good for that relay alone: it is a
 * bearer credential, and a relay that is handed a token it never issued
 * learns it — and can use it against the relay that did issue it. So the
 * token is kept together with the URL of the relay it belongs to, and that
 * URL is what decides whether the token may still be sent.
 *
 * The URL is the one the token was issued for, not the one in use: a mode
 * that does not use a relay URL at all leaves the token alone.
 */
export interface RelayToken {
  /** The token itself. Empty when there is none. */
  token: string;
  /** The URL of the relay the token was issued for. Empty when there is none. */
  relay: string;
}

/**
 * What a change of the relay configuration does to the token.
 *
 * Named rather than a nullable string, because "the token stays" and "the
 * token goes" are two different things and a caller has to say which one it
 * means. A change that said nothing carried the stored token over to
 * whatever relay came next — which is how an invite could take a bearer
 * credential to a host of its choosing.
 */
export type RelayTokenChange =
  /**
   * The token stays with the relay it was issued for: it is kept while that
   * relay is the one being configured, and dropped when the configuration
   * names another one.
   */
  | { kind: 'bound' }
  /**
   * The token is this one, and it was issued for the relay being configured.
   */
  | { kind: 'set'; token: string };

/**
 * The token that goes with a relay after a change of the configuration.
 *
 * The rule: a token belongs to the relay it was issued for, so it survives
 * only while that relay is the one being configured. An explicit token
 * belongs to the relay it comes with — that is where the user typed it.
 *
 * The URL is compared trimmed, because that is how it is written and read:
 * two spellings of one URL are one relay, and a token that goes to a
 * different spelling of the same relay goes to the same relay.
 */
export function relayTokenAfter(
  /** The URL of the relay being configured. */
  url: string,
  /** The token as it stands, and the relay it was issued for. */
  stored: RelayToken,
  /** What the change does to the token. */
  change: RelayTokenChange,
): RelayToken {
  let token = '';
  if (change.kind === 'set') {
    token = change.token.trim();
  } else if (stored.token.trim() !== '' && stored.relay.trim() === url.trim()) {
    token = stored.token;
  }
  return { token, relay: token === '' ? '' : url.trim() };
}

/**
 * The token to hand the proxy for a relay.
 *
 * A token is sent to the relay it was issued for and to no other: one whose
 * relay is not the one being configured is not sent at all. The backend has no
 * way of knowing which relay issued a token, so the answer is given here.
 */
export function relayTokenToSend(stored: RelayToken, url: string): string {
  if (stored.token.trim() === '') return '';
  if (stored.relay.trim() === '' || stored.relay.trim() !== url.trim()) return '';
  return stored.token;
}

/**
 * The relay a token read back from the credential store belongs to.
 *
 * The credential store keeps the relay token on its own — it is a global
 * entry, and the store has no room for the relay it was issued for. The
 * pairing lives in the configuration, beside the token.
 *
 * A payload written before the pairing existed carries no recorded relay, so
 * the token is bound to the relay the configuration names: that is the relay
 * it was last used with, and the next change of relay drops it. Dropping it
 * here instead would take the token of every machine that never changed its
 * relay away.
 */
export function relayTokenRelayFor(url: string, recorded: string): string {
  const relay = recorded.trim();
  return relay === '' ? url.trim() : relay;
}

/**
 * The token as it stands, and the relay it was issued for.
 *
 * Read through this rather than off the config, so that the pair is never
 * half-read: a token without its relay is a token that cannot be sent.
 */
export function currentRelayToken(config: ProxyConfig): RelayToken {
  return { token: config.relayAuthToken, relay: config.relayAuthTokenRelay };
}

/** Writes a token pair back into the config. */
export function applyRelayToken(config: ProxyConfig, token: RelayToken): void {
  config.relayAuthToken = token.token;
  config.relayAuthTokenRelay = token.relay;
}

/**
 * Sets the relay URL, and says what happens to the token.
 *
 * The token goes with the relay it was issued for: it is kept while that
 * relay is the one being configured, and dropped when the configuration
 * names another one. A manual edit and an invite that names a relay both
 * come through here, and neither of them carries a token for the relay it
 * names.
 */
export function writeRelayUrl(config: ProxyConfig, url: string): void {
  const trimmed = url.trim();
  const before = currentRelayToken(config);
  const after = relayTokenAfter(trimmed, before, { kind: 'bound' });
  config.relayUrl = trimmed;
  applyRelayToken(config, after);
  reportRelayTokenDrop(before, after);
}

/**
 * Sets the relay mode, and leaves the relay and its token alone.
 *
 * The mode says whether a relay is in use, not which one: the URL is kept
 * in every mode, so looking at another mode and coming back does not lose
 * the relay or the token issued for it.
 */
export function writeRelayMode(config: ProxyConfig, mode: RelayMode): void {
  config.relayMode = mode;
}

/**
 * Stores the token the user typed, bound to the relay it was typed for.
 *
 * The binding is the relay this machine is configured to use: a token is
 * issued by one relay and is good for that relay alone.
 */
export function writeRelayAuthToken(config: ProxyConfig, token: string): void {
  const before = currentRelayToken(config);
  const after = relayTokenAfter(config.relayUrl, before, { kind: 'set', token });
  applyRelayToken(config, after);
}

const toast = useToast();

/**
 * Says that a token was dropped.
 *
 * A token that goes is a credential the user has to enter again, and only the
 * user can enter it: the new relay's token is not something the app can
 * guess. So the drop is said out loud rather than left as an empty field.
 */
function reportRelayTokenDrop(before: RelayToken, after: RelayToken): void {
  if (before.token.trim() === '' || after.token.trim() !== '') return;
  console.info(
    '[config] the relay auth token was cleared: a token belongs to the relay it was issued for',
  );
  toast.warning(translate('config.relayTokenCleared'));
}
