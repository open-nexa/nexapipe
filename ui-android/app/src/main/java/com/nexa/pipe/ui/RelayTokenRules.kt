package com.nexa.pipe.ui

/**
 * The token that goes with a relay after a change of the configuration.
 *
 * The rule: a token belongs to the relay it was issued for, so it survives
 * only while that relay is the one being configured. An explicit token
 * belongs to the relay it comes with — that is where the user typed it — and
 * a change that brings no token of its own takes the stored one with it.
 *
 * The URL is compared trimmed, because that is how the native side reads it:
 * two spellings of one URL are one relay, and a token that goes to a
 * different spelling of the same relay goes to the same relay.
 */
internal fun relayTokenAfter(
    /** The URL of the relay being configured. */
    url: String,
    /** The token as it stands, and the relay it was issued for. */
    stored: RelayToken,
    /** What the change does to the token. */
    change: RelayTokenChange
): RelayToken {
    val token = when (change) {
        is RelayTokenChange.Set -> change.token
        RelayTokenChange.Drop -> ""
        RelayTokenChange.Bound ->
            if (stored.token.isNotBlank() && stored.relayUrl.trim() == url.trim()) {
                stored.token
            } else {
                ""
            }
    }
    return RelayToken(token = token, relayUrl = if (token.isBlank()) "" else url.trim())
}

/**
 * The token to hand to the native side for a relay.
 *
 * A token is sent to the relay it was issued for and to no other: one whose
 * relay is not the one being configured is not sent at all. The native side
 * has no way of knowing which relay issued a token, so the answer has to be
 * given here.
 */
internal fun relayTokenToSend(stored: RelayToken, url: String): String =
    if (stored.relayUrl.trim() == url.trim()) stored.token else ""
