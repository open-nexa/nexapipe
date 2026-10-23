package com.nexa.pipe.ui

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
data class RelayToken(
    /** The token itself. Empty when there is none. */
    val token: String = "",
    /** The URL of the relay the token was issued for. Empty when there is none. */
    val relayUrl: String = ""
)
