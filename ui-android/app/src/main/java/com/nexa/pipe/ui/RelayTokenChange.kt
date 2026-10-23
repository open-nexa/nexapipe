package com.nexa.pipe.ui

/**
 * What a change of the relay configuration does to the token.
 *
 * Named rather than a nullable string, because "the token stays" and "the
 * token goes" are two different things and a caller has to say which one it
 * means. A parameter that defaulted to the stored token carried a credential
 * over to whatever relay came next — which is how an invite could take a
 * bearer token to a host of its choosing.
 */
sealed interface RelayTokenChange {
    /**
     * The token stays bound to the relay it was issued for.
     *
     * It is kept while that relay is the one being configured, and dropped
     * when the configuration names another relay: a token does not follow a
     * change of relay.
     */
    data object Bound : RelayTokenChange

    /**
     * The token goes, whatever the relay is.
     *
     * For a change that brings no token of its own: an invite names a relay
     * and carries no token for it, so the token this phone holds goes with the
     * import rather than travelling to the relay the invite names.
     */
    data object Drop : RelayTokenChange

    /** The token is this one, and it was issued for the relay being configured. */
    data class Set(val token: String) : RelayTokenChange
}
