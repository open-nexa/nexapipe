package com.nexa.pipe.ui

/**
 * The setup an invite import is measured against and applied to.
 *
 * The relay is global and the token was issued for one relay, so both are
 * read here rather than from the endpoint the invite names: an invite
 * proposes a relay, it does not own one.
 */
internal data class InviteSetup(
    /** The endpoints as they stand. */
    val nodes: List<NodeConfig>,

    /** The relay mode in force. */
    val relayMode: String,

    /** The relay URL in force. */
    val relayUrl: String,

    /** The token the relay it was issued for is holding. */
    val relayAuthToken: String,
)
