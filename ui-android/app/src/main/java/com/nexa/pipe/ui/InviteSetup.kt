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

    /**
     * The Node ID a ticket invite names, resolved from the ticket by the
     * native side. The node list is keyed by Node ID everywhere — 2FA, device
     * keys, domain mappings, link readings — so a ticket invite has to be
     * reduced to that ID before it can be stored or compared with an existing
     * endpoint. Null when the invite carries a Node ID directly, or when the
     * ticket could not be read.
     *
     * Has a default so the setup a test builds by hand stays the one it was.
     */
    val resolvedNodeId: String? = null,
)
