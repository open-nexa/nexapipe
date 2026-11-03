package com.nexa.pipe.ui

import com.nexa.pipe.provisioning.EndpointInvite
import com.nexa.pipe.provisioning.InviteTarget

/**
 * The Node ID an invite refers to, used as the primary key of an endpoint.
 *
 * A Node ID invite carries it directly. A ticket carries addresses and an
 * identity inside them, so its Node ID has to be resolved on the native side
 * first and handed in here; without it the ticket cannot be stored, and a
 * conflict check that saw null would silently treat the import as a brand new
 * endpoint.
 */
internal fun inviteNodeId(
    invite: EndpointInvite,
    resolvedTicketNodeId: String? = null
): String? =
    when (val target = invite.target) {
        is InviteTarget.NodeId -> target.id
        is InviteTarget.Ticket -> resolvedTicketNodeId
    }
