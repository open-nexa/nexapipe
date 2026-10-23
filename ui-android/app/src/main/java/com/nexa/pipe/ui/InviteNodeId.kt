package com.nexa.pipe.ui

import com.nexa.pipe.provisioning.EndpointInvite
import com.nexa.pipe.provisioning.InviteTarget

/**
 * The endpoint an invite refers to, or null when it carries a ticket
 * instead — a ticket bundles addresses the endpoint list has no room for.
 */
internal fun inviteNodeId(invite: EndpointInvite): String? =
    (invite.target as? InviteTarget.NodeId)?.id
