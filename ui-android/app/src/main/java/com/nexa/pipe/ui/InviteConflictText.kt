package com.nexa.pipe.ui

import android.content.Context
import com.nexa.pipe.R
import com.nexa.pipe.provisioning.EndpointInvite

/**
 * The parts of the current setup an invite would overwrite, as the sentences
 * the confirmation shows.
 *
 * Empty means the import only adds things, so it can go through without a
 * question; domains merging into an existing node is additive too.
 *
 * The rule itself is `inviteConflictKinds`, which is a pure function and
 * is tested as one; this is the part that turns a conflict into the
 * sentence the confirmation shows.
 *
 * [localizedContext] is the locale-wrapped context: the strings are read
 * outside a composable scope, so they cannot be read with `stringResource`.
 */
internal fun inviteConflicts(
    setup: InviteSetup,
    localizedContext: Context,
    invite: EndpointInvite
): List<String> {
    val current = inviteNodeId(invite)?.let { id -> setup.nodes.firstOrNull { it.nodeId == id } }
    val conflicts = inviteConflictKinds(current, invite, setup.relayMode, setup.relayUrl).map { kind ->
        when (kind) {
            InviteConflict.TwoFactor -> {
                val client = current?.twoFactor?.clientId?.ifBlank {
                    localizedContext.getString(R.string.invite_conflict_2fa_current_client)
                } ?: localizedContext.getString(R.string.invite_conflict_2fa_current_client)
                localizedContext.getString(R.string.invite_conflict_2fa, client)
            }
            InviteConflict.EnrollmentReplacesTwoFactor ->
                localizedContext.getString(R.string.invite_conflict_enrollment)
            InviteConflict.PendingEnrollment ->
                localizedContext.getString(R.string.invite_conflict_enrollment_pending)
            InviteConflict.Relay ->
                localizedContext.getString(R.string.invite_conflict_relay)
        }
    }.toMutableList()
    // An invite names a relay and carries no token for it, so the token
    // this phone holds goes with the import. The confirmation says so:
    // the user is the one who has to enter the token the relay asks for,
    // and a credential that quietly travels to another relay is exactly
    // what this rule exists to stop.
    if (invite.relay != null && setup.relayAuthToken.isNotBlank()) {
        conflicts.add(localizedContext.getString(R.string.invite_conflict_relay_token))
    }
    return conflicts
}
