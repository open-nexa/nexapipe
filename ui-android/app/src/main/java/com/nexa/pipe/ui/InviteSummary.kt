package com.nexa.pipe.ui

import android.content.Context
import com.nexa.pipe.R
import com.nexa.pipe.provisioning.EndpointInvite
import com.nexa.pipe.provisioning.InviteTarget
import java.util.Locale

/**
 * One line per field, so the confirmation reads like the invite itself.
 *
 * [localizedContext] is the locale-wrapped context: the strings are read
 * outside a composable scope, so they cannot be read with `stringResource`.
 */
internal fun inviteSummary(invite: EndpointInvite, localizedContext: Context): String =
    buildList<String> {
        val nodeLabel = when (val target = invite.target) {
            is InviteTarget.NodeId -> target.id
            // A ticket is a credential-sized string. A confirmation dialog
            // read at a glance needs a fingerprint, not the whole thing.
            is InviteTarget.Ticket -> "${target.ticket.take(12)}…"
        }
        add(localizedContext.getString(R.string.invite_summary_node, nodeLabel))
        invite.name?.let { add(localizedContext.getString(R.string.invite_summary_name, it)) }
        add(
            localizedContext.getString(
                R.string.invite_summary_domains,
                invite.domains.joinToString(", ").ifEmpty {
                    localizedContext.getString(R.string.invite_value_none)
                }
            )
        )
        val otp = invite.totp
        // A local, so the branch below can smart-cast it: `invite.enrollment!!`
        // was an assertion the compiler already knows is unnecessary.
        val enrollment = invite.enrollment
        add(
            when {
                otp != null -> localizedContext.getString(
                    R.string.invite_summary_2fa,
                    otp.clientId,
                    otp.algorithm.uppercase(Locale.ROOT)
                )
                enrollment != null -> localizedContext.getString(
                    R.string.invite_summary_enrollment,
                    enrollment.clientId
                )
                else -> localizedContext.getString(R.string.invite_summary_2fa_none)
            }
        )
        invite.relay?.let { add(localizedContext.getString(R.string.invite_summary_relay, it)) }
    }.joinToString("\n")
