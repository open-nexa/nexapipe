package com.nexa.pipe.ui

import com.nexa.pipe.provisioning.EndpointInvite

/**
 * What an invite would overwrite.
 *
 * Named rather than described, so the rule can be tested without a Compose
 * scope and without a string table: the screen turns a conflict into the
 * sentence the confirmation shows.
 */
enum class InviteConflict {
    /** The 2FA credentials the endpoint holds. */
    TwoFactor,

    /**
     * The 2FA credentials the endpoint holds, which a one-time enrollment
     * replaces rather than adds to.
     */
    EnrollmentReplacesTwoFactor,

    /** A one-time enrollment token that has not been spent yet. */
    PendingEnrollment,

    /** The relay settings, which every endpoint shares. */
    Relay,
}

/**
 * Whether this record holds a credential the endpoint can authenticate with.
 *
 * A secret is one; so is a public key, because the private half is sealed
 * beside it. A record that carries neither is a shape rather than a
 * credential — which is what an endpoint looks like after its enrollment
 * token has been spent and before the answer has arrived.
 */
fun NodeTwoFactor.hasCredential(): Boolean =
    secret.isNotBlank() || !publicKey.isNullOrBlank()

/**
 * The parts of the current setup an invite would overwrite.
 *
 * Empty means the import only adds things, so it can go through without a
 * question; domains merging into an existing node is additive too.
 *
 * A one-time enrollment counts as a replacement, and it is the case this rule
 * used to miss: a registration code carries no secret, so it raised no
 * conflict, and applying it dropped the credential the endpoint already had
 * — with no question asked, and with the guard in `ProxyConnector` that keeps
 * an endpoint from spending a token it already has a credential for defeated
 * by the drop that came before it.
 *
 * `current` is the endpoint the invite names, or null when it names none.
 * `relayMode` and `relayUrl` are the relay settings as they stand: the relay
 * is global, so it is not part of the endpoint and is passed separately.
 */
internal fun inviteConflictKinds(
    current: NodeConfig?,
    invite: EndpointInvite,
    relayMode: String,
    relayUrl: String
): List<InviteConflict> = buildList {
    invite.totp?.let { otp ->
        // Only this endpoint's credentials are replaced: 2FA belongs to the
        // endpoint, so every other one is left alone.
        val twoFactor = current?.twoFactor
        if (twoFactor != null && twoFactor.hasCredential() &&
            (twoFactor.secret != otp.secret || twoFactor.clientId != otp.clientId)
        ) {
            add(InviteConflict.TwoFactor)
        }
    }

    invite.enrollment?.let {
        if (current?.twoFactor?.hasCredential() == true) {
            add(InviteConflict.EnrollmentReplacesTwoFactor)
        }
        if (current?.enrollment?.token?.isNotBlank() == true) {
            add(InviteConflict.PendingEnrollment)
        }
    }

    invite.relay?.let { relay ->
        if (relayMode != "custom" || (relayUrl.isNotBlank() && relayUrl != relay)) {
            add(InviteConflict.Relay)
        }
    }
}
