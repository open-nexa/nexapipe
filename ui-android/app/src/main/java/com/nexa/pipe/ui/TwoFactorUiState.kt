package com.nexa.pipe.ui

/**
 * What an endpoint's 2FA card has to show.
 *
 * Three states, not two: an endpoint that is waiting to enroll has no
 * credentials yet, but it is not 2FA-off either — the token is armed, and the
 * next connect trades it for a credential. Reading that as "off" is what made
 * a scanned invite look like it had not been applied at all.
 */
internal enum class TwoFactorUiState {
    /** No credentials and nothing pending: this endpoint does not authenticate. */
    Off,

    /** A token is waiting to be spent: the credential comes with the next connect. */
    PendingEnrollment,

    /** A credential is on file and in use. */
    On,
}

/**
 * Which of the three an endpoint is in.
 *
 * The pending one is an enrollment that has not been answered yet: the server
 * issues the credential on the next connect, and until then there is nothing
 * to show but the wait. An answered enrollment leaves a credential behind and
 * clears the token, so it is [On] by then.
 */
internal fun twoFactorUiState(
    twoFactor: NodeTwoFactor?,
    enrollment: NodeEnrollment?
): TwoFactorUiState = when {
    enrollment != null -> TwoFactorUiState.PendingEnrollment
    twoFactor?.enabled == true -> TwoFactorUiState.On
    else -> TwoFactorUiState.Off
}
