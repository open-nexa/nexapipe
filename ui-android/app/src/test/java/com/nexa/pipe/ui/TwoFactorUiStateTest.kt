package com.nexa.pipe.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * What the 2FA card shows for an endpoint.
 *
 * The state is a pure function so it can be checked here rather than by
 * scanning a code on a phone: the case it used to miss — an endpoint that is
 * waiting to enroll — read as "off" while the token was armed and the
 * credential was one connect away, so a scanned invite looked like it had not
 * been applied at all.
 */
class TwoFactorUiStateTest {

    @Test
    fun an_endpoint_without_credentials_is_off() {
        assertEquals(
            TwoFactorUiState.Off,
            twoFactorUiState(null, null)
        )
    }

    @Test
    fun a_switched_off_credential_is_off() {
        assertEquals(
            TwoFactorUiState.Off,
            twoFactorUiState(NodeTwoFactor(enabled = false), null)
        )
    }

    @Test
    fun a_credential_in_use_is_on() {
        assertEquals(
            TwoFactorUiState.On,
            twoFactorUiState(NodeTwoFactor(enabled = true), null)
        )
    }

    @Test
    fun a_pending_enrollment_is_pending_and_not_off() {
        // The token is armed and the credential comes with the next connect,
        // so this is neither on nor off.
        assertEquals(
            TwoFactorUiState.PendingEnrollment,
            twoFactorUiState(null, NodeEnrollment(clientId = "client-001", token = "token"))
        )
    }

    @Test
    fun a_pending_enrollment_is_pending_over_a_credential() {
        // An enrollment is imported over the credential the endpoint had, so
        // this is what the card sees between the import and the answer.
        assertEquals(
            TwoFactorUiState.PendingEnrollment,
            twoFactorUiState(
                NodeTwoFactor(enabled = true),
                NodeEnrollment(clientId = "client-001", token = "token")
            )
        )
    }
}
