package com.nexa.pipe

import com.nexa.pipe.ui.NodeConfig
import com.nexa.pipe.ui.NodeEnrollment
import com.nexa.pipe.ui.NodeTwoFactor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Where the app-wide 2FA setting an older version kept goes.
 *
 * It authenticated every connection, so the faithful move is the same pair on
 * every endpoint — but only on the endpoints that can take it. An endpoint
 * that has a credential of its own keeps it, and one that is waiting to enroll
 * is left alone: its enrollment is about to issue a credential of its own, and
 * a pair on a different client id would stop that from being armed at all.
 *
 * The setting itself is a credential, so the secrets file has to hold it
 * sealed: it was being carried in the clear, in the one file whose whole point
 * is that it holds ciphertext.
 */
class LegacyTwoFactorMigrationTest {

    /** The pair an older version kept, one for the whole app. */
    private fun legacy() = LegacyTwoFactor(
        enabled = true,
        clientId = "client-xm-15-pro",
        secret = "JBSWY3DPEHPK3PXP",
        algorithm = "sha1"
    )

    /**
     * An endpoint with nothing of its own takes the pair: that is the case the
     * migration exists for.
     */
    @Test
    fun an_endpoint_with_no_credential_takes_the_app_wide_pair() {
        val move = legacyTwoFactorTargets(listOf(NodeConfig("node-a")), legacy())

        assertEquals(1, move.attached)
        val otp = move.nodes.first().twoFactor
        assertEquals("client-xm-15-pro", otp?.clientId)
        assertEquals("JBSWY3DPEHPK3PXP", otp?.secret)
        assertEquals("sha1", otp?.algorithm)
    }

    /**
     * An endpoint that already has a credential keeps it. The app-wide pair is
     * older than the per-endpoint ones, so putting it on top of them would
     * replace a credential that works with one that is on its way out.
     */
    @Test
    fun an_endpoint_that_already_has_a_credential_keeps_it() {
        val node = NodeConfig(
            nodeId = "node-a",
            twoFactor = NodeTwoFactor(
                enabled = true,
                clientId = "xm17",
                secret = "NEWSECRETNEWSECRET",
                algorithm = "sha1"
            )
        )

        val move = legacyTwoFactorTargets(listOf(node), legacy())

        assertEquals(0, move.attached)
        assertEquals("xm17", move.nodes.first().twoFactor?.clientId)
        assertEquals("NEWSECRETNEWSECRET", move.nodes.first().twoFactor?.secret)
    }

    /**
     * A key is a credential too: the private half is sealed beside it, so an
     * endpoint that signs is not one that needs the app-wide pair.
     */
    @Test
    fun a_key_credential_is_a_credential_too() {
        val node = NodeConfig(
            nodeId = "node-a",
            twoFactor = NodeTwoFactor(
                enabled = true,
                clientId = "xm17",
                secret = "",
                algorithm = "sha1",
                publicKey = "ab".repeat(32)
            )
        )

        val move = legacyTwoFactorTargets(listOf(node), legacy())

        assertEquals(0, move.attached)
        assertEquals("xm17", move.nodes.first().twoFactor?.clientId)
    }

    /**
     * An endpoint that is waiting to enroll is left alone.
     *
     * Its enrollment is about to issue a credential of its own, on the client
     * id the invite named. The app-wide pair is on a client id that has
     * nothing to do with it, and an endpoint that holds one does not enroll at
     * all — so the pair would take the place of a credential the server is
     * about to issue, and answer with one the server never issued.
     */
    @Test
    fun an_endpoint_waiting_to_enroll_is_left_alone() {
        val node = NodeConfig(
            nodeId = "node-a",
            enrollment = NodeEnrollment(clientId = "xm17", token = "the-token")
        )

        val move = legacyTwoFactorTargets(listOf(node), legacy())

        assertEquals(0, move.attached)
        assertNull(move.nodes.first().twoFactor)
        assertEquals("xm17", move.nodes.first().enrollment?.clientId)
    }

    /**
     * The endpoints are told apart: one takes the pair and one does not, and
     * the count says how many did.
     */
    @Test
    fun the_count_is_how_many_endpoints_took_the_pair() {
        val free = NodeConfig(nodeId = "node-a")
        val taken = NodeConfig(
            nodeId = "node-b",
            twoFactor = NodeTwoFactor(enabled = true, clientId = "xm17", secret = "SECRET")
        )
        val enrolling = NodeConfig(
            nodeId = "node-c",
            enrollment = NodeEnrollment(clientId = "xm17", token = "the-token")
        )

        val move = legacyTwoFactorTargets(listOf(free, taken, enrolling), legacy())

        assertEquals(1, move.attached)
        assertEquals("client-xm-15-pro", move.nodes[0].twoFactor?.clientId)
        assertEquals("xm17", move.nodes[1].twoFactor?.clientId)
        assertNull(move.nodes[2].twoFactor)
    }

    /**
     * The app-wide setting is a credential, so the secrets file holds it
     * sealed. It was carried in the clear: the seed is a TOTP secret and the
     * client id is half of the pair that authenticates with it.
     */
    @Test
    fun the_app_wide_setting_is_a_credential_the_secrets_file_holds_sealed() {
        assertTrue(isCredentialKey(SettingsManager.KEY_2FA_SECRET))
        assertTrue(isCredentialKey(SettingsManager.KEY_2FA_CLIENT_ID))
    }

    /**
     * The per-endpoint credentials are sealed, and the flag that says the
     * migration ran is not a credential and stays readable.
     */
    @Test
    fun the_other_keys_are_where_they_were() {
        assertTrue(isCredentialKey(SettingsManager.KEY_RELAY_AUTH_TOKEN))
        assertTrue(isCredentialKey(SettingsManager.SECRET_PREFIX + "node-a"))
        assertTrue(isCredentialKey(SettingsManager.ENROLLMENT_PREFIX + "node-a"))
        assertFalse(isCredentialKey(SettingsManager.KEY_2FA_MIGRATED))
        assertFalse(isCredentialKey(SettingsManager.KEY_2FA_ALGORITHM))
    }
}
