package com.nexa.pipe.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which endpoints a machine that has just been switched on will reach.
 *
 * The rule itself is small; what it decides is not. A boot connection cannot
 * enrol an endpoint — enrolling spends a token and answers with a credential
 * that has to be stored, and a boot has nobody to ask about a device that
 * cannot protect one — so an endpoint waiting for that is left out of the
 * connection and waits for the user.
 */
class BootConnectorTest {

    @Test
    fun an_endpoint_that_is_still_waiting_to_be_enrolled_is_left_out() {
        val enrolled = NodeConfig(nodeId = "enrolled", domains = listOf("a.example"))
        val waiting = NodeConfig(
            nodeId = "waiting",
            domains = listOf("b.example"),
            enrollment = NodeEnrollment(clientId = "client", token = "token")
        )

        val usable = BootConnector.endpointsUsableAtBoot(listOf(enrolled, waiting))

        assertEquals(listOf("enrolled"), usable.map { it.nodeId })
    }

    @Test
    fun an_endpoint_with_its_credentials_is_kept() {
        val node = NodeConfig(
            nodeId = "ready",
            domains = listOf("a.example"),
            twoFactor = NodeTwoFactor(enabled = true, clientId = "client", secret = "s")
        )

        assertEquals(listOf(node), BootConnector.endpointsUsableAtBoot(listOf(node)))
    }

    @Test
    fun nothing_configured_means_nothing_to_connect_to() {
        assertTrue(BootConnector.endpointsUsableAtBoot(emptyList()).isEmpty())
    }

    @Test
    fun an_endpoint_that_is_only_waiting_leaves_nothing_behind() {
        // The whole point of the rule: when every endpoint is waiting, the
        // boot connection has nothing to do, and the app says so rather than
        // spending a token nobody asked it to spend.
        val waiting = NodeConfig(
            nodeId = "waiting",
            enrollment = NodeEnrollment(clientId = "client", token = "token")
        )

        assertTrue(BootConnector.endpointsUsableAtBoot(listOf(waiting)).isEmpty())
    }

    @Test
    fun only_a_failed_attempt_leaves_the_native_side_to_be_taken_down() {
        // The native side is process-global: a teardown that runs for an
        // attempt that started nothing takes down whatever else is running in
        // the process — a session the user is using, for one. Only a failure
        // can have brought the native side up and not kept it.
        assertFalse(BootConnector.BootOutcome.Skipped.needsNativeRelease)
        assertFalse(BootConnector.BootOutcome.Established.needsNativeRelease)
        assertTrue(BootConnector.BootOutcome.Failed(Exception("no network")).needsNativeRelease)
    }
}
