package com.nexa.pipe.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the rule that decides whether a connect may take the single
 * VPN slot Android allows.
 *
 * The rule is pure — no ConnectivityManager, no Context — which is why it can
 * be tested on the JVM without instrumentation.
 */
class VpnTakeoverPolicyTest {

    @Test
    fun `proceeds when no vpn is up`() {
        assertEquals(
            VpnTakeoverDecision.Proceed,
            VpnTakeoverPolicy.decide(VpnSlot.Free, VpnTakeoverChoice.Ask)
        )
    }

    @Test
    fun `proceeds when the vpn that is up is our own tunnel`() {
        assertEquals(
            VpnTakeoverDecision.Proceed,
            VpnTakeoverPolicy.decide(VpnSlot.OwnSession, VpnTakeoverChoice.Ask)
        )
    }

    @Test
    fun `asks when another vpn is up and nothing has been chosen`() {
        assertEquals(
            VpnTakeoverDecision.Ask,
            VpnTakeoverPolicy.decide(VpnSlot.ForeignVpn, VpnTakeoverChoice.Ask)
        )
    }

    @Test
    fun `takes the slot when the user chose to`() {
        assertEquals(
            VpnTakeoverDecision.Proceed,
            VpnTakeoverPolicy.decide(VpnSlot.ForeignVpn, VpnTakeoverChoice.TakeOver)
        )
    }

    @Test
    fun `leaves the other vpn alone when the user chose to cancel`() {
        assertEquals(
            VpnTakeoverDecision.Refuse,
            VpnTakeoverPolicy.decide(VpnSlot.ForeignVpn, VpnTakeoverChoice.Cancel)
        )
    }

    /**
     * The service has no UI, so it asks with `Cancel` — refusing is the only
     * reading of "ask" it can act on.
     */
    @Test
    fun `refuses when there is no answer to ask with`() {
        assertEquals(
            VpnTakeoverDecision.Refuse,
            VpnTakeoverPolicy.decide(VpnSlot.ForeignVpn, VpnTakeoverChoice.Cancel)
        )
    }

    @Test
    fun `refuses an always-on vpn whatever the choice was`() {
        for (choice in VpnTakeoverChoice.entries) {
            assertEquals(
                VpnTakeoverDecision.RefuseAlwaysOn("com.other.vpn"),
                VpnTakeoverPolicy.decide(VpnSlot.AlwaysOnVpn("com.other.vpn"), choice)
            )
        }
    }

    @Test
    fun `treats an unset always-on vpn as no conflict`() {
        assertFalse(VpnTakeoverPolicy.isForeignAlwaysOn(null, "com.nexa.pipe"))
        assertFalse(VpnTakeoverPolicy.isForeignAlwaysOn("", "com.nexa.pipe"))
    }

    @Test
    fun `treats this app being the always-on vpn as no conflict`() {
        assertFalse(VpnTakeoverPolicy.isForeignAlwaysOn("com.nexa.pipe", "com.nexa.pipe"))
    }

    @Test
    fun `treats another app being the always-on vpn as a conflict`() {
        assertTrue(VpnTakeoverPolicy.isForeignAlwaysOn("com.other.vpn", "com.nexa.pipe"))
    }
}
