package com.nexa.pipe.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for reading a route's prefix out of the text the framework gives.
 *
 * The text is the only thing an Android before API 29 exposes, and it carries
 * the route's next hop with it — so reading it is a matter of taking what is
 * in front of the arrow.
 */
class VirtualBlockSurveyTest {

    /** A prefix, as the survey reads one. */
    private fun prefix(network: String, length: Int): VirtualBlockSelector.Prefix =
        VirtualBlockSelector.Prefix(Ipv4.parse(network)!!, length)

    @Test
    fun `a route's text still names its prefix`() {
        // The text of a route is the prefix with the next hop and the
        // interface appended, and the prefix is what is in front of the arrow.
        assertEquals(
            prefix("192.168.1.0", 24),
            VirtualBlockSurvey.parsePrefix("192.168.1.0/24 -> 192.168.1.1 wlan0")
        )
    }

    @Test
    fun `a prefix on its own is read as it is`() {
        assertEquals(
            prefix("198.18.0.0", 15),
            VirtualBlockSurvey.parsePrefix("198.18.0.0/15")
        )
    }

    @Test
    fun `the default route claims no block in particular`() {
        // 0.0.0.0/0 is the default route: a prefix of length zero, which is
        // no claim on any block.
        assertEquals(
            prefix("0.0.0.0", 0),
            VirtualBlockSurvey.parsePrefix("0.0.0.0/0 -> 192.168.1.1 wlan0")
        )
    }

    @Test
    fun `text that is not a prefix is not read as one`() {
        assertNull(VirtualBlockSurvey.parsePrefix("default"))
        assertNull(VirtualBlockSurvey.parsePrefix(""))
        assertNull(VirtualBlockSurvey.parsePrefix("192.168.1.0/24 unreachable"))
    }

    @Test
    fun `a prefix length that is not a length is not read as one`() {
        assertNull(VirtualBlockSurvey.parsePrefix("192.168.1.0/33"))
        assertNull(VirtualBlockSurvey.parsePrefix("192.168.1.0/x"))
    }
}
