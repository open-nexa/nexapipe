package com.nexa.pipe.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the rule that picks the block the tunnel claims.
 *
 * The rule is pure — no ConnectivityManager, no native library — which is why
 * it can be tested on the JVM without instrumentation.
 */
class VirtualBlockSelectorTest {

    /** The candidate list the native side walks, as the tests need it. */
    private val candidates = listOf(
        Ipv4.parse("198.18.0.0")!!,
        Ipv4.parse("198.19.0.0")!!,
        Ipv4.parse("100.100.0.0")!!,
        Ipv4.parse("172.26.0.0")!!,
        Ipv4.parse("10.200.0.0")!!,
        Ipv4.parse("10.0.0.0")!!,
    )

    /** A prefix something else on the device claims. */
    private fun prefix(network: String, length: Int): VirtualBlockSelector.Prefix =
        VirtualBlockSelector.Prefix(Ipv4.parse(network)!!, length)

    @Test
    fun `takes the first candidate when nothing is claimed`() {
        assertEquals(
            Ipv4.parse("198.18.0.0"),
            VirtualBlockSelector.choose(candidates, emptyList(), emptyList())
        )
    }

    @Test
    fun `skips a candidate another interface holds an address in`() {
        // A block that holds somebody's address is not ours to take, and the
        // address would be answered by the network rather than by the tunnel.
        val held = listOf(prefix("192.168.50.7", 32))
        assertEquals(
            Ipv4.parse("10.5.0.0"),
            VirtualBlockSelector.choose(
                listOf(Ipv4.parse("192.168.50.0")!!, Ipv4.parse("10.5.0.0")!!),
                held,
                emptyList()
            )
        )
    }

    @Test
    fun `skips a candidate a route already claims`() {
        val routed = listOf(prefix("100.100.0.0", 24))
        assertEquals(
            Ipv4.parse("10.5.0.0"),
            VirtualBlockSelector.choose(
                listOf(Ipv4.parse("100.100.0.0")!!, Ipv4.parse("10.5.0.0")!!),
                emptyList(),
                routed
            )
        )
    }

    @Test
    fun `a route wider than the block swallows it`() {
        // A /16 somebody else routes covers every /24 inside it, which is the
        // fake-IP case: a tool holds one address and routes a range forty
        // thousand times wider at it.
        val routed = listOf(prefix("10.5.0.0", 16))
        assertEquals(
            Ipv4.parse("10.9.0.0"),
            VirtualBlockSelector.choose(
                listOf(Ipv4.parse("10.5.0.0")!!, Ipv4.parse("10.9.0.0")!!),
                emptyList(),
                routed
            )
        )
    }

    @Test
    fun `the default route disqualifies nothing`() {
        val routed = listOf(prefix("0.0.0.0", 0))
        assertEquals(
            Ipv4.parse("198.18.0.0"),
            VirtualBlockSelector.choose(candidates, emptyList(), routed)
        )
    }

    @Test
    fun `the two halves of a vpn taking the default route disqualify nothing`() {
        // A VPN installs 0.0.0.0/1 and 128.0.0.0/1 to sit in front of every
        // destination without replacing the default route itself. Our /24 is
        // more specific than either, so the two coexist.
        val routed = listOf(prefix("0.0.0.0", 1), prefix("128.0.0.0", 1))
        assertEquals(
            Ipv4.parse("198.18.0.0"),
            VirtualBlockSelector.choose(candidates, emptyList(), routed)
        )
    }

    @Test
    fun `an address in the fake-ip range disqualifies both of its halves`() {
        // A fake-IP tool hands out addresses across 198.18.0.0/15 while its
        // own interface holds only a sliver of it, so one address in the range
        // disqualifies 198.18.0.0/24 and 198.19.0.0/24 alike.
        val held = listOf(prefix("198.19.5.7", 32))
        assertEquals(
            Ipv4.parse("100.100.0.0"),
            VirtualBlockSelector.choose(candidates, held, emptyList())
        )
    }

    @Test
    fun `nothing free means no block`() {
        val held = listOf(prefix("10.5.0.7", 32))
        assertNull(
            VirtualBlockSelector.choose(
                listOf(Ipv4.parse("10.5.0.0")!!),
                held,
                emptyList()
            )
        )
    }

    @Test
    fun `the reasons the log wants are reported`() {
        val evaluation = VirtualBlockSelector.evaluate(
            candidates,
            listOf(prefix("198.19.5.7", 32)),
            emptyList()
        )
        assertEquals(Ipv4.parse("100.100.0.0"), evaluation.base)
        assertEquals(2, evaluation.skipped.size)
        assertTrue(evaluation.skipped[0].contains("198.18.0.0/24"))
        assertTrue(evaluation.skipped[1].contains("198.19.0.0/24"))
    }
}
