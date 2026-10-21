package com.nexa.pipe.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for the answers the native side sends and the addresses they are
 * read into.
 */
class VirtualBlockTest {

    /**
     * The answer the native side sends, spelled the way the Rust side spells
     * it: the same keys, in the same order.
     */
    private val encoded =
        "base=198.18.0.0;network=198.18.0.0/24;interface=198.18.0.1;dns=198.18.0.2;" +
            "proxy=198.18.0.3;ipv6=fd00:198:18::;ipv6Interface=fd00:198:18::1"

    @Test
    fun `reads every address the native side names`() {
        val block = VirtualBlock.parse(encoded)!!
        assertEquals("198.18.0.0", block.base)
        assertEquals("198.18.0.0/24", block.network)
        assertEquals("198.18.0.1", block.interfaceIp)
        assertEquals("198.18.0.2", block.dnsIp)
        assertEquals("198.18.0.3", block.legacyProxyIp)
        assertEquals("fd00:198:18::", block.ipv6Network)
        assertEquals("fd00:198:18::1", block.ipv6InterfaceIp)
    }

    @Test
    fun `a missing key is no block at all`() {
        assertNull(VirtualBlock.parse(encoded.replace(";dns=198.18.0.2", "")))
    }

    @Test
    fun `an empty value is no block at all`() {
        assertNull(VirtualBlock.parse(encoded.replace("dns=198.18.0.2", "dns=")))
    }

    @Test
    fun `reads an address as the number it is written as`() {
        assertEquals(0xC6120000L, Ipv4.parse("198.18.0.0"))
        assertEquals(0x0A000001L, Ipv4.parse("10.0.0.1"))
    }

    @Test
    fun `refuses an address that is not one`() {
        assertNull(Ipv4.parse("1.2.3"))
        assertNull(Ipv4.parse("1.2.3.4.5"))
        assertNull(Ipv4.parse("256.1.1.1"))
        assertNull(Ipv4.parse("a.b.c.d"))
        assertNull(Ipv4.parse(""))
    }

    @Test
    fun `writes an address back the way it was written`() {
        assertEquals("198.18.0.0", Ipv4.format(Ipv4.parse("198.18.0.0")!!))
        assertEquals("10.0.0.1", Ipv4.format(Ipv4.parse("10.0.0.1")!!))
    }

    @Test
    fun `masks the leading bits of a prefix`() {
        assertEquals(0L, Ipv4.mask(0))
        assertEquals(0xFFFF_FFFFL, Ipv4.mask(32))
        assertEquals(0xFFFF_FF00L, Ipv4.mask(24))
    }
}
