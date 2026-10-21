package com.nexa.pipe.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for the answer the native side sends about each backend's path.
 *
 * The encoding crosses a language boundary — the Rust side writes it, this
 * side reads it — so the two halves have to agree on every part of it. These
 * pin the reading of that format: what a kind means, what a latency means,
 * and which of them may be absent.
 */
class LinkReadingsTest {

    @Test
    fun `reads the kind of each backend`() {
        val readings = parseLinkReadings("abc=direct;def=relay;ghi=unknown")

        assertEquals(LinkKind.DIRECT, readings.kinds["abc"])
        assertEquals(LinkKind.RELAY, readings.kinds["def"])
        assertEquals(LinkKind.UNKNOWN, readings.kinds["ghi"])
    }

    @Test
    fun `reads the round trip time of each backend`() {
        val readings = parseLinkReadings("abc=direct/23;def=relay/140")

        assertEquals(23L, readings.rtts["abc"])
        assertEquals(140L, readings.rtts["def"])
    }

    @Test
    fun `an unmeasured path has no latency rather than a zero`() {
        val readings = parseLinkReadings("abc=direct/-")

        assertEquals(LinkKind.DIRECT, readings.kinds["abc"])
        assertNull(readings.rtts["abc"])
    }

    @Test
    fun `a kind without a latency still reads`() {
        // The shape the native side used before it carried a latency, and a
        // value that arrives in that shape must not be read as broken.
        val readings = parseLinkReadings("abc=direct")

        assertEquals(LinkKind.DIRECT, readings.kinds["abc"])
        assertNull(readings.rtts["abc"])
    }

    @Test
    fun `an unknown kind is unknown rather than a failure`() {
        val readings = parseLinkReadings("abc=hole-punched/12")

        assertEquals(LinkKind.UNKNOWN, readings.kinds["abc"])
        assertEquals(12L, readings.rtts["abc"])
    }

    @Test
    fun `a broken entry is skipped rather than taking the list with it`() {
        val readings = parseLinkReadings(";=direct/12;abc=relay/30")

        assertEquals(1, readings.kinds.size)
        assertEquals(LinkKind.RELAY, readings.kinds["abc"])
    }

    @Test
    fun `a backend is found whatever case its id came back in`() {
        val readings = parseLinkReadings("ABC=direct/23")

        assertEquals(LinkKind.DIRECT, linkKindOf(readings.kinds, "abc"))
        assertEquals(23L, linkRttOf(readings.rtts, "abc"))
    }

    @Test
    fun `a backend nobody reported has neither a kind nor a latency`() {
        val readings = parseLinkReadings("abc=direct/23")

        assertNull(linkKindOf(readings.kinds, "other"))
        assertNull(linkRttOf(readings.rtts, "other"))
    }
}
