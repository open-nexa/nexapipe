package com.nexa.pipe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The name a device answers with is read by a server that enforces the shape
 * again — printable ASCII with the space excluded — so these pin the rule where
 * it is produced rather than leaving a refusal to turn up at a handshake.
 */
class DeviceNameTest {

    /** The whole name has to fit the wire, tag included. */
    @Test
    fun a_generated_name_answers_to_printable_ascii_without_spaces() {
        val name = DeviceName.generate("Pixel 9 Pro")

        assertTrue("no spaces survive", !name.contains(' '))
        assertTrue("everything is printable ASCII", name.all { it.code in 0x21..0x7e })
        assertTrue("the name fits", name.length <= DeviceName.MAX)
    }

    /** Dropped rather than escaped: 手机 is not a hostname a server can key on. */
    @Test
    fun a_name_with_characters_outside_printable_ascii_loses_them() {
        val name = DeviceName.generate("手机")

        assertEquals(DeviceName.FALLBACK + "-" + name.takeLast(8), name)
    }

    /** A space unites the words instead of running them together. */
    @Test
    fun spaces_in_a_model_become_dashes() {
        val name = DeviceName.generate("Pixel 9 Pro")

        assertTrue("readable as three words", name.startsWith("Pixel-9-Pro-"))
    }

    /**
     * The tag is what keeps two identical phones apart, and it is what a
     * truncation would quietly eat: cutting the model to the maximum and
     * appending after it loses it entirely.
     */
    @Test
    fun a_long_model_leaves_room_for_the_tag() {
        val name = DeviceName.generate("x".repeat(DeviceName.MAX * 2))

        assertEquals("nothing is wasted", DeviceName.MAX, name.length)
        assertTrue("the tag survived", name.takeLast(8).all { it.isDigit() || it in 'a'..'f' })
    }

    /** An unnamed device is one that answers with the client's shared secret. */
    @Test
    fun a_device_that_reports_no_model_still_gets_a_name() {
        val name = DeviceName.generate("")

        assertTrue("it is named after something", name.startsWith(DeviceName.FALLBACK + "-"))
        assertTrue("and tagged", name.length > DeviceName.FALLBACK.length + 1)
    }

    /** Two installs on the same model must not answer as one device. */
    @Test
    fun two_generations_do_not_collide() {
        assertTrue(DeviceName.generate("Pixel 9 Pro") != DeviceName.generate("Pixel 9 Pro"))
    }
}
