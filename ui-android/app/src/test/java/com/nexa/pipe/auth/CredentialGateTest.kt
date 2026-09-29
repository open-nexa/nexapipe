package com.nexa.pipe.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The credential door, off-device.
 *
 * What can be pinned here is the window and nothing else: whether a device can
 * authenticate is a `KeyguardManager` answer, and what `BiometricPrompt` does
 * with the result is a system answer. Both need a device. The window does not,
 * and it is the part worth being precise about — it is the difference between
 * "authenticated two minutes ago" and "authenticated".
 *
 * The rest of the class is deliberately not exercised: a `Build.VERSION` that
 * returns 0 and a `getSystemService` that returns null would only prove what
 * the android.jar stubs do.
 */
class CredentialGateTest {

    @Before
    fun lockTheGate() {
        CredentialGate.lock()
    }

    @Test
    fun a_gate_nobody_has_opened_is_shut() {
        assertFalse("a fresh gate must not be open", CredentialGate.isUnlocked(1_000L))
    }

    /** The window is a duration, so the instant it ends has to be outside it. */
    @Test
    fun the_window_is_closed_at_the_moment_it_ends() {
        val openedAt = 10_000L
        val endsAt = openedAt + CredentialGate.UNLOCK_WINDOW_MS

        assertFalse("the last instant of the window is not in it", CredentialGate.isUnlockedAt(endsAt, endsAt))
        assertTrue("one instant earlier still is", CredentialGate.isUnlockedAt(endsAt - 1L, endsAt))
    }

    @Test
    fun unlocking_opens_the_window_and_locking_closes_it() {
        CredentialGate.unlock(nowMs = 5_000L)

        assertTrue(CredentialGate.isUnlocked(nowMs = 5_000L + CredentialGate.UNLOCK_WINDOW_MS - 1L))
        assertFalse(CredentialGate.isUnlocked(nowMs = 5_000L + CredentialGate.UNLOCK_WINDOW_MS))

        CredentialGate.lock()
        assertFalse("locking must not wait for the window to lapse", CredentialGate.isUnlocked(nowMs = 5_001L))
    }

    /**
     * A second authentication extends the window rather than restarting a
     * shorter one: authenticating near the end of a window must not leave less
     * time than authenticating at the start of one.
     */
    @Test
    fun unlocking_again_starts_a_full_window_from_there() {
        CredentialGate.unlock(nowMs = 1_000L)
        val firstEndsAt = 1_000L + CredentialGate.UNLOCK_WINDOW_MS

        CredentialGate.unlock(nowMs = firstEndsAt - 1L)

        assertTrue(
            "the second window runs its full length from the moment it was opened",
            CredentialGate.isUnlocked(firstEndsAt - 1L + CredentialGate.UNLOCK_WINDOW_MS - 1L)
        )
    }

    /** The policy itself, so a change to it has to be made on purpose. */
    @Test
    fun the_window_last_two_minutes() {
        assertEquals(120_000L, CredentialGate.UNLOCK_WINDOW_MS)
    }
}
