package com.nexa.pipe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What happens to a relay token an older version left in the backed-up
 * preferences.
 *
 * The token is a credential — it is handed to the relay verbatim — and the
 * file it is moving out of is the one that rides the backup. The file it is
 * moving into is the one whose whole point is that it holds ciphertext, so a
 * token that cannot be sealed has nowhere to go.
 */
class RelayTokenMoveTest {

    /**
     * A token this device can seal moves, and what is written is the sealed
     * value rather than the token itself.
     */
    @Test
    fun a_sealable_token_moves_sealed() {
        val move = relayTokenMove("the-relay-token") { "sealed:$it" }

        assertTrue("the token moves: $move", move is RelayTokenMove.Move)
        assertEquals("sealed:the-relay-token", (move as RelayTokenMove.Move).sealed)
    }

    /**
     * A device with no keystore cannot seal anything, and the token stays
     * where it is.
     *
     * It is not written in the clear into the secrets file: that file is
     * excluded from the backup precisely because it holds ciphertext, and a
     * plain value in it is a credential in a file that says it holds none.
     */
    @Test
    fun a_token_that_cannot_be_sealed_stays_where_it_is() {
        val move = relayTokenMove("the-relay-token") { null }

        assertEquals(RelayTokenMove.Keep, move)
    }

    /**
     * A blank value is the one saved whenever a relay needs no token. It is
     * not a credential, so nothing is written anywhere — but the key is still
     * removed, so the file does not carry one that looks like a credential.
     */
    @Test
    fun a_blank_token_is_not_a_credential() {
        assertEquals(RelayTokenMove.None, relayTokenMove("") { "sealed:$it" })
        assertEquals(RelayTokenMove.None, relayTokenMove("   ") { "sealed:$it" })
    }

    /**
     * A blank value is answered before the keystore is asked at all, so a
     * relay that needs no token cannot make the device look unprotected.
     */
    @Test
    fun a_blank_token_never_asks_the_keystore() {
        var asked = false
        relayTokenMove("") { asked = true; "sealed" }

        assertTrue("the keystore was asked for nothing", !asked)
    }
}
