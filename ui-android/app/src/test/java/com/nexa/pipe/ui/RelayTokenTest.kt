package com.nexa.pipe.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Which relay a bearer token may travel to.
 *
 * The rule is a pure function so it can be checked here rather than by
 * watching a phone: a token is issued by one relay and is good for that
 * relay alone, so a token that follows a change of relay is a credential
 * handed to whoever named the new relay. An invite names a relay, and the
 * invite is written by whoever sent it.
 *
 * The case this rule exists for is the one a default used to get wrong: the
 * parameter that decided what happened to the token defaulted to the token
 * that was already stored, so every change of relay carried it along — and
 * an import could therefore take a bearer token to a host of its choosing.
 */
class RelayTokenTest {

    private val relay = "https://relay.example"
    private val otherRelay = "https://other.example"
    private val token = "the-relay-token"

    private fun stored(
        token: String = this.token,
        relayUrl: String = relay
    ): RelayToken = RelayToken(token = token, relayUrl = relayUrl)

    /**
     * The change of relay the rule is about: a token issued by one relay is
     * presented to another, and the other relay learns it.
     */
    @Test
    fun a_change_of_relay_clears_the_token() {
        val after = relayTokenAfter(otherRelay, stored(), RelayTokenChange.Bound)

        assertEquals("the token went with the relay", "", after.token)
        assertEquals("and nothing is bound to the new relay", "", after.relayUrl)
    }

    /**
     * The other half of the rule: a token that is still with the relay it
     * was issued for stays. A mode that does not name a relay at all is not
     * a change of relay, so looking at another mode keeps the token.
     */
    @Test
    fun the_same_relay_keeps_the_token() {
        val after = relayTokenAfter(relay, stored(), RelayTokenChange.Bound)

        assertEquals("the token stayed", token, after.token)
        assertEquals("with the relay it was issued for", relay, after.relayUrl)
    }

    /**
     * An invite names a relay and carries no token for it, so the token this
     * phone holds goes with the import rather than travelling to the relay
     * the invite names.
     *
     * Dropped even when the invite names the relay the token was issued for:
     * an import brings no token of its own, and a token that quietly
     * travels is the thing this rule exists to stop.
     */
    @Test
    fun an_invite_that_names_a_relay_does_not_carry_the_token_over() {
        val after = relayTokenAfter(otherRelay, stored(), RelayTokenChange.Drop)

        assertEquals("the token did not travel", "", after.token)

        val sameRelay = relayTokenAfter(relay, stored(), RelayTokenChange.Drop)

        assertEquals("nor to the relay it was issued for", "", sameRelay.token)
    }

    /**
     * A token the user types belongs to the relay they typed it for: it is
     * stored, and it is bound to that relay.
     */
    @Test
    fun a_token_the_user_types_is_kept_for_that_relay() {
        val after = relayTokenAfter(otherRelay, stored(token = ""), RelayTokenChange.Set(token))

        assertEquals("the token was stored", token, after.token)
        assertEquals("for the relay it was typed for", otherRelay, after.relayUrl)
    }

    /**
     * Saving the same relay again keeps the token: a re-save is not a
     * change of relay, and a token that vanishes on every save is a token
     * the user cannot keep.
     */
    @Test
    fun a_token_survives_a_re_save_of_the_same_relay() {
        val typed = relayTokenAfter(relay, stored(token = ""), RelayTokenChange.Set(token))
        val saved = relayTokenAfter(relay, typed, RelayTokenChange.Bound)

        assertEquals("the token stayed", token, saved.token)
        assertEquals("with its relay", relay, saved.relayUrl)
    }

    /**
     * The last place the token can be held back: what is handed to the
     * native side is the token of the relay being configured, and nothing
     * else.
     */
    @Test
    fun a_token_that_belongs_to_another_relay_is_not_sent() {
        assertEquals("nothing was sent", "", relayTokenToSend(stored(), otherRelay))
    }

    /**
     * And the token that does belong to the relay is sent — otherwise the
     * rule would cost a working relay its token.
     */
    @Test
    fun a_token_is_sent_to_the_relay_it_was_issued_for() {
        assertEquals("the token was sent", token, relayTokenToSend(stored(), relay))
    }

    /**
     * Two spellings of one URL are one relay: that is how the native side
     * reads a URL, so a token that goes to one of them goes to the relay
     * both of them name.
     */
    @Test
    fun a_url_that_differs_only_in_whitespace_is_the_same_relay() {
        val after = relayTokenAfter("  $relay  ", stored(), RelayTokenChange.Bound)

        assertEquals("the token stayed", token, after.token)
    }

    /**
     * A token with no relay behind it belongs to nobody, so it is not sent
     * to whoever happens to be configured.
     */
    @Test
    fun a_token_with_no_relay_is_not_sent() {
        assertEquals("", relayTokenToSend(stored(relayUrl = ""), relay))
    }
}
