package com.nexa.pipe.ui

import com.nexa.pipe.provisioning.EndpointInvite
import com.nexa.pipe.provisioning.InviteEnrollment
import com.nexa.pipe.provisioning.InviteTarget
import com.nexa.pipe.provisioning.InviteTotp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The rule that decides whether an invite needs a question before it is
 * applied.
 *
 * It is a pure function so it can be checked here rather than by scanning a
 * code on a phone, and because the case it used to miss — a one-time
 * enrollment over an endpoint that already holds a credential — is exactly
 * the kind of thing that has to be pinned by a test: a registration code
 * carries no secret, so it raised no conflict, and applying it dropped the
 * credential the endpoint already had.
 */
class InviteConflictsTest {

    private val nodeId = "1f2e3d4c5b6a798807162534435261708f9ea0b1c2d3e4f5061728394a5b6c7d"

    private fun node(
        secret: String? = null,
        publicKey: String? = null,
        enrollmentToken: String? = null
    ): NodeConfig = NodeConfig(
        nodeId = nodeId,
        domains = listOf("a.example"),
        twoFactor = if (secret != null || publicKey != null) {
            NodeTwoFactor(
                enabled = true,
                clientId = "client-001",
                secret = secret.orEmpty(),
                algorithm = "sha1",
                publicKey = publicKey
            )
        } else {
            null
        },
        enrollment = enrollmentToken?.let { NodeEnrollment(clientId = "client-001", token = it) }
    )

    private fun totpInvite(secret: String = "JBSWY3DPEHPK3PXP"): EndpointInvite = EndpointInvite(
        target = InviteTarget.NodeId(nodeId),
        name = "Home",
        domains = listOf("a.example"),
        relay = null,
        totp = InviteTotp(
            issuer = "NexaPipe",
            clientId = "client-001",
            secret = secret,
            algorithm = "sha1",
            digits = 6,
            period = 30
        )
    )

    private fun enrollmentInvite(): EndpointInvite = EndpointInvite(
        target = InviteTarget.NodeId(nodeId),
        name = "Home",
        domains = listOf("a.example"),
        relay = null,
        totp = null,
        enrollment = InviteEnrollment(clientId = "client-001", token = "0123456789abcdef")
    )

    private fun conflicts(
        current: NodeConfig?,
        invite: EndpointInvite,
        relayMode: String = "pinned",
        relayUrl: String = ""
    ): List<InviteConflict> =
        inviteConflictKinds(current, invite, relayMode, relayUrl)

    /**
     * The case the rule used to miss.
     *
     * An enrollment is a credential as much as a secret is: the token is spent
     * on the first connect and what comes back replaces what the endpoint
     * authenticates with now. It raised no conflict, so it was applied
     * without a question and the working credential went with it.
     */
    @Test
    fun an_enrollment_over_a_secret_is_a_conflict() {
        assertEquals(
            listOf(InviteConflict.EnrollmentReplacesTwoFactor),
            conflicts(node(secret = "JBSWY3DPEHPK3PXP"), enrollmentInvite())
        )
    }

    /**
     * A key is a credential too: the private half is sealed beside the public
     * one, and the enrollment replaces the pair.
     */
    @Test
    fun an_enrollment_over_a_key_is_a_conflict() {
        assertEquals(
            listOf(InviteConflict.EnrollmentReplacesTwoFactor),
            conflicts(node(publicKey = "ab".repeat(32)), enrollmentInvite())
        )
    }

    /**
     * An endpoint with nothing to replace is the ordinary case: a
     * registration code for a device that has not enrolled yet goes straight
     * in.
     */
    @Test
    fun an_enrollment_over_nothing_is_no_conflict() {
        assertEquals(emptyList<InviteConflict>(), conflicts(node(), enrollmentInvite()))
        assertEquals(
            emptyList<InviteConflict>(),
            conflicts(null, enrollmentInvite())
        )
    }

    /**
     * A token that has not been spent yet is a credential of its own: the
     * import would replace it with another one.
     */
    @Test
    fun an_enrollment_over_an_unspent_token_is_a_conflict() {
        assertEquals(
            listOf(InviteConflict.PendingEnrollment),
            conflicts(node(enrollmentToken = "unspent-invite-token"), enrollmentInvite())
        )
    }

    /**
     * Both at once: an endpoint that holds a credential *and* an unspent
     * token loses both.
     */
    @Test
    fun an_enrollment_over_both_names_both() {
        assertEquals(
            listOf(
                InviteConflict.EnrollmentReplacesTwoFactor,
                InviteConflict.PendingEnrollment
            ),
            conflicts(
                node(secret = "JBSWY3DPEHPK3PXP", enrollmentToken = "unspent-invite-token"),
                enrollmentInvite()
            )
        )
    }

    /**
     * The v=1 rule, unchanged: a secret that differs is a replacement, and a
     * secret that is the same is not.
     */
    @Test
    fun a_different_secret_is_a_conflict_and_the_same_one_is_not() {
        assertEquals(
            listOf(InviteConflict.TwoFactor),
            conflicts(node(secret = "JBSWY3DPEHPK3PXP"), totpInvite(secret = "OTHERSECRETAAA"))
        )
        assertEquals(
            emptyList<InviteConflict>(),
            conflicts(node(secret = "JBSWY3DPEHPK3PXP"), totpInvite())
        )
    }

    /**
     * The relay is global, so it is not the endpoint's — but an invite that
     * changes it is still a replacement of something that works.
     */
    @Test
    fun a_relay_that_changes_is_a_conflict() {
        val invite = EndpointInvite(
            target = InviteTarget.NodeId(nodeId),
            name = "Home",
            domains = listOf("a.example"),
            relay = "https://relay.example",
            totp = null
        )
        assertEquals(
            listOf(InviteConflict.Relay),
            conflicts(node(), invite, relayMode = "pinned")
        )
        assertEquals(
            listOf(InviteConflict.Relay),
            conflicts(node(), invite, relayMode = "custom", relayUrl = "https://other.example")
        )
        assertEquals(
            emptyList<InviteConflict>(),
            conflicts(node(), invite, relayMode = "custom", relayUrl = "https://relay.example")
        )
    }

    /**
     * A credential is a secret or a key, and nothing else. A record that
     * carries neither is a shape — which is what an endpoint looks like after
     * its token was spent and before the answer arrived.
     */
    @Test
    fun a_record_with_neither_a_secret_nor_a_key_is_not_a_credential() {
        assertTrue(!NodeTwoFactor(enabled = true).hasCredential())
        assertTrue(NodeTwoFactor(enabled = true, secret = "JBSWY3DPEHPK3PXP").hasCredential())
        assertTrue(NodeTwoFactor(enabled = true, publicKey = "ab".repeat(32)).hasCredential())
    }
}
