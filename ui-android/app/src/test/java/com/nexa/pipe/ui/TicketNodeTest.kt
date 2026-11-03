package com.nexa.pipe.ui

import com.nexa.pipe.provisioning.EndpointInvite
import com.nexa.pipe.provisioning.InviteTarget
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A ticket is not a Node ID, but the app keys everything by Node ID. These
 * are the rules that keep a ticket invite from becoming an endpoint nobody
 * can dial, and an older saved endpoint list from being lost on upgrade.
 */
class TicketNodeTest {
    private val json = Json { ignoreUnknownKeys = true }
    private val nodeId = "1f2e3d4c5b6a798807162534435261708f9ea0b1c2d3e4f5061728394a5b6c7d"

    private fun invite(target: InviteTarget) = EndpointInvite(
        target = target,
        name = null,
        domains = listOf("a.example"),
        relay = null,
        totp = null,
    )

    @Test
    fun `a node id invite is keyed by its id`() {
        assertEquals(nodeId, inviteNodeId(invite(InviteTarget.NodeId(nodeId))))
    }

    @Test
    fun `a ticket invite is keyed by the id resolved from the ticket`() {
        val ticketInvite = invite(InviteTarget.Ticket("endpoint:abc"))

        // Without the resolved id it cannot be stored, and a conflict check
        // would see a brand new endpoint instead of the one already there.
        assertNull(inviteNodeId(ticketInvite))
        assertEquals(nodeId, inviteNodeId(ticketInvite, nodeId))

        // That id is what finds the existing endpoint in the setup.
        val setup = InviteSetup(
            nodes = listOf(NodeConfig(nodeId = nodeId)),
            relayMode = "pinned",
            relayUrl = "",
            relayAuthToken = "",
            resolvedNodeId = nodeId,
        )
        val current = inviteNodeId(ticketInvite, setup.resolvedNodeId)
            ?.let { id -> setup.nodes.firstOrNull { it.nodeId == id } }
        assertEquals(nodeId, current?.nodeId)
    }

    @Test
    fun `an endpoint list written before tickets existed still decodes`() {
        // The new field has a default and sits last: a payload missing it must
        // not turn into an empty list (and take the old 2FA with it).
        val oldJson = """[{"nodeId":"$nodeId","domains":["a.example"]}]"""
        val nodes = json.decodeFromString<List<NodeConfig>>(oldJson)

        assertEquals(1, nodes.size)
        assertEquals(nodeId, nodes[0].nodeId)
        assertEquals(listOf("a.example"), nodes[0].domains)
        assertNull(nodes[0].ticket)
    }

    @Test
    fun `a ticket round trips through the node model`() {
        val node = NodeConfig(nodeId = nodeId, ticket = "endpoint:abc")
        val decoded = json.decodeFromString<List<NodeConfig>>(json.encodeToString(listOf(node)))

        assertEquals("endpoint:abc", decoded[0].ticket)
    }

    @Test
    fun `a ticket counts as a credential in a settings write`() {
        val write = SettingsWrite(
            nodes = listOf(NodeConfig(nodeId = nodeId, ticket = "endpoint:abc")),
            relayMode = "pinned",
            relayUrl = "",
            relayToken = "",
            discoveryMode = "none",
        )

        assertTrue(write.carriesCredential())
    }
}
