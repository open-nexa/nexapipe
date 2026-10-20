package com.nexa.pipe.ui

import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.nexa.pipe.SettingsManager
import com.nexa.pipe.vpn.NexaVpnService

/**
 * Brings the tunnel back after the machine has been restarted.
 *
 * A proxy that has to be switched on by hand every time the phone is switched
 * on is not an always-on proxy, and on a phone that is the difference between
 * a machine that is protected and a machine that is not. So the app asks to
 * be let back in after a restart, and this is what lets it back in.
 *
 * # What it does not do
 *
 * It does not take the VPN slot from another app. The boot path never answers
 * the takeover question, because there is nobody to answer it: a tunnel that
 * quietly revoked somebody else's VPN at seven in the morning would be a
 * surprise nobody could prepare for. Another app that owns the slot means the
 * tunnel does not come back, and the settings page says so.
 *
 * It does not enrol an endpoint either. Enrolling spends a token and answers
 * with a credential that has to be stored, and a boot has nobody to ask about
 * a device that cannot protect one. An endpoint still waiting to be enrolled
 * is left out of the boot connection and waits for the user.
 */
object BootConnector {

    /**
     * Whether the tunnel is asked to come back after a restart.
     *
     * Read by the broadcast receiver before it starts anything, so a user who
     * has not asked for this is not woken by a service on every restart.
     */
    fun isWanted(context: Context): Boolean =
        SettingsManager(context).autoConnectOnBoot()

    /**
     * The endpoints a boot connection may use.
     *
     * An endpoint still waiting to be enrolled is left out: enrolling spends a
     * token and answers with a credential that has to be stored, and a boot has
     * nobody to ask about a device that cannot protect one. Every other
     * endpoint is usable — it already has the credential it connects with.
     *
     * A function of its own because this is the rule worth pinning down: it
     * decides which endpoints a machine that has just been switched on will
     * reach, and it does not need a device to be checked.
     */
    fun endpointsUsableAtBoot(configured: List<NodeConfig>): List<NodeConfig> =
        configured.filter { it.enrollment == null }

    /**
     * Connects, if the user asked for it.
     *
     * Returns whether a tunnel was brought up. Every path that does not bring
     * one up says why on the way out, because "the tunnel did not come back" on
     * its own is a question the user cannot answer.
     */
    suspend fun connectIfWanted(context: Context, log: (String) -> Unit): Boolean {
        val settings = SettingsManager(context)
        if (!settings.autoConnectOnBoot()) {
            log("boot: the tunnel was not asked to come back")
            return false
        }

        // Android does not promise that the permission a VPN app was given
        // survives a restart, so this asks rather than assumes. A missing
        // permission is recorded, so the app can say why the tunnel did not
        // come back instead of leaving the user to work it out.
        if (VpnService.prepare(context) != null) {
            log("boot: the VPN permission has to be granted again before the tunnel can come back")
            settings.saveVpnConsentMissing(true)
            return false
        }
        settings.saveVpnConsentMissing(false)

        val configured = settings.loadNodes()
        if (configured.isEmpty()) {
            log("boot: no endpoint is configured, so there is nothing to connect to")
            return false
        }

        // An endpoint that is still waiting to be enrolled is left out: the
        // enrolment spends a token and answers with a credential that has to be
        // stored, and a boot has nobody to ask about a device that cannot
        // protect one.
        val endpoints = endpointsUsableAtBoot(configured)
        if (endpoints.isEmpty()) {
            log("boot: every endpoint is still waiting to be enrolled, which a boot cannot do")
            return false
        }
        if (endpoints.size != configured.size) {
            log("boot: ${configured.size - endpoints.size} endpoint(s) left out, still waiting to be enrolled")
        }

        val connector = ProxyConnector(object : ProxyConnector.ConnectionLog {
            override fun log(message: String) {
                log(message)
            }
        })

        val plan = ProxyConnector.Plan(
            nodes = endpoints,
            relayMode = settings.loadRelayMode(),
            relayUrl = settings.loadRelayUrl(),
            relayAuthToken = settings.loadRelayAuthToken(),
            deviceId = settings.deviceId(),
            // Read when the sequence asks for it, and for the endpoints it
            // carries: the boot path has nothing to wait for — the key was
            // sealed in an earlier session — but the sequence is the one that
            // decides when to read it.
            deviceKeys = { nodes ->
                nodes.mapNotNull { node ->
                    val key = settings.deviceKeyFor(node.nodeId)
                    if (key.isBlank()) null else node.nodeId to key
                }.toMap()
            }
        )

        // Throws when the attempt cannot be made; the caller decides what to do
        // about it. The sequence is the same one the screen runs, so a tunnel
        // brought up here is built exactly like one the user asked for.
        connector.prepare(context, plan)
        log("boot: the tunnel is up")

        // The service is what holds the TUN and the notification; the sequence
        // above only brought the proxy up behind it.
        val domains = endpoints.flatMap { it.domains }.distinct()
        val intent = Intent(context, NexaVpnService::class.java).apply {
            action = NexaVpnService.ACTION_START
            putStringArrayListExtra(NexaVpnService.EXTRA_DOMAINS, ArrayList(domains))
            // Carried through to the service: it is the only thing that lets
            // establish() past its own guard. A boot never carries it — see
            // the note about taking the slot at the top of this file.
            putExtra(NexaVpnService.EXTRA_ALLOW_TAKEOVER, false)
        }
        context.startForegroundService(intent)
        return true
    }
}
