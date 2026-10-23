package com.nexa.pipe.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import kotlinx.coroutines.delay

/**
 * The networks the VPN service knows about: the physical network the tunnel
 * runs over, and the VPN networks Android created for it.
 *
 * Two things are tracked here, and they are told apart by identity rather
 * than by a flag: Android does not label a VPN network with the app that owns
 * it, so ours is recognised by which network appeared when we called
 * establish().
 *
 * The log tag is the one the service has always used: these logs are read by
 * that tag, and splitting the service must not change what they say.
 */
internal class VpnNetworkTracking(private val service: NexaVpnService) {
    private val TAG = "NexaVpnService"

    var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    // The physical network the tunnel runs over: the one the TUN names as its
    // underlying network, and the one the DNS servers come from.
    @Volatile var underlyingNetwork: Network? = null
    // The VPN networks Android created for our own TUN. Android does not label
    // a VPN network with the app that owns it, so ours is identified by which
    // network appeared when we called establish() — see trackOwnVpnNetwork.
    // Replaced wholesale rather than mutated in place: establish runs on the IO
    // dispatcher while stopVPN() and onRevoke() are entered on the main thread.
    // (stopVPN() only clears flags there — the native stop it used to run
    // inline is on teardownScope now.)
    @Volatile var ownVpnNetworks: Set<Network> = emptySet()
    // Whether the last establish could not tell which VPN network was ours.
    // Only then does vpnSlot() fall back to "a single unknown VPN while our own
    // session is up is our own tunnel"; the rest of the time identity decides.
    @Volatile var ownVpnUnidentified = false

    fun registerNetworkCallback() {
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                refreshUnderlyingNetwork("network available: $network")
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                super.onCapabilitiesChanged(network, capabilities)
                refreshUnderlyingNetwork("network capabilities changed: $network")
            }

            override fun onLost(network: Network) {
                super.onLost(network)
                refreshUnderlyingNetwork("network lost: $network")
            }
        }

        // NET_CAPABILITY_VALIDATED is deliberately not required: carriers often
        // hijack the connectivity check, so Wi-Fi may never be validated ->
        // onAvailable is never called -> underlyingNetwork stays null. We do not
        // hijack the system connectivity-check domains either; they are still
        // validated over the real physical network.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager?.registerNetworkCallback(request, networkCallback as ConnectivityManager.NetworkCallback)
    }

    /**
     * Re-evaluate all physical networks on every callback instead of retaining
     * the first one delivered by ConnectivityManager.  This makes the policy
     * deterministic: usable Wi-Fi always wins over cellular.
     */
    fun refreshUnderlyingNetwork(reason: String) {
        val cm = connectivityManager ?: return
        val selected = UnderlyingNetworkSelector.selectPreferredNetwork(cm)
        val previous = underlyingNetwork
        if (selected == previous) return

        underlyingNetwork = selected
        val selectedDescription = "${UnderlyingNetworkSelector.transportName(cm, selected)} $selected"
        Log.d(TAG, "Underlying network changed ($reason): $previous -> $selectedDescription")

        // The initial choice is consumed by the establish.  Once TUN is
        // running, a different preferred network needs a new VPN interface so
        // Android updates both the underlying network and the TUN DNS snapshot.
        service.onUnderlyingNetworkChanged("$reason; selected $selectedDescription")
    }

    fun unregisterNetworkCallback() {
        networkCallback?.let {
            connectivityManager?.unregisterNetworkCallback(it)
        }
    }

    /**
     * Records the VPN network Android created for the TUN just established.
     *
     * [before] is the set of VPN networks that existed when establish() was
     * called; whatever appears on top of it is ours. Android registers that
     * network asynchronously, hence the short wait: without a recorded network
     * the next rebuild would see our own tunnel as a foreign VPN and refuse to
     * re-establish, which would break network switching altogether.
     */
    suspend fun trackOwnVpnNetwork(before: Set<Network>) {
        val cm = connectivityManager ?: return
        var created: Set<Network> = emptySet()
        for (attempt in 0 until OWN_NETWORK_POLL_ATTEMPTS) {
            val appeared = UnderlyingNetworkSelector.vpnNetworks(cm) - before
            if (appeared.isNotEmpty()) {
                created = appeared
                break
            }
            if (attempt < OWN_NETWORK_POLL_ATTEMPTS - 1) delay(OWN_NETWORK_POLL_MS)
        }
        if (created.size != 1) {
            // Nothing appeared, or a foreign VPN appeared in the same window and
            // the two cannot be told apart. Guessing would let a rebuild revoke
            // that foreign VPN, so nothing is recorded and vpnSlot() keeps its
            // isServiceActive exemption for one network.
            ownVpnUnidentified = true
            Log.w(TAG, "Could not tell which VPN network is ours (${created.size} appeared)")
            return
        }
        val current = UnderlyingNetworkSelector.vpnNetworks(cm)
        // Drop the networks that are gone: the set would otherwise grow by one
        // on every network switch, none of them ever matching again.
        ownVpnNetworks = (ownVpnNetworks intersect current) + created
        ownVpnUnidentified = false
        Log.d(TAG, "Own VPN network: ${created.first()}")
    }

    /**
     * Who owns the platform VPN slot right now.
     *
     * Our own tunnel is excluded by identity rather than by a flag: a flag
     * cannot tell "our session is up" apart from "our session is up and another
     * app has already taken the slot", which is exactly the rebuild race that
     * used to revoke the other app.
     */
    fun vpnSlot(): VpnSlot {
        val cm = connectivityManager ?: return VpnSlot.Free
        val unknown = UnderlyingNetworkSelector.vpnNetworks(cm) - ownVpnNetworks
        val foreign = when {
            unknown.isEmpty() -> false
            // Our own tunnel could not be told apart from a foreign one when it
            // was established. Calling it foreign would tear the session down on
            // the next network switch, which is worse than leaving the old
            // exemption in place for a single network.
            ownVpnUnidentified && NexaVpnService.isServiceActive -> unknown.size > 1
            else -> true
        }
        if (!foreign) {
            return if (NexaVpnService.isServiceActive) VpnSlot.OwnSession else VpnSlot.Free
        }
        // Which network belongs to which package is not something Android tells
        // an app, so a configured always-on VPN is taken to be the VPN that is
        // up. Refusing is the safe answer: Android would restore it anyway.
        val alwaysOn = UnderlyingNetworkSelector.alwaysOnVpnPackage(service)
            ?: return VpnSlot.ForeignVpn
        return if (VpnTakeoverPolicy.isForeignAlwaysOn(alwaysOn, service.packageName)) {
            VpnSlot.AlwaysOnVpn(alwaysOn)
        } else {
            VpnSlot.ForeignVpn
        }
    }

    private companion object {
        // How long to wait for Android to register the VPN network of the TUN
        // we just established, and how often to look. Short on purpose: this
        // runs inside establish(), between the TUN coming up and the proxy
        // starting.
        const val OWN_NETWORK_POLL_ATTEMPTS = 5
        const val OWN_NETWORK_POLL_MS = 100L
    }
}
