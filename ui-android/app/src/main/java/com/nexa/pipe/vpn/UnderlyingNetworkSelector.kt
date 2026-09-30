package com.nexa.pipe.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.provider.Settings

/**
 * Selects the physical network used by Nexa's VPN and exposes its DNS servers.
 *
 * A VPN must name its actual egress network with setUnderlyingNetworks().  Do
 * not use callback delivery order here: when Wi-Fi and cellular are both up,
 * Android is free to report cellular first.  Nexa deliberately prefers Wi-Fi
 * whenever it is connected and usable, then falls back to cellular.
 */
object UnderlyingNetworkSelector {
    /**
     * The `Settings.Secure` key holding the package name of the device's
     * always-on VPN. Not part of the SDK — see [alwaysOnVpnPackage].
     */
    private const val ALWAYS_ON_VPN_APP = "always_on_vpn_app"

    @Suppress("DEPRECATION")
    fun selectPreferredNetwork(connectivityManager: ConnectivityManager): Network? {
        var cellular: Network? = null

        for (network in connectivityManager.allNetworks) {
            val capabilities = connectivityManager.getNetworkCapabilities(network) ?: continue
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            ) {
                continue
            }

            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return network
            }
            if (cellular == null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                cellular = network
            }
        }

        return cellular
    }

    /**
     * Every network Android is currently reporting as a VPN.
     *
     * Android allows only one active VpnService TUN per user, so this doubles
     * as the occupancy check before establish(). `activeNetwork` alone is not
     * enough: a per-app / split-tunnel VPN, or one still in the window before
     * it becomes the default network, is up without being the default — and
     * establish() would revoke it just the same.
     */
    @Suppress("DEPRECATION")
    fun vpnNetworks(connectivityManager: ConnectivityManager): Set<Network> {
        val vpn = LinkedHashSet<Network>()
        for (network in connectivityManager.allNetworks) {
            val capabilities = connectivityManager.getNetworkCapabilities(network) ?: continue
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpn.add(network)
            }
        }
        return vpn
    }

    /**
     * The package name of the device's always-on VPN, or null when none is
     * configured — or when the answer is not available.
     *
     * `ConnectivityManager.getAlwaysOnVpnPackageForUser` is the documented way
     * to ask, but it is a privileged call: a third-party app gets a
     * SecurityException rather than an answer. The setting behind it is
     * world-readable, so it is read from `Settings.Secure` instead. That key is
     * not part of the SDK, hence the best-effort reading: when this returns
     * null the caller treats the other VPN as an ordinary foreign one and
     * asks, which is the harmless direction to be wrong in.
     *
     * Which network belongs to which package is not something Android tells an
     * app, so a configured always-on VPN is treated as the VPN that is up.
     */
    fun alwaysOnVpnPackage(context: Context): String? = runCatching {
        Settings.Secure.getString(context.contentResolver, ALWAYS_ON_VPN_APP)
    }.getOrNull()?.takeIf { it.isNotBlank() }

    fun dnsServers(connectivityManager: ConnectivityManager, network: Network?): List<String> {
        if (network == null) return emptyList()

        return connectivityManager.getLinkProperties(network)
            ?.dnsServers
            ?.mapNotNull { it.hostAddress }
            ?.distinct()
            .orEmpty()
    }

    fun transportName(connectivityManager: ConnectivityManager, network: Network?): String = when {
        network == null -> "none"
        connectivityManager.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "Wi-Fi"
        connectivityManager.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
        else -> "unknown"
    }
}
