package com.nexa.pipe.vpn

import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.RouteInfo
import android.os.Build
import android.util.Log
import com.nexa.pipe.IrohProxy
import java.net.Inet4Address

/**
 * The device's own answer to "which block is free", and the block that follows
 * from it.
 *
 * The survey is the Android half of the desktop's block policy: the desktop
 * asks the operating system which addresses the other interfaces hold and
 * which prefixes the other routes claim, and Android asks the framework for
 * the same two things about the networks the device is on.
 */
object VirtualBlockSurvey {
    private const val TAG = "VirtualBlockSurvey"

    /** What the device's networks have claimed. */
    data class Claims(
        /** The prefixes the interfaces hold their addresses on. */
        val held: List<VirtualBlockSelector.Prefix>,
        /** The prefixes the routes claim. */
        val routed: List<VirtualBlockSelector.Prefix>,
    )

    /**
     * The addresses and routes the device's other networks have claimed.
     *
     * [ownNetworks] holds the VPN networks that are ours: Android does not
     * label a VPN network with the app that owns it, so ours is identified by
     * which network appeared when we established (see NexaVpnService). Our own
     * tunnel claims the very block this survey is looking for, so counting it
     * would disqualify the block we are using.
     */
    @Suppress("DEPRECATION")
    fun claims(connectivityManager: ConnectivityManager, ownNetworks: Set<Network>): Claims {
        val held = mutableListOf<VirtualBlockSelector.Prefix>()
        val routed = mutableListOf<VirtualBlockSelector.Prefix>()

        for (network in connectivityManager.allNetworks) {
            if (ownNetworks.contains(network)) continue
            val properties = connectivityManager.getLinkProperties(network) ?: continue

            for (address in properties.linkAddresses) {
                val ipv4 = address.address as? Inet4Address ?: continue
                val bits = Ipv4.parse(ipv4.hostAddress ?: continue) ?: continue
                val length = address.prefixLength
                held += VirtualBlockSelector.Prefix(Ipv4.mask(length) and bits, length)
            }

            for (route in properties.routes) {
                val prefix = routePrefix(route) ?: continue
                routed += prefix
            }
        }

        return Claims(held, routed)
    }

    /**
     * Chooses the block the tunnel claims and tells the native side about it.
     *
     * The native side holds the addresses: the per-domain addresses it hands
     * the resolver live in the same block, so the two halves of the tunnel have
     * to agree about which addresses they are.
     *
     * Returns null when the block could not be determined. The caller has to
     * configure the VPN's addresses from it, and a VPN configured with
     * addresses the tunnel does not use is a tunnel that comes up and carries
     * nothing.
     */
    fun select(
        connectivityManager: ConnectivityManager?,
        ownNetworks: Set<Network>,
    ): VirtualBlock? {
        val candidates = runCatching { IrohProxy.nativeVirtualBlockCandidates() }
            .getOrNull()
            ?.split(',')
            ?.mapNotNull { Ipv4.parse(it) }
            ?.takeIf { it.isNotEmpty() }
        if (candidates == null) {
            Log.e(TAG, "The native side did not name any candidate block")
            return null
        }

        val taken = if (connectivityManager != null) {
            claims(connectivityManager, ownNetworks)
        } else {
            Claims(emptyList(), emptyList())
        }

        val evaluation = VirtualBlockSelector.evaluate(candidates, taken.held, taken.routed)
        for (reason in evaluation.skipped) {
            Log.d(TAG, "Skipping virtual block: $reason")
        }
        val base = evaluation.base
        if (base == null) {
            Log.e(TAG, "Every candidate block is claimed by another network")
            return null
        }

        val encoded = runCatching { IrohProxy.nativeVirtualBlock(Ipv4.format(base)) }
            .getOrNull()
        if (encoded == null) {
            Log.e(TAG, "The native side did not accept the block ${Ipv4.format(base)}")
            return null
        }
        return VirtualBlock.parse(encoded)
    }

    /**
     * The prefix a route claims, or null when it claims none.
     *
     * The destination is read where the framework hands it over as a prefix,
     * and the route's own text is read where it does not: that text is the
     * prefix with the next hop appended (`198.18.0.0/15 -> 192.168.1.1`), so
     * the prefix is what is in front of the arrow. The default route's text
     * is `0.0.0.0/0` — a prefix of length zero, which claims no block in
     * particular.
     */
    @Suppress("DEPRECATION")
    private fun routePrefix(route: RouteInfo): VirtualBlockSelector.Prefix? {
        val text = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // The destination is typed as non-null, but the default route has
            // none and the framework has been seen to hand one back anyway —
            // so it is read as nullable and the route's own text is the
            // fallback.
            val destination: IpPrefix? = route.destination
            destination?.toString() ?: route.toString()
        } else {
            route.toString()
        }
        return parsePrefix(text)
    }

    /**
     * Reads `198.18.0.0/15` into a prefix; anything else is not a prefix.
     *
     * A route's own text carries its next hop with it (`198.18.0.0/15 ->
     * 192.168.1.1`), so what is in front of the arrow is what is read: the
     * rest is not a prefix.
     */
    internal fun parsePrefix(text: String): VirtualBlockSelector.Prefix? {
        val parts = text.substringBefore(" ->").trim().split('/')
        if (parts.size != 2) return null
        val bits = Ipv4.parse(parts[0]) ?: return null
        val length = parts[1].toIntOrNull() ?: return null
        if (length !in 0..32) return null
        return VirtualBlockSelector.Prefix(Ipv4.mask(length) and bits, length)
    }
}
