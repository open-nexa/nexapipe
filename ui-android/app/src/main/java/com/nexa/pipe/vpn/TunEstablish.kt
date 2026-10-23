package com.nexa.pipe.vpn

import android.app.Service
import android.os.ParcelFileDescriptor
import android.util.Log
import com.nexa.pipe.IrohProxy
import com.nexa.pipe.R
import kotlinx.coroutines.TimeoutCancellationException

/**
 * The TUN: the interface Android gives the service, the descriptor that comes
 * with it, and the handover of that descriptor to the native side.
 *
 * The descriptor is the delicate part of the whole service: it changes hands
 * twice — from Android to this code, and from this code to Rust — and it has
 * to be closed exactly once. A second close of a number the process has
 * already handed on closes whatever holds that number now, and the failure is
 * silent; a missed close leaks the descriptor and leaves the device with a TUN
 * nobody drains. The rules are therefore written down where they are acted on,
 * and the code that follows them is not to be rearranged.
 *
 * The log tag is the one the service has always used: these logs are read by
 * that tag, and splitting the service must not change what they say.
 */
internal class TunEstablish(private val service: NexaVpnService) {
    private val TAG = "NexaVpnService"

    // TUN interface MTU. Must match TUN_MTU in crates/nexapipe-client/src/tun_proxy.rs and
    // ui-desktop/src-tauri/src/proxy/tun_proxy.rs. 1400 keeps one inner IP packet inside a
    // single QUIC datagram (~1435 usable bytes after the short header + AEAD tag); at 1500
    // every inner segment was split across two datagrams, roughly doubling the packet count
    // and AEAD cost.
    private val tunMtu = 1400

    /**
     * Establishes the VPN and the TUN proxy. Shared by the initial setup and
     * by the reconnect after a network switch.
     *
     * [allowTakeover] says the user has agreed to take the slot from another
     * VPN app. It is the only way past the guard below, and the rebuild path
     * never passes it.
     *
     * @return true on success; false on failure (the caller then handles the
     *         isRunning state).
     */
    suspend fun establish(allowTakeover: Boolean): Boolean {
        // A teardown that landed while this was still queued: none of what
        // follows would outlive the service, so do not even ask Android for a
        // TUN slot.
        if (service.isStopping) {
            Log.d(TAG, "Establish skipped: the service is stopping")
            return false
        }

        // The native library has to be there before a TUN is established.
        // Without it the calls below raise an UnsatisfiedLinkError — an
        // Error, not an Exception — which would escape the catch at the end
        // of this function and take the process with it. Establishing the TUN
        // first would be worse: the routes and the DNS server of the VPN
        // point into a TUN that nothing ever reads, so the device would be
        // left without DNS. Refuse before the TUN exists.
        if (!IrohProxy.isNativeLoaded()) {
            Log.e(TAG, "Establish failed: the native library is not loaded")
            return false
        }

        // Mutual-exclusion guard: Android allows only one active VpnService
        // TUN per user. If a foreign VPN app (e.g. Clash) currently owns the
        // slot, establish() would silently revoke it — refuse instead of
        // stealing it, unless the user agreed to take it. This single choke
        // point covers both the initial setup and the reconnect path
        // (rebuildTunnel), including the race where the other VPN started
        // while our session flags were still up.
        val slot = service.network.vpnSlot()
        val decision = VpnTakeoverPolicy.decide(
            slot,
            if (allowTakeover) VpnTakeoverChoice.TakeOver else VpnTakeoverChoice.Cancel
        )
        if (decision != VpnTakeoverDecision.Proceed) {
            val reason = when (decision) {
                is VpnTakeoverDecision.RefuseAlwaysOn ->
                    service.getString(R.string.error_vpn_always_on, decision.packageName)
                else -> service.getString(R.string.error_vpn_taken_over)
            }
            Log.e(TAG, "Another VPN owns the slot ($slot); refusing to establish")
            service.markRevoked()
            NexaVpnService.notifyVpnRevoked(reason)
            return false
        }

        val cm = service.network.connectivityManager
        // Snapshot before establish(): the VPN network that appears on top of
        // this is the one Android created for us.
        val vpnNetworksBefore = cm?.let { UnderlyingNetworkSelector.vpnNetworks(it) }.orEmpty()

        // The TUN descriptor's owner, tracked explicitly because it changes
        // hands three times below:
        //
        //   PFD   — Android opened it in establish(); the ParcelFileDescriptor
        //           owns it until detachFd() is called.
        //   LOCAL — after detachFd() this function owns the raw int.
        //   RUST  — once nativeStartTunProxy() has been entered the native
        //           side owns it and closes it on every path.
        //
        // Only one of the two variables below is ever set: the
        // ParcelFileDescriptor while it still owns the descriptor, the
        // detached int while this function owns it, and neither of them once
        // the native side has taken it. The descriptor has to be closed
        // exactly once — a second close of a number the process has already
        // handed on closes whatever holds that number now, and the failure is
        // silent — so the finally at the end of this function closes only
        // what is still ours.
        var tunPfd: ParcelFileDescriptor? = null
        var tunFd: Int? = null

        return try {
            // The block the tunnel claims, and the addresses inside it. The
            // native side holds them: the per-domain addresses it hands the
            // resolver live in the same block, so the two halves of the tunnel
            // cannot disagree about which addresses they are.
            val block = VirtualBlockSurvey.select(
                service.network.connectivityManager,
                service.network.ownVpnNetworks
            )
            if (block == null) {
                Log.e(TAG, "Could not determine the virtual block; refusing to establish")
                return false
            }
            Log.d(TAG, "Virtual block: ${block.network} and ${block.ipv6Network}/64")

            // The builder is the service's own: it carries the service with
            // it, and establish() below is what asks Android for the TUN.
            val builder = service.tunBuilder()
                .setSession("Nexa")
                // Must match TUN_MTU in crates/nexapipe-client/src/tun_proxy.rs.
                .setMtu(tunMtu)
                .addAddress(block.interfaceIp, 24)
                // The IPv6 half of the block. Without an address Android gives
                // the TUN no IPv6 at all, and a route to a prefix the interface
                // does not hold is refused, so both are needed for the AAAA
                // answers Rust hands out to be reachable.
                .addAddress(block.ipv6InterfaceIp, 64)
                // Route only the virtual IP ranges: the DNS server and the
                // per-domain addresses go through the TUN, and so does the IPv6
                // half of the block. Nothing else is claimed: the device's own
                // IPv6 traffic is not our business.
                .addRoute(block.base, 24)
                .addRoute(block.ipv6Network, 64)
                .addDnsServer(block.dnsIp)
                // Exclude this app's own traffic so proxy connections use the
                // physical network.
                .addDisallowedApplication(service.packageName)

            val selectedNetwork = service.network.underlyingNetwork
            if (selectedNetwork != null) {
                builder.setUnderlyingNetworks(arrayOf(selectedNetwork))
                Log.d(
                    TAG,
                    "Set underlying network: $selectedNetwork " +
                        "(${UnderlyingNetworkSelector.transportName(service.network.connectivityManager!!, selectedNetwork)})"
                )
            } else {
                Log.d(TAG, "No underlying network from callback, skipping setUnderlyingNetworks")
            }

            val pfd = builder.establish()
            if (pfd == null) {
                Log.d(TAG, "Failed to establish VPN")
                return false
            }
            // The ParcelFileDescriptor owns the descriptor from here until
            // detachFd() below.
            tunPfd = pfd

            // A suspension point, and the only one between the TUN coming up
            // and the descriptor changing hands: the coroutine can be
            // cancelled here — the user taps Disconnect while a network
            // switch is rebuilding, or the service is destroyed — and the
            // ParcelFileDescriptor is then the only thing holding the
            // descriptor. The finally below closes it. Without that the TUN
            // would stay established with nobody reading it while its routes
            // and its DNS server still point the device's DNS into it: a
            // device-wide DNS blackhole, with the foreground notification
            // taken away at the same time.
            service.network.trackOwnVpnNetwork(vpnNetworksBefore)

            // Transfer TUN fd ownership to Rust (the PFD is no longer usable
            // after detachFd).
            val fd = pfd.detachFd()
            tunPfd = null
            tunFd = fd

            val proxyDomainsStr = service.allowedDomains.joinToString(",")

            // TunProxy snapshots CUSTOM_DNS_SERVERS when it starts.  Refresh it
            // from the selected egress network so Wi-Fi and cellular DNS are
            // never mixed after a network switch.
            val dnsServers = UnderlyingNetworkSelector
                .dnsServers(service.network.connectivityManager!!, selectedNetwork)
            if (dnsServers.isNotEmpty()) {
                val dnsServersStr = dnsServers.joinToString(",")
                IrohProxy.nativeSetDnsServers(dnsServersStr)
                Log.d(TAG, "Set TUN DNS from ${UnderlyingNetworkSelector.transportName(service.network.connectivityManager!!, selectedNetwork)}: $dnsServersStr")
            } else {
                Log.w(TAG, "No DNS servers on selected underlying network: $selectedNetwork")
            }

            Log.d(TAG, "Starting TUN proxy: fd=$fd, " +
                    "proxyDomains=${service.allowedDomains.size} items")

            // The native side takes ownership of the descriptor: it closes it
            // on every path, including the ones that fail, because the
            // ownership transfer happens at the JNI boundary and it happens
            // once. So this side must not close it after the call — a second
            // close of a number the process may already have handed to
            // something else closes that instead, and the failure is silent.
            //
            // The one case where it is still ours is a native method that was
            // never entered at all, and that is what a `LinkageError` means:
            // the library or the method is not there. Anything else that
            // comes out of the call means the native method ran — it took the
            // descriptor and closed it on its way out — so closing it here
            // would be the second close this whole change is about.
            val result = try {
                IrohProxy.nativeStartTunProxy(
                    fd, proxyDomainsStr
                )
            } catch (e: Throwable) {
                if (e is LinkageError) {
                    Log.e(TAG, "nativeStartTunProxy could not be called at all", e)
                    // The native method was never entered, so it took the
                    // descriptor nowhere: it is still ours, and this is the
                    // only place that may close it.
                    closeTunFd(tunFd)
                } else {
                    Log.e(TAG, "nativeStartTunProxy threw after taking the fd", e)
                }
                throw e
            } finally {
                // The native side owns the descriptor from here on: it took it
                // at the JNI boundary and closes it on every path, including
                // the ones that fail. The LinkageError above is the one case
                // where it did not, and that branch closed it itself — so
                // there is nothing left here for the finally below.
                tunFd = null
            }

            if (result != 0) {
                Log.e(TAG, "Failed to start TUN proxy: $result")
                service.tunProxyStarted = false
                return false
            }

            // The service can be stopped while the call above blocks in Rust;
            // cancelling the scope never reached it, so ask again here. A
            // notification published now would belong to a service that is
            // gone, and the TUN proxy would outlive it.
            if (service.isStopping) {
                Log.d(TAG, "Service stopped during establish; discarding the TUN proxy")
                runCatching { IrohProxy.nativeStopTunProxy() }
                    .onFailure { Log.e(TAG, "nativeStopTunProxy after stop failed: ${it.message}") }
                service.tunProxyStarted = false
                return false
            }

            service.tunProxyStarted = true
            service.markSessionActive()
            // The tunnel is up, and whoever asked for it is waiting for
            // exactly this answer. The flag above is already true, so a
            // reader that looks at it now and one that is woken by this
            // call see the same thing.
            NexaVpnService.notifyStartOutcome(true)
            Log.d(
                TAG,
                "VPN + TUN proxy established successfully (routing ${block.network} and " +
                    "${block.ipv6Network}/64)"
            )
            service.notification.startForegroundConnected()
            // The tunnel is up, so the counters mean something: start showing them.
            service.notification.startTrafficPolling()
            true
        } catch (e: TimeoutCancellationException) {
            // The budget of the reconnect that called this ran out. It has to
            // leave the coroutine the way it found it: the caller decides what
            // a timeout means (a retry), and turning it into a plain failure
            // here would swallow it.
            throw e
        } catch (e: kotlinx.coroutines.CancellationException) {
            // A deliberate cancellation — the user disconnected, or the
            // service is being destroyed. It is not a failure of the
            // establish and must not become one: the descriptor is cleaned up
            // on the way out, and the caller has to see the cancellation
            // rather than a `false` that leaves the session flags standing
            // over a tunnel that is not there.
            Log.d(TAG, "Establish cancelled")
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "VPN establishment failed: ${e.message}", e)
            service.tunProxyStarted = false
            false
        } finally {
            // Close the descriptor if it is still ours to close: the
            // ParcelFileDescriptor while it still owns it, the detached int
            // while this function owns it, and nothing at all once the native
            // side has taken it. Only one of the two is ever set, so this
            // closes the descriptor exactly once.
            tunPfd?.let { owned ->
                try {
                    owned.close()
                } catch (e: Exception) {
                    Log.e(TAG, "Could not close the TUN descriptor: ${e.message}")
                }
            }
            closeTunFd(tunFd)
        }
    }

    /**
     * The half of the teardown that blocks: stopping the TUN proxy aborts the
     * smoltcp tasks and closes the duplicated fd, which brings the VPN down
     * with it.
     *
     * Running twice is harmless and expected — the Rust side takes the proxy
     * out of the state before stopping it, so the second call finds nothing
     * there — because every caller that stops the service calls [stopVPN] and
     * then reaches onDestroy(), which calls it again.
     */
    fun stopTunProxyAndLeaveForeground() {
        // Stop the TUN proxy first (abort the smoltcp task + close the
        // duplicated fd -> the VPN is torn down automatically).
        // Must run before touching vpnInterface, because fd ownership has been
        // transferred to Rust.
        try {
            IrohProxy.nativeStopTunProxy()
        } catch (e: Exception) {
            Log.e(TAG, "nativeStopTunProxy failed: ${e.message}")
        }

        // Nothing to close here: by the time the TUN proxy runs, the
        // descriptor belongs to Rust — nativeStartTunProxy took it at the JNI
        // boundary and nativeStopTunProxy above closed it. A descriptor that
        // was never handed over was closed by the establish that still held
        // it, which is the path this function used to leave open.
        service.stopForeground(Service.STOP_FOREGROUND_REMOVE)
    }

    /**
     * Closes a descriptor this side still owns.
     *
     * Only for a descriptor that was never handed to the native side: closing
     * a number the process has already handed on closes whatever holds that
     * number now, and the failure is silent.
     */
    private fun closeTunFd(fd: Int?) {
        if (fd == null) return
        try {
            ParcelFileDescriptor.adoptFd(fd).close()
        } catch (e: Exception) {
            Log.e(TAG, "Could not close the TUN descriptor $fd: ${e.message}")
        }
    }
}
