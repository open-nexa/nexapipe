package com.nexa.pipe.vpn

import android.os.SystemClock
import android.util.Log
import com.nexa.pipe.ui.BootConnector
import kotlinx.coroutines.delay

/**
 * Bringing the tunnel back after a restart.
 *
 * The work is the same as a connection the user asked for — see
 * [com.nexa.pipe.ui.BootConnector] — and it runs in the service rather than in
 * the broadcast receiver because the service outlives the broadcast and can
 * wait for a network.
 *
 * The log tag is the one the service has always used: these logs are read by
 * that tag, and splitting the service must not change what they say.
 */
internal class BootReconnect(private val service: NexaVpnService) {
    private val TAG = "NexaVpnService"

    /**
     * Brings the tunnel back after a restart.
     *
     * The work is the same as a connection the user asked for — see
     * [com.nexa.pipe.ui.BootConnector] — and it runs here rather than in the
     * broadcast receiver because this service outlives the broadcast and can
     * wait for a network.
     */
    suspend fun bootConnect() {
        if (!awaitNetwork(BOOT_NETWORK_TIMEOUT_MS)) {
            Log.w(TAG, "boot: no network came up in time, so the tunnel stays down")
            service.notification.shutdownService()
            return
        }

        when (val outcome = BootConnector.connectIfWanted(service) { Log.i(TAG, it) }) {
            is BootConnector.BootOutcome.Established -> {
                // The tunnel itself is the service's to establish, and it does
                // that after this returns.
            }
            is BootConnector.BootOutcome.Failed -> {
                Log.w(TAG, "boot connect failed: ${outcome.cause.message}")
                // The attempt may have brought the native side up before it
                // failed, and that side is process-global: the iroh endpoint
                // and the endpoint group with their warm backend connections
                // outlive the service that started them, so a failed attempt
                // would leave a live QUIC connection to the relay behind
                // nothing that the user can see or stop. They are taken down
                // here as well; the user's path does the same through
                // releaseAllResources().
                service.releaseNativeResources()
                service.notification.shutdownService()
            }
            is BootConnector.BootOutcome.Skipped -> {
                // Nothing was started, so nothing is left behind to take
                // down: the native side is process-global, and what is running
                // in it may belong to a session that is not this one's to end.
                service.notification.shutdownService()
            }
        }
    }

    /**
     * Waits for a network to come up.
     *
     * A boot broadcast arrives while the phone is still finding its way onto
     * a network, and a tunnel built on no network reaches no backend. Polling
     * is enough here: what is being waited for is a fact about the radio, and
     * the radio does not offer a better signal than "there is a network now".
     *
     * Bounded, because waiting forever is the same as not trying: the phone
     * may never get a network, and a foreground service waiting for one it
     * will never have is a notification nobody asked for.
     */
    private suspend fun awaitNetwork(timeoutMs: Long): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (SystemClock.elapsedRealtime() < deadline) {
            if (service.network.connectivityManager?.activeNetwork != null) {
                return true
            }
            delay(BOOT_NETWORK_POLL_MS)
        }
        return false
    }

    private companion object {
        // How long the boot path waits for a network, and how often it looks.
        //
        // Generous, because a phone that has just been switched on has to find
        // a network first, and a tunnel built on no network reaches no
        // backend — but bounded, because a phone that never finds one must not
        // leave a foreground service waiting for it.
        const val BOOT_NETWORK_TIMEOUT_MS = 60_000L
        const val BOOT_NETWORK_POLL_MS = 1_000L
    }
}
