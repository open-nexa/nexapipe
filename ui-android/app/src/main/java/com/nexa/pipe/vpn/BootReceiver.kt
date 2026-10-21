package com.nexa.pipe.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.nexa.pipe.ui.BootConnector

/**
 * Starts the tunnel again after the machine has been restarted.
 *
 * The receiver does nothing but hand the work to the VPN service, which is
 * already a foreground service with a notification of its own. A broadcast
 * receiver has about ten seconds to finish with — not enough to wait for a
 * network to come up and bring a tunnel with it — and a service already
 * outlives the broadcast that started it.
 *
 * The receiver is exported because that is what a receiver of a system
 * broadcast has to be, and it is safe: `BOOT_COMPLETED` is a protected
 * broadcast, so no other app can send one.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) {
            return
        }
        // Asked before anything is started: a user who has not asked for this
        // is not woken by a service on every restart.
        if (!BootConnector.isWanted(context)) {
            Log.i(TAG, "boot: the tunnel was not asked to come back")
            return
        }

        val service = Intent(context, NexaVpnService::class.java).apply {
            action = NexaVpnService.ACTION_BOOT_CONNECT
        }
        try {
            context.startForegroundService(service)
        } catch (e: Exception) {
            // The service could not be started — a foreground service is not
            // allowed from the background in some states, and the rules about
            // that change. The tunnel stays down, and the log says why.
            Log.w(TAG, "boot: the VPN service could not be started: ${e.message}")
        }
    }

    private companion object {
        const val TAG = "BootReceiver"
    }
}
