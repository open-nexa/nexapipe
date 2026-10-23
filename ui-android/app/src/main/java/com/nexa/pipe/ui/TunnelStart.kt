package com.nexa.pipe.ui

import com.nexa.pipe.R
import com.nexa.pipe.locale.AppStrings
import com.nexa.pipe.vpn.NexaVpnService
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout

/**
 * Whether the tunnel of a start is up.
 *
 * The two things that say so, and only them: the service reported the
 * establish as done, and the service's own flag says a tunnel is there.
 *
 * The request being delivered says nothing — `startForegroundService()`
 * returns as soon as the request is delivered — and treating it as a tunnel
 * is what made the UI say "connected" over a tunnel that was never
 * established, and keep saying it when the establish failed.
 *
 * @param reportedUp what the service reported about the establish.
 * @param serviceActive whether the service says a tunnel is there.
 */
internal fun tunnelIsUp(reportedUp: Boolean, serviceActive: Boolean): Boolean =
    reportedUp && serviceActive

/**
 * Waits for the service to report whether the tunnel it was asked to build
 * came up.
 *
 * Bounded, because a service that says nothing at all must not leave the UI
 * saying "connecting" forever — and because a start nobody answered is not a
 * tunnel: the attempt is a failure and is retried like any other.
 *
 * @param outcome what the service will report about the start.
 * @param timeoutMs how long to wait for that report.
 * @param log where the line about a wait that ran out goes.
 * @return what the service reported: true when the tunnel is up.
 */
internal suspend fun awaitTunnelUp(
    outcome: CompletableDeferred<Boolean>,
    timeoutMs: Long,
    log: (String) -> Unit
): Boolean {
    return try {
        withTimeout(timeoutMs) { outcome.await() }
    } catch (e: TimeoutCancellationException) {
        // The service was asked and never answered. Not a cancellation of
        // the caller: the wait is over, and the attempt failed.
        log("The tunnel did not come up within ${timeoutMs}ms")
        false
    }
}

/**
 * What to tell the user when a start did not bring the tunnel up.
 *
 * The reason the service refused with, when there is one: another VPN
 * app owning the slot is something the user can act on, and a generic
 * "connection failed" would hide it.
 */
internal fun tunnelUpFailedMessage(): String =
    NexaVpnService.lastRevokeReason
        ?: AppStrings.get(R.string.error_connection_failed)
