package com.nexa.pipe.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.util.Log
import com.nexa.pipe.IrohProxy
import com.nexa.pipe.R
import com.nexa.pipe.locale.AppLocale
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull

/**
 * VPN service: creates the TUN interface and hands the fd over to the smoltcp
 * TUN proxy on the Rust side.
 *
 * The original ~1600-line hand-written TCP/IP stack has been removed and
 * replaced by the Rust netstack-smoltcp userspace stack. The Kotlin side is
 * only responsible for establishing the VPN, network callbacks, the foreground
 * service, and passing the TUN fd to Rust.
 *
 * Data flow: APP -> TUN fd -> Rust(smoltcp) -> handle_local_connection ->
 * iroh -> backend. DNS hijacking and TCP MSS / retransmit / FIN-ACK handling
 * are all done on the Rust side.
 *
 * This class is the part the system talks to: the lifecycle, the session, the
 * rebuild after a network switch, and the events the UI listens to. The parts
 * it is made of are classes of their own, one per file, in this package:
 *
 *  - [VpnNotification] — the notification and the foreground service.
 *  - [TunEstablish] — the TUN: establish(), the fd handover, the teardown.
 *  - [VpnNetworkTracking] — the underlying network and the VPN networks.
 *  - [BootReconnect] — bringing the tunnel back after a restart.
 */
class NexaVpnService : VpnService() {
    // The notification this service shows is written from its own context, so
    // it needs the selected language as much as the Activity does; switching
    // language and reconnecting is enough to rebuild it.
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLocale.apply(newBase))
    }

    private val TAG = "NexaVpnService"
    // The TUN descriptor is not held in a field: it belongs to the establish
    // that opened it, from establish() until the native side takes it, and
    // that is also where it is closed when it never gets that far. See
    // TunEstablish.establish.

    // @Volatile: written from the main thread (onStartCommand/onRevoke) and
    // read from IO coroutines (reconnect logic).
    @Volatile private var isRunning = false
    // Set for good by stopVPN(), cleared by startVPN(): the service is on its
    // way out, so an establish that is already running must not publish
    // anything. Cancelling the scope cannot stop it — the native call chain
    // blocks in Rust and has no suspension point a cancellation could hit — so
    // the cooperation has to be explicit.
    @Volatile internal var isStopping = false
    internal var allowedDomains = mutableSetOf<String>()

    // Whether the user agreed, for this connect, that Nexa may take the slot
    // from another VPN app. Never set on the rebuild path: a network switch
    // must not revoke a VPN that took over while ours was being rebuilt.
    @Volatile private var allowTakeover = false
    internal val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    // A second scope, deliberately not `serviceScope`: onDestroy() cancels that
    // one the moment stopVPN() returns, so the teardown stopVPN() schedules
    // there would be cancelled before it ever ran and the duplicated fd would
    // stay open. This one is never cancelled — the only thing it runs is a
    // native stop, which has to finish whether or not the service is still
    // alive to hear about it.
    private val teardownScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    // The boot connection, while it runs. Kept so it can be cancelled with
    // the service rather than left behind holding a native call.
    private var bootConnectJob: Job? = null
    @Volatile private var isUserStarted = false

    // Reconnect on network switch: keeps the reconnect job. The mutex serializes the rebuilds
    // themselves — one cannot be interrupted inside a native call, so two must never run at once.
    private var reconnectJob: Job? = null
    // Whether the TUN proxy has started successfully. A network switch only
    // triggers a reconnect when this is true, so the initial VPN setup cannot
    // trigger one by accident.
    @Volatile internal var tunProxyStarted = false
    private val reconnectMutex = Mutex()

    // The parts this service is made of. Each one is a class of its own, in
    // its own file, in this package — the service holds them and calls them.
    internal val notification = VpnNotification(this)
    internal val tun = TunEstablish(this)
    internal val network = VpnNetworkTracking(this)
    internal val boot = BootReconnect(this)

    // The addresses of the TUN are not written down here: the block the tunnel
    // claims is chosen per session (see VirtualBlockSurvey), and the addresses
    // inside it come from the native side — the same block the per-domain
    // addresses are handed out of. The legacy proxy address (`.3` in that
    // block) is not needed here: DNS responses are built by Rust, and TCP
    // traffic is split by Rust according to local_addr.ip().
    //
    // Note: do not hijack the system captive-portal check domains
    // (connectivitycheck.gstatic.com and friends) to a private IP. Android's
    // NetworkMonitor treats "the check domain resolves to a private IP" as "no
    // internet", which puts an exclamation mark on the Wi-Fi icon in the status
    // bar. Let them use real DNS over the physical network instead.

    override fun onCreate() {
        super.onCreate()
        network.connectivityManager =
            getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        network.registerNetworkCallback()
        network.refreshUnderlyingNetwork("service created")
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVPN()
        network.unregisterNetworkCallback()
        // Cancel the scope last: it is what would otherwise keep a slow
        // establish alive past the service. nativeStartTunProxy blocks for
        // tens of seconds, so this alone does not stop one that is already
        // inside it — that is what the isStopping checks are for — but it does
        // stop everything that was still waiting to run (a debounced
        // reconnect, a warm-up) from running against a dead service.
        serviceScope.cancel()
    }

    fun startVPN(domains: Set<String>, allowTakeover: Boolean = false) {
        this.allowedDomains = domains.toMutableSet()
        this.allowTakeover = allowTakeover
        isUserStarted = true
        // A new session begins: clear the stale "revoked" marker from a
        // previous session (consumed by VpnViewModel.syncVpnServiceState()),
        // and the reason that came with it.
        wasRevoked = false
        lastRevokeReason = null

        // The tunnel of this session is not up yet, whatever an earlier
        // session left behind: the flag says a tunnel is there, and it has
        // to mean *this* one — a UI that reads it while this session is
        // still being built would call a tunnel that is not there a
        // connected one.
        isServiceActive = false

        // A new session clears the teardown marker: the same service instance
        // is reused when the user stops and starts again without the process
        // being recreated, and an establish must be allowed to run then.
        isStopping = false

        val prepareIntent = prepare(this)
        if (prepareIntent != null) {
            Log.d(TAG, "VPN permission not granted")
            // The service goes away with it: a foreground service with no
            // tunnel behind it is a notification that says the tunnel is up
            // over a tunnel that is not there, and there is nothing else this
            // start was going to do. The boot path reaches this when the
            // consent was withdrawn between its own check and this one.
            //
            // The native side goes with it: this start was handed a proxy that
            // is already up — the boot path brings the native side up before
            // it asks the service to establish, and so does the screen — and
            // that side is process-global, so a service that goes away with it
            // still running leaves a live connection to the relay behind
            // nothing that the user can see or stop.
            releaseNativeResources()
            // The start is over and there is no tunnel: whoever asked for
            // it is waiting for exactly this answer.
            notifyStartOutcome(false)
            notification.shutdownService()
            return
        }

        // ACTION_START means VpnViewModel wants the VPN re-established (with a
        // new TUN fd). nativeStopProxy (called by startProxyWithRetries during
        // connect) already stopped the Rust TUN proxy, but isRunning may still
        // be true because the service was never stopped through stopVPN.
        // isRunning must be reset, otherwise establishVPN bails out with
        // "VPN already running" and the TUN proxy is never rebuilt -> the data
        // plane is dead (it looks like the connection drops right after
        // connecting).
        synchronized(this@NexaVpnService) {
            if (isRunning) {
                Log.d(TAG, "startVPN: resetting isRunning (TUN proxy was stopped by nativeStopProxy)")
                isRunning = false
                tunProxyStarted = false
            }
        }
        // Cancel any pending reconnect so it cannot race with the new setup.
        reconnectJob?.cancel()
        reconnectJob = null

        network.refreshUnderlyingNetwork("VPN start requested")
        establishVPN()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            // A sticky restart: the system brought the service back without an
            // intent, and a service started with startForegroundService() has
            // five seconds to call startForeground() or the system takes the
            // app down with it.
            //
            // What the machine asks for when it wants the tunnel back is the
            // boot path, and that path ends the service when it cannot bring
            // a tunnel up — so nothing is left running over a tunnel that is
            // not there.
            notification.startForegroundConnecting()
            bootConnectJob = serviceScope.launch {
                boot.bootConnect()
            }
            return START_STICKY
        }

        when (intent.action) {
            ACTION_START -> {
                val domains = intent.getStringArrayListExtra(EXTRA_DOMAINS) ?: emptyList()
                // Whether the UI asked and was told to take the slot from
                // another VPN app. Absent means no: a start that carries no
                // such answer must not revoke anything.
                val takeover = intent.getBooleanExtra(EXTRA_ALLOW_TAKEOVER, false)
                // The same obligation the boot path meets, and for the same
                // reason: a service started with startForegroundService() has
                // five seconds to call startForeground(), and the system takes
                // the app down when it does not. Everything startVPN() does
                // before its own startForeground() — the consent check, the
                // establish, and the wait for Android to register the VPN
                // network — can take longer than that, so the obligation is
                // met here, before any of it.
                notification.startForegroundConnecting()
                startVPN(domains.toSet(), takeover)
            }
            ACTION_STOP -> {
                stopVPN()
            }
            ACTION_BOOT_CONNECT -> {
                // The machine asked for the tunnel to come back.
                //
                // Android gives a service started with
                // startForegroundService() five seconds to call
                // startForeground(), and the wait for a network below can
                // take longer than that, so the obligation is met here —
                // with the text that says what is happening rather than
                // the one that says the tunnel is up, because it is not
                // yet.
                notification.startForegroundConnecting()
                bootConnectJob = serviceScope.launch {
                    boot.bootConnect()
                }
            }
        }
        return START_STICKY
    }

    /**
     * Takes down the native side of a start that is not going to happen.
     *
     * The iroh endpoint and the endpoint group are process-global and outlive
     * the service: the service owns the TUN and the notification, and the
     * native side owns the connection to the relay and the warm backend
     * connections behind it. A start that is refused after the native side was
     * brought up — a boot attempt that failed, a tunnel that could not be
     * established because the consent was withdrawn — leaves all of it behind,
     * with no service and no notification and nothing the user can stop.
     *
     * The teardown is process-global, so it takes down whatever else is
     * running in the process as well. It is therefore only for a start that
     * brought the native side up: an attempt that started nothing must not
     * call it, or it ends a session that belongs to somebody else.
     *
     * It runs on the teardown scope and not on the caller's thread: the
     * native stop closes the endpoint and the warm connections behind it, and
     * that blocks for as long as they take — long enough to be the system's
     * "the app is not responding" on the main thread.
     */
    internal fun releaseNativeResources() {
        teardownScope.launch {
            // The library may not be there at all, and the call would raise an
            // UnsatisfiedLinkError — an Error, not an Exception — which would
            // escape the catch below and take the process with it.
            if (!IrohProxy.isNativeLoaded()) return@launch
            try {
                IrohProxy.nativeDestroy()
            } catch (e: Exception) {
                Log.e(TAG, "nativeDestroy failed: ${e.message}")
            }
        }
    }

    /**
     * The system revoked our VPN: another VPN app (e.g. Clash) was established
     * and took over the single VPN slot Android allows per user.
     *
     * Without this override the service used to keep running with stale state
     * (isRunning / tunProxyStarted / isServiceActive all true), so the next
     * network switch triggered a reconnect that called establish() again and
     * stole the VPN slot back from the other app — a "VPN war" where both apps
     * kept killing each other. Instead: reset every session flag synchronously
     * (so an in-flight reconnect aborts), tear down off the main thread, stop
     * the service, and notify the UI.
     */
    override fun onRevoke() {
        Log.w(TAG, "onRevoke: another VPN app took over the VPN slot, tearing down")
        // Synchronous flag reset: reconnectTunnel()/rebuildTunnel() check these
        // before re-establishing, so this closes the steal-back race immediately.
        isUserStarted = false
        isRunning = false
        tunProxyStarted = false
        isServiceActive = false
        // The session is over, and no tunnel is coming up for it: whoever is
        // waiting for one is told now rather than at the end of its wait.
        notifyStartOutcome(false)
        network.ownVpnNetworks = emptySet()
        network.ownVpnUnidentified = false
        wasRevoked = true
        reconnectJob?.cancel()
        reconnectJob = null

        // stopVPN() defers the native stop itself, so this is not what keeps
        // the main thread free any more — but notifyVpnRevoked() and
        // stopSelf() must still follow it, and they cannot run on the main
        // thread that onRevoke() was called on either.
        serviceScope.launch {
            stopVPN()
            // Notified before stopping: stopSelf() runs onDestroy(), which
            // cancels this scope, and the UI would otherwise wait for a signal
            // that the shutdown it triggered cut off.
            notifyVpnRevoked(getString(R.string.error_vpn_taken_over))
            stopSelf()
        }
    }

    /**
     * Tear the session down.
     *
     * Every flag is cleared synchronously, because an establish or a reconnect
     * that is already running reads them and has to see this before it goes
     * any further — that is why this is safe to call from the main thread.
     * The native stop is not: it joins the smoltcp tasks, up to ~500 ms each,
     * and is handed to [teardownScope] instead.
     */
    fun stopVPN() {
        isRunning = false
        isUserStarted = false
        tunProxyStarted = false
        isServiceActive = false
        network.ownVpnNetworks = emptySet()
        network.ownVpnUnidentified = false
        // First, so an establish that is already running sees it however far
        // it gets.
        isStopping = true
        // Cancel an in-flight reconnect so it cannot race with this manual
        // disconnect.
        reconnectJob?.cancel()
        reconnectJob = null
        // ...and the notification's rate, whose job belongs to this service and
        // would otherwise keep reading counters of a proxy that is going away.
        notification.stopTrafficPolling()

        teardownScope.launch { tun.stopTunProxyAndLeaveForeground() }
    }

    private fun establishVPN() {
        synchronized(this@NexaVpnService) {
            if (isRunning) {
                Log.d(TAG, "VPN already running, skipping")
                return
            }
            isRunning = true
        }

        serviceScope.launch {
            if (!tun.establish(allowTakeover)) {
                Log.d(TAG, "VPN establishment failed")
                isRunning = false
                // The start is over and there is no tunnel: whoever asked for
                // it is waiting for exactly this answer, and the attempt has
                // to be retried rather than announced as a success.
                notifyStartOutcome(false)
                // Nothing left to shut down when the service is already going
                // away: startForeground() after stopSelf() is what throws
                // ForegroundServiceDidNotStartInTimeException, and the service
                // is being stopped anyway.
                if (!isStopping) notification.shutdownService()
            }
        }
    }

    // ============================================================
    // Network-switch reconnect - rebuild the whole tunnel when the
    // underlying network (Wi-Fi / cellular) changes
    // ============================================================

    internal fun onUnderlyingNetworkChanged(reason: String) {
        // Only trigger once the user has started the VPN and the TUN proxy is
        // up, so the initial setup cannot trigger it by accident.
        if (!isUserStarted || !isRunning || !tunProxyStarted) {
            Log.d(TAG, "Network change ignored ($reason): session not fully up")
            return
        }
        Log.d(TAG, "Network change detected ($reason), scheduling reconnect")
        scheduleReconnect()
    }

    private fun scheduleReconnect() {
        // Debounce: consecutive onLost/onAvailable collapse into the last one,
        // and the new network gets a moment to settle.
        reconnectJob?.cancel()
        reconnectJob = serviceScope.launch {
            delay(RECONNECT_DEBOUNCE_MS)
            reconnectTunnel()
        }
    }

    /**
     * Runs one reconnect, serialized against any other.
     *
     * The debounce cancels the previous job, but a cancelled coroutine only notices at a
     * suspension point and a rebuild has none inside its native calls — so the previous attempt
     * can still be mid-flight when this one starts. Waiting for it is the whole point: the
     * earlier code returned on "already in progress" instead, and the attempt that had been
     * cancelled had already stopped the TUN proxy. That combination is how a network switch
     * could end with the TUN down and nothing left to rebuild it.
     */
    private suspend fun reconnectTunnel() {
        if (!isUserStarted || !isRunning) return
        val completed = withTimeoutOrNull(RECONNECT_HANDOVER_TIMEOUT_MS) {
            reconnectMutex.withLock { reconnectTunnelOnce() }
            true
        }
        if (completed == null) {
            Log.w(
                TAG,
                "Reconnect: the previous attempt did not finish within " +
                    "${RECONNECT_HANDOVER_TIMEOUT_MS}ms, skipping this one"
            )
        }
    }

    private suspend fun reconnectTunnelOnce() {
        // The switch is not finished yet (e.g. airplane mode was turned
        // on): wait for the next network event.
        if (network.underlyingNetwork == null) {
            Log.d(TAG, "Reconnect: no underlying network yet, skipping")
            return
        }
        if (!IrohProxy.isNativeLoaded()) {
            Log.e(TAG, "Reconnect: native library not loaded")
            return
        }
        Log.d(TAG, "Reconnect: rebuilding tunnel on underlying network ${network.underlyingNetwork}")

        var lastError: Exception? = null
        for (attempt in 1..MAX_RECONNECT_ATTEMPTS) {
            if (!isUserStarted || !isRunning) return
            try {
                withTimeout(RECONNECT_ATTEMPT_TIMEOUT_MS) {
                    rebuildTunnel()
                }
                Log.d(TAG, "Reconnect complete (attempt $attempt/$MAX_RECONNECT_ATTEMPTS)")
                return
            } catch (e: TimeoutCancellationException) {
                lastError = e
                Log.e(TAG, "Reconnect attempt $attempt/$MAX_RECONNECT_ATTEMPTS timed out")
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Deliberate cancellation from a manual disconnect or
                // service destruction: do not retry.
                throw e
            } catch (e: Exception) {
                lastError = e
                Log.e(TAG, "Reconnect attempt $attempt/$MAX_RECONNECT_ATTEMPTS failed: ${e.message}")
            }
            if (attempt < MAX_RECONNECT_ATTEMPTS) {
                delay(RECONNECT_BACKOFF_MS)
            }
        }
        Log.e(TAG, "Reconnect: all attempts failed: ${lastError?.message}")
        // The TUN proxy is stopped at this point and the VPN went down with it, while
        // `isRunning` / `isServiceActive` are still true. That combination is what used to
        // leave the UI showing "Connected" over a dead data plane with no way back short of
        // killing the app: report it and tear the session down so the UI can say so and the
        // user can reconnect.
        //
        // Tear the session down *before* reporting it: the UI tells "the session is over" apart
        // from "the tunnel is up but the backend is not answering" by looking at
        // isServiceActive, which stopVPN() has just cleared.
        stopVPN()
        stopSelf()
        notifyBroken(getString(R.string.notify_tunnel_rebuild_failed))
    }

    /**
     * Rebuilds the tunnel: stop the old TUN proxy -> drop the connections that
     * were opened on the previous network -> re-establish the VPN and the TUN
     * proxy on the new underlying network -> warm the pool again.
     *
     * The iroh endpoint and the local proxy are left untouched on purpose:
     * recreating the endpoint opens an outage window of seconds to tens of
     * seconds (nativeStartIroh can block for 30s on a weak network) and may
     * leave the tunnel unusable if the rebuild fails.
     *
     * Step 2 is the one that used to be missing, and it is why a rebuilt tunnel
     * could still not reach the backend: QUIC does not notice a network switch.
     * A connection opened on the old network reports no close reason while its
     * path is dead, so the pool keeps handing it out and every proxied request
     * fails or hangs — the UI says "Connected" over a tunnel that carries
     * nothing. Dropping them makes the next request dial on the network that is
     * actually up.
     */
    private suspend fun rebuildTunnel() {
        // 1. Stop the old TUN proxy (closes the duplicated fd -> the old VPN is
        //    torn down automatically).
        runCatching { IrohProxy.nativeStopTunProxy() }
            .onFailure { Log.e(TAG, "Reconnect: nativeStopTunProxy failed: ${it.message}") }
        tunProxyStarted = false

        // 2. Forget the connections the old network left behind.
        runCatching { IrohProxy.nativeDropConnections() }
            .onFailure { Log.e(TAG, "Reconnect: nativeDropConnections failed: ${it.message}") }

        // 3. Re-establish the VPN (new TUN fd + new underlying network) and
        //    start the TUN proxy. Never with the user's takeover consent: a
        //    network switch is not an answer to "may we disconnect the other
        //    app", and a foreign VPN that arrived during the rebuild must not
        //    be revoked by it.
        if (!tun.establish(allowTakeover = false)) {
            throw Exception("Reconnect: failed to re-establish VPN/TUN proxy")
        }

        // 4. Warm the pool again, and check that the backend is reachable from
        //    the new network. Without this a network the backend cannot be
        //    dialed on looks exactly like a working one until a request fails.
        val warmed = IrohProxy.nativePreconnect()
        if (warmed <= 0) {
            Log.w(TAG, "Reconnect: no backend answered the warm-up (nativePreconnect=$warmed)")
            notifyBroken(getString(R.string.notify_backend_unreachable))
        } else {
            Log.d(TAG, "Reconnect: $warmed backend(s) reachable on the new network")
        }
    }

    /**
     * The builder for the TUN.
     *
     * It is made here and not in [TunEstablish] because
     * `VpnService.Builder` is an inner class of `VpnService`: only the
     * service itself can make one that carries the service with it, and that
     * is what lets the builder ask Android for the interface.
     */
    internal fun tunBuilder(): VpnService.Builder = Builder()

    /**
     * Marks the session as up: the flag is the one the UI reads to know that
     * the tunnel is there.
     *
     * The establish is what raises it, and it lives in [TunEstablish] now, so
     * the flag is raised through here.
     */
    internal fun markSessionActive() {
        isServiceActive = true
    }

    /**
     * Marks the VPN slot as lost to another app: the same event
     * [wasRevoked] stands for, raised from the establish that refused to
     * steal the slot back.
     */
    internal fun markRevoked() {
        wasRevoked = true
    }

    companion object {
        const val ACTION_START = "com.nexa.pipe.vpn.ACTION_START"
        const val ACTION_STOP = "com.nexa.pipe.vpn.ACTION_STOP"
        /**
         * Bring the tunnel back after a restart.
         *
         * Sent by [BootReceiver] rather than by the screen: the user asked
         * for the tunnel to come back when the machine starts, and there is no
         * screen to ask at that point.
         */
        const val ACTION_BOOT_CONNECT = "com.nexa.pipe.vpn.ACTION_BOOT_CONNECT"
        const val EXTRA_DOMAINS = "com.nexa.pipe.vpn.EXTRA_DOMAINS"
        // Whether the user agreed that Nexa may take the slot from another VPN
        // app. Carried by ACTION_START; absent (or false) means the service
        // refuses to establish rather than revoking the other app.
        const val EXTRA_ALLOW_TAKEOVER = "com.nexa.pipe.vpn.EXTRA_ALLOW_TAKEOVER"

        // Network-switch reconnect parameters
        private const val RECONNECT_DEBOUNCE_MS = 1_500L
        private const val MAX_RECONNECT_ATTEMPTS = 3
        private const val RECONNECT_ATTEMPT_TIMEOUT_MS = 60_000L
        private const val RECONNECT_BACKOFF_MS = 2_000L
        // How long a new reconnect waits for the one before it. Generous on purpose: a rebuild
        // blocked in a native call cannot be interrupted, so the wait is what keeps two of them
        // from ever touching the TUN at the same time.
        private const val RECONNECT_HANDOVER_TIMEOUT_MS = 120_000L

        /**
         * Process-level flag: whether the VPN service is active (the TUN proxy
         * has been established). Used by the ViewModel to sync the UI state
         * after the activity is recreated, so the UI cannot show
         * "Disconnected" while the VPN service is actually still running.
         */
        @Volatile
        @JvmStatic
        var isServiceActive: Boolean = false
            private set

        /**
         * Set when the VPN slot was lost to another VPN app: either onRevoke()
         * fired (the other app displaced our established VPN) or the
         * establish-time mutual-exclusion guard refused to steal the slot
         * back. Consumed by VpnViewModel.syncVpnServiceState() so the UI
         * aligns even when the event happened while no revoked-listener was
         * registered (app backgrounded / ViewModel recreated). Cleared when a
         * new session starts (startVPN()).
         */
        @Volatile
        @JvmStatic
        var wasRevoked: Boolean = false
            private set

        /**
         * Why the slot was lost, kept because the event that carries the reason
         * may reach no listener at all: a boot connection is refused with no
         * screen to report to, and the reason is what the user needs then.
         * Cleared with [wasRevoked] when a new session starts.
         */
        @Volatile
        @JvmStatic
        var lastRevokeReason: String? = null
            private set

        // Push channel for the "VPN slot lost" event so a foreground UI
        // updates immediately instead of waiting for the next resume-time
        // syncVpnServiceState() call. The reason is the message to show: the
        // slot can be lost to an ordinary VPN app or to the device's always-on
        // one, and those need different words.
        @Volatile
        @JvmStatic
        private var revokedListener: ((String) -> Unit)? = null

        fun setRevokedListener(listener: ((String) -> Unit)?) {
            revokedListener = listener
        }

        // Internal rather than private: the establish that refuses to steal
        // the slot reports it from TunEstablish, and the report is the same
        // event either way.
        internal fun notifyVpnRevoked(reason: String) {
            // Kept whether or not anyone is listening: a boot connection is
            // refused with no screen to report to, and the reason is what the
            // user is told when the app is opened afterwards.
            lastRevokeReason = reason
            revokedListener?.invoke(reason)
        }

        /**
         * Push channel for "the session is up but not actually working": a network switch the
         * tunnel did not survive, or one it survived while the backend stayed unreachable.
         *
         * Both used to be invisible — `isServiceActive` stayed true, so the UI kept showing a
         * healthy "Connected" over a dead data plane. The listener lets a foreground UI drop
         * back to the error state instead of lying.
         */
        @Volatile
        @JvmStatic
        private var brokenListener: ((String) -> Unit)? = null

        fun setBrokenListener(listener: ((String) -> Unit)?) {
            brokenListener = listener
        }

        /**
         * Reports a session that can no longer carry traffic. [reason] is the
         * message to show; the service decides whether the session is merely
         * degraded (the tunnel is up, the backend is not) or over.
         */
        private fun notifyBroken(reason: String) {
            brokenListener?.invoke(reason)
        }

        /**
         * Push channel for the outcome of a start.
         *
         * The service is the only side that knows it: the request to start
         * says nothing about the tunnel — `startForegroundService()` returns
         * as soon as the request is delivered — and only the establish says
         * whether the tunnel is up. The listener is told so once per start:
         * true when the tunnel is up, false when the start failed.
         *
         * Registered for the duration of one start, so a start nobody is
         * waiting for is reported to nobody.
         */
        @Volatile
        @JvmStatic
        private var startOutcomeListener: ((Boolean) -> Unit)? = null

        fun setStartOutcomeListener(listener: ((Boolean) -> Unit)?) {
            startOutcomeListener = listener
        }

        /**
         * Removes the listener, unless it is already another one.
         *
         * The check is what keeps a caller that has given up from removing
         * the listener of a start that came after it.
         */
        fun clearStartOutcomeListener(listener: (Boolean) -> Unit) {
            if (startOutcomeListener === listener) startOutcomeListener = null
        }

        /**
         * Reports the outcome of the start that is running.
         */
        // Internal rather than private: the establish reports the tunnel
        // being up from TunEstablish, and the report is the same event either
        // way.
        internal fun notifyStartOutcome(up: Boolean) {
            startOutcomeListener?.invoke(up)
        }
    }
}
