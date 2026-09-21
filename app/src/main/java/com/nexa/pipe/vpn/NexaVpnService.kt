package com.nexa.pipe.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.nexa.pipe.IrohProxy
import com.nexa.pipe.MainActivity
import com.nexa.pipe.R
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout

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
 */
class NexaVpnService : VpnService() {
    private val TAG = "NexaVpnService"
    private var vpnInterface: ParcelFileDescriptor? = null
    // @Volatile: written from the main thread (onStartCommand/onRevoke) and
    // read from IO coroutines (reconnect logic).
    @Volatile private var isRunning = false
    private var allowedDomains = mutableSetOf<String>()

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var underlyingNetwork: Network? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var isUserStarted = false

    // Reconnect on network switch: keeps the reconnect job and its mutex so
    // that concurrent native calls cannot race.
    private var reconnectJob: Job? = null
    @Volatile private var reconnectInProgress = false
    // Whether the TUN proxy has started successfully. A network switch only
    // triggers a reconnect when this is true, so the initial VPN setup cannot
    // trigger one by accident.
    @Volatile private var tunProxyStarted = false
    private val reconnectMutex = Any()

    // TUN subnet configuration (must match the virtual IP constants in Rust
    // tun_proxy.rs)
    private val virtualDNSIP = "10.0.1.2"
    private val tunInterfaceIP = "10.0.1.1"
    // TUN interface MTU. Must match TUN_MTU in crates/nexapipe-client/src/tun_proxy.rs and
    // ui-desktop/src-tauri/src/proxy/tun_proxy.rs. 1400 keeps one inner IP packet inside a
    // single QUIC datagram (~1435 usable bytes after the short header + AEAD tag); at 1500
    // every inner segment was split across two datagrams, roughly doubling the packet count
    // and AEAD cost.
    private val tunMtu = 1400
    // virtualProxyIP (10.0.1.3) is hardcoded on the Rust side and not needed
    // here: DNS responses are built by Rust, and TCP traffic is split by Rust
    // according to local_addr.ip().
    //
    // Note: do not hijack the system captive-portal check domains
    // (connectivitycheck.gstatic.com and friends) to a private IP. Android's
    // NetworkMonitor treats "the check domain resolves to a private IP" as "no
    // internet", which puts an exclamation mark on the Wi-Fi icon in the status
    // bar. Let them use real DNS over the physical network instead.

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        registerNetworkCallback()
        refreshUnderlyingNetwork("service created")
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVPN()
        unregisterNetworkCallback()
    }

    fun startVPN(domains: Set<String>) {
        this.allowedDomains = domains.toMutableSet()
        isUserStarted = true
        // A new session begins: clear the stale "revoked" marker from a
        // previous session (consumed by VpnViewModel.syncVpnServiceState()).
        wasRevoked = false

        val prepareIntent = prepare(this)
        if (prepareIntent != null) {
            Log.d(TAG, "VPN permission not granted")
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

        refreshUnderlyingNetwork("VPN start requested")
        establishVPN()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent != null) {
            when (intent.action) {
                ACTION_START -> {
                    val domains = intent.getStringArrayListExtra(EXTRA_DOMAINS) ?: emptyList()
                    startVPN(domains.toSet())
                }
                ACTION_STOP -> {
                    stopVPN()
                }
            }
        }
        return START_STICKY
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
        wasRevoked = true
        reconnectJob?.cancel()
        reconnectJob = null

        // nativeStopTunProxy joins the smoltcp tasks (up to ~500ms each) —
        // keep the main thread free.
        serviceScope.launch {
            stopVPN()
            stopSelf()
            notifyVpnRevoked()
        }
    }

    fun stopVPN() {
        isRunning = false
        isUserStarted = false
        tunProxyStarted = false
        isServiceActive = false
        // Cancel an in-flight reconnect so it cannot race with this manual
        // disconnect.
        reconnectJob?.cancel()
        reconnectJob = null

        // Stop the TUN proxy first (abort the smoltcp task + close the
        // duplicated fd -> the VPN is torn down automatically).
        // Must run before touching vpnInterface, because fd ownership has been
        // transferred to Rust.
        try {
            IrohProxy.nativeStopTunProxy()
        } catch (e: Exception) {
            Log.e(TAG, "nativeStopTunProxy failed: ${e.message}")
        }

        // vpnInterface already went through detachFd, so the fd is owned by
        // Rust and must not be closed here. Just drop the reference.
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_REMOVE)
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
            if (!establishVpnInternal()) {
                Log.d(TAG, "VPN establishment failed")
                isRunning = false
                shutdownService()
            }
        }
    }

    /**
     * Establishes the VPN and the TUN proxy. Shared by the initial setup and
     * by the reconnect after a network switch.
     * @return true on success; false on failure (the caller then handles the
     *         isRunning state).
     */
    private suspend fun establishVpnInternal(): Boolean {
        // Mutual-exclusion guard: Android allows only one active VpnService
        // TUN per user. If a foreign VPN app (e.g. Clash) currently owns the
        // slot, establish() would silently revoke it — refuse instead of
        // stealing it back. This single choke point covers both the initial
        // setup and the reconnect path (rebuildTunnel), including the race
        // where the other VPN started while our session flags were still up.
        if (isForeignVpnActive()) {
            Log.e(TAG, "Another VPN app is active; refusing to establish our VPN (would revoke it)")
            wasRevoked = true
            notifyVpnRevoked()
            return false
        }

        return try {
            val builder = Builder()
                .setSession("Nexa")
                // Must match TUN_MTU in crates/nexapipe-client/src/tun_proxy.rs.
                .setMtu(tunMtu)
                .addAddress(tunInterfaceIP, 24)
                // Route only the virtual IP range (10.0.1.0/24):
                // DNS queries (to 10.0.1.2:53) go through the TUN,
                // TCP proxy traffic (to 10.0.1.3:80/443) goes through the TUN.
                .addRoute("10.0.1.0", 24)
                .addDnsServer(virtualDNSIP)
                // Exclude this app's own traffic so proxy connections use the
                // physical network.
                .addDisallowedApplication(packageName)

            val selectedNetwork = underlyingNetwork
            if (selectedNetwork != null) {
                builder.setUnderlyingNetworks(arrayOf(selectedNetwork))
                Log.d(
                    TAG,
                    "Set underlying network: $selectedNetwork " +
                        "(${UnderlyingNetworkSelector.transportName(connectivityManager!!, selectedNetwork)})"
                )
            } else {
                Log.d(TAG, "No underlying network from callback, skipping setUnderlyingNetworks")
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.d(TAG, "Failed to establish VPN")
                return false
            }

            // Transfer TUN fd ownership to Rust (the PFD is no longer usable
            // after detachFd).
            val fd = vpnInterface!!.detachFd()
            vpnInterface = null  // the PFD is invalid now, drop the reference

            val proxyDomainsStr = allowedDomains.joinToString(",")

            // TunProxy snapshots CUSTOM_DNS_SERVERS when it starts.  Refresh it
            // from the selected egress network so Wi-Fi and cellular DNS are
            // never mixed after a network switch.
            val dnsServers = UnderlyingNetworkSelector
                .dnsServers(connectivityManager!!, selectedNetwork)
            if (dnsServers.isNotEmpty()) {
                val dnsServersStr = dnsServers.joinToString(",")
                IrohProxy.nativeSetDnsServers(dnsServersStr)
                Log.d(TAG, "Set TUN DNS from ${UnderlyingNetworkSelector.transportName(connectivityManager!!, selectedNetwork)}: $dnsServersStr")
            } else {
                Log.w(TAG, "No DNS servers on selected underlying network: $selectedNetwork")
            }

            Log.d(TAG, "Starting TUN proxy: fd=$fd, " +
                    "proxyDomains=${allowedDomains.size} items")

            val result = IrohProxy.nativeStartTunProxy(
                fd, proxyDomainsStr
            )

            if (result != 0) {
                Log.e(TAG, "Failed to start TUN proxy: $result, closing fd")
                // When nativeStartTunProxy fails Rust never took ownership of
                // the fd, so close it here.
                try {
                    ParcelFileDescriptor.adoptFd(fd).close()
                } catch (_: Exception) {}
                tunProxyStarted = false
                return false
            }

            tunProxyStarted = true
            isServiceActive = true
            Log.d(TAG, "VPN + TUN proxy established successfully (routing 10.0.1.0/24)")
            createNotificationChannel()
            startForeground(1, createNotification())
            true
        } catch (e: Exception) {
            Log.e(TAG, "VPN establishment failed: ${e.message}", e)
            tunProxyStarted = false
            false
        }
    }

    /**
     * Whether a foreign VPN app (e.g. Clash) currently owns the platform VPN
     * slot. Our own session is exempt via isServiceActive: during a reconnect
     * the old TUN is torn down before the new one is established, and
     * isServiceActive stays true throughout, so our own rebuilding session is
     * never misdetected as a foreign VPN.
     */
    private fun isForeignVpnActive(): Boolean {
        if (isServiceActive) return false
        val cm = connectivityManager ?: return false
        return UnderlyingNetworkSelector.hasActiveVpnNetwork(cm)
    }

    /**
     * Stops the service cleanly after a failed establish.
     *
     * The service is started with startForegroundService(), which obligates it
     * to call startForeground() once; skipping that throws
     * ForegroundServiceDidNotStartInTimeException. If the VPN was never
     * established the brief startForeground here satisfies the obligation, and
     * the notification is removed immediately afterwards.
     */
    private fun shutdownService() {
        runCatching {
            createNotificationChannel()
            startForeground(1, createNotification())
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ============================================================
    // Network callbacks - track the underlyingNetwork (Wi-Fi / cellular)
    // ============================================================

    private fun registerNetworkCallback() {
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
    private fun refreshUnderlyingNetwork(reason: String) {
        val cm = connectivityManager ?: return
        val selected = UnderlyingNetworkSelector.selectPreferredNetwork(cm)
        val previous = underlyingNetwork
        if (selected == previous) return

        underlyingNetwork = selected
        val selectedDescription = "${UnderlyingNetworkSelector.transportName(cm, selected)} $selected"
        Log.d(TAG, "Underlying network changed ($reason): $previous -> $selectedDescription")

        // The initial choice is consumed by establishVpnInternal.  Once TUN is
        // running, a different preferred network needs a new VPN interface so
        // Android updates both the underlying network and the TUN DNS snapshot.
        onUnderlyingNetworkChanged("$reason; selected $selectedDescription")
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            connectivityManager?.unregisterNetworkCallback(it)
        }
    }

    // ============================================================
    // Network-switch reconnect - rebuild the whole tunnel when the
    // underlying network (Wi-Fi / cellular) changes
    // ============================================================

    private fun onUnderlyingNetworkChanged(reason: String) {
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

    private suspend fun reconnectTunnel() {
        if (!isUserStarted || !isRunning) return
        synchronized(reconnectMutex) {
            if (reconnectInProgress) return
            reconnectInProgress = true
        }
        try {
            // The switch is not finished yet (e.g. airplane mode was turned
            // on): wait for the next network event.
            if (underlyingNetwork == null) {
                Log.d(TAG, "Reconnect: no underlying network yet, skipping")
                return
            }
            if (!IrohProxy.isNativeLoaded()) {
                Log.e(TAG, "Reconnect: native library not loaded")
                return
            }
            Log.d(TAG, "Reconnect: rebuilding tunnel on underlying network $underlyingNetwork")

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
            // Keep the service running: request-level retries on the Rust side
            // act as a safety net, and the next network change triggers another
            // reconnect.
        } finally {
            synchronized(reconnectMutex) { reconnectInProgress = false }
        }
    }

    /**
     * Rebuilds the tunnel: stop the old TUN proxy -> re-establish the VPN and
     * the TUN proxy on the new underlying network.
     *
     * The iroh endpoint and the local proxy are left untouched: iroh handles
     * path migration and relay reconnection itself, and the connection pool
     * opens new backend connections on demand. Do not destroy and recreate the
     * endpoint - that opens an outage window of seconds to tens of seconds
     * (nativeStartIroh can block for 30s on a weak network) and may leave the
     * tunnel unusable if the rebuild fails.
     */
    private suspend fun rebuildTunnel() {
        // 1. Stop the old TUN proxy (closes the duplicated fd -> the old VPN is
        //    torn down automatically).
        runCatching { IrohProxy.nativeStopTunProxy() }
            .onFailure { Log.e(TAG, "Reconnect: nativeStopTunProxy failed: ${it.message}") }
        tunProxyStarted = false

        // 2. Re-establish the VPN (new TUN fd + new underlying network) and
        //    start the TUN proxy.
        if (!establishVpnInternal()) {
            throw Exception("Reconnect: failed to re-establish VPN/TUN proxy")
        }
    }

    // ============================================================
    // Notifications
    // ============================================================

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Nexa", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Nexa Service"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("Nexa")
            .setContentText("Connected")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "NexaVPN"
        const val ACTION_START = "com.nexa.pipe.vpn.ACTION_START"
        const val ACTION_STOP = "com.nexa.pipe.vpn.ACTION_STOP"
        const val EXTRA_DOMAINS = "com.nexa.pipe.vpn.EXTRA_DOMAINS"

        // Network-switch reconnect parameters
        private const val RECONNECT_DEBOUNCE_MS = 1_500L
        private const val MAX_RECONNECT_ATTEMPTS = 3
        private const val RECONNECT_ATTEMPT_TIMEOUT_MS = 60_000L
        private const val RECONNECT_BACKOFF_MS = 2_000L

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

        // Push channel for the "VPN slot lost" event so a foreground UI
        // updates immediately instead of waiting for the next resume-time
        // syncVpnServiceState() call.
        @Volatile
        @JvmStatic
        private var revokedListener: (() -> Unit)? = null

        fun setRevokedListener(listener: (() -> Unit)?) {
            revokedListener = listener
        }

        private fun notifyVpnRevoked() {
            revokedListener?.invoke()
        }
    }
}
