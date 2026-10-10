package com.nexa.pipe.ui

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nexa.pipe.IrohProxy
import com.nexa.pipe.NodeTraffic
import com.nexa.pipe.PermissionManager
import com.nexa.pipe.R
import com.nexa.pipe.parseNodeTraffic
import com.nexa.pipe.SecretStore
import com.nexa.pipe.SettingsManager
import com.nexa.pipe.locale.AppStrings
import com.nexa.pipe.vpn.NexaVpnService
import com.nexa.pipe.vpn.UnderlyingNetworkSelector
import com.nexa.pipe.vpn.VpnSlot
import com.nexa.pipe.vpn.VpnTakeoverChoice
import com.nexa.pipe.vpn.VpnTakeoverDecision
import com.nexa.pipe.vpn.VpnTakeoverPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress

import kotlinx.serialization.Serializable

/**
 * The 2FA credentials of one endpoint.
 *
 * They belong to the endpoint, not to the app: every server keeps its own
 * `[auth].clients` table, so a second server either needs its own pair or has
 * to be handed the first one's secret. [secret] is only ever persisted in the
 * prefs file that backup excludes — see `SettingsManager`.
 */
@Serializable
data class NodeTwoFactor(
    val enabled: Boolean = true,
    val clientId: String = "",
    val secret: String = "",
    val algorithm: String = "sha1", // "sha1", "sha256", "sha512"
    /**
     * The device this credential was issued to, when the server said which.
     *
     * Null or blank means it is the client's shared secret rather than one
     * device's — what every pair saved before this existed is, and what the
     * field stays until the endpoint is enrolled under a name. The server
     * cannot revoke one device of a client through a credential nobody owns.
     */
    val device: String? = null
)

/**
 * A one-time enrollment token, in place of credentials.
 *
 * The token is spent by the first connection, which answers with the secret this
 * device then keeps — and rotates the one the server held, so a code that leaked
 * on its way here stops working the moment it is used.
 */
@Serializable
data class NodeEnrollment(
    val clientId: String = "",
    val token: String = ""
)

@Serializable
data class NodeConfig(
    val nodeId: String,
    val domains: List<String> = emptyList(),
    val twoFactor: NodeTwoFactor? = null,
    /**
     * A token to spend instead of presenting credentials. Cleared once the
     * issued secret has landed in [twoFactor], so an endpoint never holds both.
     */
    val enrollment: NodeEnrollment? = null
)

class VpnViewModel : ViewModel() {
    private val TAG = "VpnViewModel"
    private var settingsManager: SettingsManager? = null

    val isVpnRunning = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isIrohStarted = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isConnecting = kotlinx.coroutines.flow.MutableStateFlow(false)
    // Deliberately typed as an immutable List: mutating the published list in
    // place makes MutableStateFlow's equality check always succeed, so no
    // update is ever emitted and the UI never recomposes. Always assign a
    // brand-new list instead.
    val nodes = kotlinx.coroutines.flow.MutableStateFlow<List<NodeConfig>>(emptyList())
    val logMessages = kotlinx.coroutines.flow.MutableStateFlow<List<String>>(emptyList())
    val errorMessage = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)
    val connectionStatusText = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)
    val vpnPermissionGranted = kotlinx.coroutines.flow.MutableStateFlow(false)
    val notificationPermissionGranted = kotlinx.coroutines.flow.MutableStateFlow(false)

    // Relay configuration. There is deliberately no "force relay" switch: iroh 1.0.1 exposes
    // no stable way to stop it promoting a connection to a direct path, so a switch that
    // claimed to would be a lie.
    val relayMode = kotlinx.coroutines.flow.MutableStateFlow("pinned") // "pinned", "default", "disabled", "custom"
    val relayUrl = kotlinx.coroutines.flow.MutableStateFlow("")
    // Bearer token for a custom relay that asks for one. Never logged.
    val relayAuthToken = kotlinx.coroutines.flow.MutableStateFlow("")

    /**
     * What this install calls itself when it authenticates.
     *
     * Generated once on the device and then kept: a server can only revoke, or
     * rate-limit, one device of a client if that device has a name of its own,
     * and a name that changed between runs would leave a stale row behind on
     * every single connect. Empty until [loadSettings] has run, which is also
     * what leaves nothing to send on a handshake made before then.
     */
    val deviceId = kotlinx.coroutines.flow.MutableStateFlow("")

    /**
     * Whether the credentials on this device are actually encrypted at rest.
     *
     * Refreshed wherever a credential is written, which is the only moment the
     * answer can change. `Sealed` before anything has been written is honest
     * rather than optimistic: nothing is stored in plaintext yet.
     */
    val credentialProtection =
        kotlinx.coroutines.flow.MutableStateFlow(SecretStore.Protection.Sealed)

    /**
     * Set when a credential is about to be written to a device that cannot
     * protect it. The write waits for the answer: nothing reaches storage
     * while this is true.
     */
    val plaintextConsentPending = kotlinx.coroutines.flow.MutableStateFlow(false)

    /**
     * Whether storing credentials in the clear has already been agreed to on
     * this device. Asked once rather than per credential — a device that cannot
     * seal one cannot seal the next either, and asking again on every write
     * would teach the user to stop reading the question.
     */
    private var plaintextAccepted = false

    /**
     * What to do when another VPN app owns the slot, as the user last decided.
     *
     * [VpnTakeoverChoice.Ask] until one is made, and resettable from the
     * settings: a remembered Cancel is a decision to never use Nexa alongside
     * another VPN, which is not something the user should have to uninstall the
     * app to revisit.
     */
    val vpnTakeoverChoice =
        kotlinx.coroutines.flow.MutableStateFlow(VpnTakeoverChoice.Ask)

    /**
     * Runtime link type per backend (endpoint ID -> direct/relay), reported by iroh and
     * refreshed while the tunnel is up. Empty whenever nothing is connected, which is what
     * keeps the UI from drawing a stale icon after a disconnect.
     */
    val linkKinds = kotlinx.coroutines.flow.MutableStateFlow<Map<String, LinkKind>>(emptyMap())

    /**
     * What each backend has carried, keyed by endpoint ID: cumulative bytes since the proxy
     * was started, plus the flows open to it right now. Refreshed alongside [linkKinds], and
     * empty whenever nothing is connected, for the same reason.
     *
     * A node that is absent has carried nothing — the native side leaves those out instead of
     * reporting zeroes — so a caller showing per-node figures has to say "nothing yet" rather
     * than leave the gap looking like a backend that is down.
     */
    val traffic = kotlinx.coroutines.flow.MutableStateFlow<Map<String, NodeTraffic>>(emptyMap())

    /**
     * What every backend has carried together: [traffic] summed across the map.
     *
     * Derived, not read a second time — the native side is not asked for anything it does not
     * already report, and there is no way for the row on screen to disagree with the per-node
     * figures beside it.
     *
     * `null` while the map is empty, which is the same distinction [traffic] makes per node:
     * nothing has been counted yet, which is not the same as a total that happens to be zero.
     * A screen that drew `0 B` before the first byte would look like a tunnel that works and
     * carries nothing.
     */
    val totalTraffic: StateFlow<NodeTraffic?> =
        traffic
            .map { totals ->
                if (totals.isEmpty()) {
                    null
                } else {
                    NodeTraffic(
                        sent = totals.values.sumOf { it.sent },
                        received = totals.values.sumOf { it.received },
                        active = totals.values.sumOf { it.active },
                    )
                }
            }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    // 2FA lives on the endpoint now (`NodeConfig.twoFactor`): one server, one
    // pair of credentials. There is no app-wide setting left to publish here.

    // Serialize connect/disconnect so concurrent native calls cannot race.
    private val connectionMutex = Mutex()
    // Refreshes `linkKinds` while the tunnel is up: a connection can be upgraded from relay to
    // direct at any moment, so the icon has to be re-read rather than sampled once.
    private var linkPollJob: Job? = null
    // Keeps a handle on the connect coroutine so disconnect can cancel it
    // (JNI cannot be interrupted, but the next suspension point throws
    // CancellationException).
    private var connectJob: Job? = null

    init {
        // Push channel from NexaVpnService: our VPN was revoked (or its
        // establishment was refused) because another VPN app (e.g. Clash)
        // took over the single VPN slot Android allows. Update the UI
        // immediately instead of waiting for the next syncVpnServiceState().
        NexaVpnService.setRevokedListener { reason ->
            viewModelScope.launch {
                if (isVpnRunning.value) {
                    // The counters belong to the session that just ended, and the poll that
                    // reads them belongs to it too: leaving either running would keep a total
                    // on screen under "Disconnected", which reads as a tunnel that is up and
                    // carrying bytes. See `refreshTraffic` — no total outlives its session.
                    stopLinkPolling()
                    isVpnRunning.value = false
                    errorMessage.value = reason
                    addLog("Tunnel revoked: $reason")
                }
            }
        }
        // The service telling us the session stopped working (a network switch it could not
        // recover from, or a backend it cannot reach on the new network). Reported while this
        // UI was in the background or not alive at all, so it is the only way the status card
        // stops claiming "Connected" over a tunnel that carries nothing.
        NexaVpnService.setBrokenListener { reason ->
            viewModelScope.launch {
                // The service clears `isServiceActive` when it tore the session down, and leaves
                // it set when the tunnel survived but nothing behind it answers — so this is how
                // "the session is over" is told apart from "the session is degraded". Only the
                // former drops back to Disconnected; reporting the latter as a disconnect would
                // send the user to reconnect a tunnel that is still up.
                if (!NexaVpnService.isServiceActive) {
                    stopLinkPolling()
                    isVpnRunning.value = false
                    isIrohStarted.value = false
                    addLog("Tunnel stopped working: $reason")
                } else {
                    addLog("Tunnel degraded: $reason")
                }
                errorMessage.value = reason
            }
        }
    }

    override fun onCleared() {
        NexaVpnService.setRevokedListener(null)
        NexaVpnService.setBrokenListener(null)
        stopLinkPolling()
        super.onCleared()
    }

    /**
     * Re-reads what the UI shows after it comes back to the foreground.
     *
     * Everything a session reports can change while this screen is not visible: the service
     * rebuilds the tunnel on a network switch, and it may give up and tear the session down.
     * Without a re-read the main page keeps showing whatever it last knew — an "old state"
     * that no longer matches the tunnel.
     */
    fun onForeground() {
        syncVpnServiceState()
        // A session that survived in the service also has to be reported again: this ViewModel
        // may have been created after connect() ran, in which case nothing is polling yet.
        if (isVpnRunning.value) startLinkPolling()
    }

    /**
     * Reads the current link type of every backend from the native side.
     *
     * Best-effort: a failed read leaves the last known values in place rather than emptying the
     * map, so a transient JNI hiccup does not make every icon disappear.
     *
     * Deliberately **not** gated on [isIrohStarted]. That flag lives in this ViewModel, so it is
     * false again as soon as the UI is recreated — which is exactly what a background switch or a
     * process restore does while the tunnel keeps running in the service. Gating on it emptied
     * the map for the rest of the session: the status card said "Connected" while the connection
     * type was never shown again. Whether anything is started is the native side's answer to
     * give, and it says so by returning null.
     */
    fun refreshLinkKinds() {
        if (!IrohProxy.isNativeLoaded()) {
            if (linkKinds.value.isNotEmpty()) linkKinds.value = emptyMap()
            return
        }
        val raw = try {
            IrohProxy.nativeLinkKinds()
        } catch (e: Exception) {
            addLog("Could not read link types: ${e.message}")
            return
        }
        if (raw == null) {
            // Nothing has been started, or the endpoint group is gone: no link to report.
            if (linkKinds.value.isNotEmpty()) linkKinds.value = emptyMap()
            return
        }
        linkKinds.value = parseLinkKinds(raw)
    }

    /**
     * Reads what each backend has carried from the native side.
     *
     * Best-effort, as [refreshLinkKinds] is: a failed read leaves the last known values in
     * place rather than zeroing every row. A null answer means nothing has been started — or
     * the endpoint group is gone — and clears the map, so no total survives the session it
     * was counted in.
     *
     * The read and the decoding stay on whichever dispatcher the caller was on — the polling
     * loop runs on [Dispatchers.IO], and a JNI call has no business on the main thread — but
     * the map itself is UI state, so it is published on [Dispatchers.Main]. Writing it from
     * the polling thread would work, because `MutableStateFlow.value` is thread-safe, and
     * would still be the wrong place to write it from.
     */
    suspend fun refreshTraffic() {
        if (!IrohProxy.isNativeLoaded()) {
            withContext(Dispatchers.Main) { traffic.value = emptyMap() }
            return
        }
        val raw = try {
            IrohProxy.nativeTraffic()
        } catch (e: Exception) {
            addLog("Could not read traffic counters: ${e.message}")
            return
        }
        val totals = if (raw == null) emptyMap() else parseNodeTraffic(raw)
        withContext(Dispatchers.Main) { traffic.value = totals }
    }

    /** Decodes `id=direct;id2=relay` — the format the native side writes. */
    private fun parseLinkKinds(raw: String): Map<String, LinkKind> {
        val parsed = linkedMapOf<String, LinkKind>()
        for (entry in raw.split(";")) {
            val separator = entry.indexOf('=')
            if (separator <= 0) continue
            parsed[entry.substring(0, separator)] = when (entry.substring(separator + 1)) {
                "direct" -> LinkKind.DIRECT
                "relay" -> LinkKind.RELAY
                else -> LinkKind.UNKNOWN
            }
        }
        return parsed
    }

    /**
     * Starts re-reading what the tunnel reports per backend — the link type and what each one
     * has carried; no-op when a poll is already running.
     *
     * Public because `connect()` is not the only way a session comes to exist: the service
     * outlives a UI that was recreated in the background, and the ViewModel that wakes up with
     * it has to pick the reporting back up. See [onForeground].
     */
    fun startLinkPolling() {
        if (linkPollJob?.isActive == true) return
        linkPollJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                refreshLinkKinds()
                refreshTraffic()
                delay(LINK_POLL_INTERVAL_MS)
            }
        }
    }

    private fun stopLinkPolling() {
        linkPollJob?.cancel()
        linkPollJob = null
        linkKinds.value = emptyMap()
        traffic.value = emptyMap()
    }

    companion object {
        // Timeout and retry parameters for a single connect attempt. iroh bind
        // can take up to 30s on a weak network, so the budget is generous.
        private const val MAX_CONNECT_ATTEMPTS = 3
        private const val ATTEMPT_TIMEOUT_MS = 60_000L
        private const val DISCONNECT_MUTEX_TIMEOUT_MS = 70_000L
        private val BACKOFF_MS = longArrayOf(0, 1_000, 2_000)

        // `error_vpn_taken_over` is what is shown when another proxy app (e.g.
        // Clash) owns the single tunnel slot Android allows per user.

        // Upper bound on the in-memory log buffer.
        private const val MAX_LOG_LINES = 100

        // How often the link type of each backend is re-read while connected. Short enough to
        // notice a relay -> direct upgrade without hammering the native side.
        private const val LINK_POLL_INTERVAL_MS = 5_000L
    }

    fun initSettings(context: android.content.Context) {
        if (settingsManager == null) {
            settingsManager = SettingsManager(context)
        }
    }

    fun loadSettings() {
        settingsManager?.let { manager ->
            val loadedNodes = manager.loadNodes()
            nodes.value = loadedNodes
            relayMode.value = manager.loadRelayMode()
            relayUrl.value = manager.loadRelayUrl()
            relayAuthToken.value = manager.loadRelayAuthToken()
            vpnTakeoverChoice.value = manager.loadVpnTakeoverChoice()
            deviceId.value = manager.deviceId()
            // Read after the load, because building a SettingsManager runs the
            // migration that re-seals whatever older versions left in plaintext —
            // on a device with a broken keystore that is the write that fails.
            credentialProtection.value = manager.credentialProtection()
            addLog("Settings loaded: ${loadedNodes.size} nodes, relay=${relayMode.value}")
        }
    }

    private fun saveSettings() {
        val manager = settingsManager ?: return
        if (needsPlaintextConsent(manager)) {
            plaintextConsentPending.value = true
            return
        }
        manager.saveNodes(nodes.value)
        manager.saveRelayConfig(relayMode.value, relayUrl.value, relayAuthToken.value)
        credentialProtection.value = manager.credentialProtection()
    }

    /**
     * Whether writing now would put a credential in the clear with nobody
     * having agreed to it.
     *
     * Only a write that actually carries a credential counts: adding an
     * endpoint, renaming one or switching relay mode stores nothing that needs
     * protecting, and asking about those would make the question meaningless
     * long before it was needed.
     */
    private fun needsPlaintextConsent(manager: SettingsManager): Boolean {
        if (plaintextAccepted) return false
        if (manager.canProtectCredentials()) return false
        return nodes.value.any {
            !it.enrollment?.token.isNullOrBlank() || !it.twoFactor?.secret.isNullOrBlank()
        } || relayAuthToken.value.isNotBlank()
    }

    /**
     * Agrees that credentials may be stored unencrypted. The write that was
     * waiting goes through, and later ones no longer ask.
     */
    fun acceptPlaintextCredentials() {
        plaintextAccepted = true
        plaintextConsentPending.value = false
        saveSettings()
    }

    /**
     * Declines. The waiting write is dropped rather than deferred: a credential
     * nobody agreed to store stays out of storage. The endpoint it belonged to
     * is left as the user last saw it, still unsaved.
     */
    fun declinePlaintextCredentials() {
        plaintextConsentPending.value = false
        addLog("Credential not stored: this device cannot encrypt it")
    }

    fun updateRelayConfig(mode: String, url: String, authToken: String = relayAuthToken.value) {
        relayMode.value = mode
        // A URL only means anything in "custom"; keeping one around after a switch to
        // another mode would leave a stale field behind.
        relayUrl.value = if (mode == "custom") url else ""
        relayAuthToken.value = if (mode == "custom") authToken else ""
        saveSettings()
        addLog("Relay config updated: mode=${mode}, url=${relayUrl.value}")
    }

    /**
     * Sets or clears the enrollment token of one endpoint.
     *
     * A token replaces the credentials rather than sitting beside them: an
     * endpoint holding a token has not been issued any yet. Cleared as soon as
     * the issued secret lands in [twoFactor].
     */
    fun updateNodeEnrollment(nodeId: String, enrollment: NodeEnrollment?) {
        val index = nodes.value.indexOfFirst { it.nodeId == nodeId }
        if (index < 0) return
        val updated = nodes.value.toMutableList()
        updated[index] = nodes.value[index].copy(enrollment = enrollment)
        nodes.value = updated
        val manager = settingsManager
        // An enrollment token is a credential, and this is the one write that
        // does not go through `saveSettings`, so it asks here or not at all.
        if (manager != null && needsPlaintextConsent(manager)) {
            plaintextConsentPending.value = true
            return
        }
        manager?.saveNodes(nodes.value)
        // A token is a credential, so this write is one of the two places the
        // answer can change without going through `saveSettings`.
        manager?.let { credentialProtection.value = it.credentialProtection() }
        addLog("Enrollment updated for " + nodeId.take(8) + ": " + (enrollment?.clientId ?: "none"))
    }

    /**
     * Stores the credential the server issued for an enrollment token, if the
     * connect that just happened spent one.
     *
     * This is the only moment the secret exists on this device: the token is
     * gone, so without this the endpoint is left with an invite the server has
     * already forgotten and cannot enroll a second time.
     */
    private fun collectIssuedCredential() {
        val encoded = IrohProxy.nativeTakeIssuedCredential() ?: return
        val parts = encoded.split("\n")
        if (parts.size < 3) {
            addLog("Enrollment answered with a credential this app cannot read")
            return
        }
        val clientId = parts[0]
        val secret = parts[1]
        val algorithm = parts[2]
        // A fourth line names the device the server enrolled; it answers with
        // three when it does not name devices at all. Left null rather than
        // blank, because what it records is "no name was given" — the state
        // that leaves this pair indistinguishable from the client's shared
        // secret, and the one the page offers to re-enroll out of.
        val device = parts.getOrNull(3)?.takeIf { it.isNotBlank() }
        val node = nodes.value.firstOrNull { it.enrollment?.clientId == clientId }
            ?: nodes.value.firstOrNull { it.enrollment != null }
        if (node == null) {
            // Dropping a secret is the safe outcome, but doing it silently is
            // not: the endpoint will never connect and nothing will say why.
            addLog("A credential was issued but no endpoint is enrolling")
            return
        }
        updateNodeTwoFactor(
            node.nodeId,
            NodeTwoFactor(
                enabled = true,
                clientId = clientId,
                secret = secret,
                algorithm = algorithm,
                device = device
            )
        )
        updateNodeEnrollment(node.nodeId, null)
        addLog("Enrolled: the token is spent and the issued secret is saved")
    }

    /**
     * Replaces the 2FA credentials of one endpoint.
     *
     * A null [twoFactor] means this endpoint has none, which also drops the
     * saved secret rather than leaving it behind for whatever endpoint next
     * reuses the ID.
     *
     * No client id in the log: debug builds expose Log.d, and the ID is half
     * of the 2FA credential pair.
     */
    fun updateNodeTwoFactor(nodeId: String, twoFactor: NodeTwoFactor?) {
        val index = nodes.value.indexOfFirst { it.nodeId == nodeId }
        if (index == -1) return
        val updated = nodes.value.toMutableList().apply {
            set(index, this[index].copy(twoFactor = twoFactor))
        }
        nodes.value = updated
        saveSettings()
        addLog(
            "2FA updated for ${nodeId.take(8)}: enabled=${twoFactor?.enabled ?: false}, " +
                "algorithm=${twoFactor?.algorithm ?: "-"}"
        )
    }

    fun addLog(message: String) {
        Log.d(TAG, message)
        viewModelScope.launch {
            // Publish a brand-new list instead of mutating the current one in
            // place: MutableStateFlow compares the new value with the old one
            // using equals(), and a List compares structurally, so an in-place
            // mutation followed by assigning a copy of it is a no-op and the
            // collectors (the Compose UI) never see a change.
            val updated = logMessages.value.toMutableList().apply { add(message) }
            if (updated.size > MAX_LOG_LINES) {
                // removeAt(0), not removeFirst(): the latter resolves to
                // java.util.List#removeFirst, which only exists from API 35
                // (this app still runs on API 26).
                updated.removeAt(0)
            }
            logMessages.value = updated
        }
    }

    fun startIroh() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                ensureIrohStarted()
            } catch (e: Exception) {
                addLog("Error starting iroh: ${e.message}")
                errorMessage.value = e.message ?: AppStrings.get(R.string.error_unknown)
            }
        }
    }

    /**
     * Starts the iroh endpoint if it is not up yet. nativeStartIroh already has
     * a 30s timeout on the Rust side. Throwing means failure; the caller
     * decides whether to retry.
     */
    private suspend fun ensureIrohStarted() {
        if (isIrohStarted.value) return
        addLog("Starting iroh first...")
        val id = IrohProxy.nativeStartIroh()
        if (id != null) {
            isIrohStarted.value = true
            addLog("Iroh started: $id")
        } else {
            throw Exception(AppStrings.get(R.string.error_start_iroh))
        }
    }

    /**
     * Reads the system DNS server list from ConnectivityManager and returns it
     * as a comma-separated string of IPs.
     *
     * By default iroh fails to read the system DNS on Android through JNI
     * ("Null pointer in call_method obj argument") and falls back to Google DNS
     * (8.8.8.8/8.8.4.4), which is unreliable behind restrictive networks and
     * leaves the backend unreachable. Instead, Kotlin reads the system DNS
     * straight from ConnectivityManager.getLinkProperties().dnsServers and
     * hands it to nativeSetDnsServers on the Rust side, so iroh uses a custom
     * DnsResolver instead of the broken JNI path.
     *
     * A connected Wi-Fi network is always preferred; cellular is only picked
     * when no usable Wi-Fi exists. Only that network's DNS is read, so Wi-Fi
     * and cellular DNS are never mixed. If the system DNS list is empty (an
     * edge case), fall back to public DNS servers that are widely reachable
     * from mainland China (AliDNS 223.5.5.5, 114DNS 114.114.114.114).
     */
    private fun getSystemDnsServers(context: Context): String {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return ""
        val selectedNetwork = UnderlyingNetworkSelector.selectPreferredNetwork(cm)
        val servers = UnderlyingNetworkSelector
            .dnsServers(cm, selectedNetwork)
            .toCollection(linkedSetOf())
        if (servers.isNotEmpty()) {
            addLog(
                "Using ${UnderlyingNetworkSelector.transportName(cm, selectedNetwork)} DNS: $servers"
            )
        }

        // Last-resort fallback: public DNS servers commonly reachable from
        // mainland China. AliDNS + 114DNS cover the common cases.
        if (servers.isEmpty()) {
            addLog("No system DNS found, falling back to public DNS (223.5.5.5, 114.114.114.114)")
            servers.add("223.5.5.5")
            servers.add("114.114.114.114")
        }

        return servers.joinToString(",")
    }

    /**
     * Pre-resolves the IPs of the iroh infrastructure domains and injects them
     * into the OverrideResolver on the Rust side.
     *
     * The Great Firewall (GFW) drops UDP DNS responses for iroh.link domains,
     * so iroh's internal hickory resolver times out on dns.iroh.link and
     * *.relay.n0.iroh.link. Those domains are pre-resolved here with the system
     * DNS (InetAddress, which may go through DoT / Private DNS and bypass the
     * GFW) and returned as "domain=ip1,ip2;domain2=ip3" for connect() to pass
     * to nativeSetDnsOverride. The OverrideResolver then returns the
     * pre-resolved IPs directly for these domains, so pkarr resolve (HTTPS to
     * dns.iroh.link/pkarr/<z32>) and the relay connection succeed.
     */
    private suspend fun resolveIrohDnsOverrides(): String {
        // DNS origin and default relay servers used by iroh presets::N0.
        val domains = listOf(
            "dns.iroh.link",
            "use1-1.relay.n0.iroh.link",
            "usw1-1.relay.n0.iroh.link",
            "euc1-1.relay.n0.iroh.link",
            "aps1-1.relay.n0.iroh.link",
        )

        val overrides = kotlinx.coroutines.coroutineScope {
            domains.map { domain ->
                async(Dispatchers.IO) {
                    try {
                        val addrs = InetAddress.getAllByName(domain)
                        val ips = addrs.mapNotNull { it.hostAddress }
                        if (ips.isNotEmpty()) {
                            addLog("Resolved iroh domain $domain -> $ips")
                            "$domain=${ips.joinToString(",")}"
                        } else {
                            addLog("Failed to resolve iroh domain $domain (no IPs)")
                            null
                        }
                    } catch (e: Exception) {
                        addLog("Failed to resolve iroh domain $domain: ${e.message}")
                        null
                    }
                }
            }.awaitAll()
        }

        val result = overrides.filterNotNull().joinToString(";")
        addLog("iroh DNS overrides: $result")
        return result
    }

    /**
     * Clears and re-adds the domain -> node mappings. Returns the list of all
     * domains that have to be proxied; throws when there is no mapping at all.
     */
    private suspend fun addDomainMappings(): List<String> {
        IrohProxy.nativeClearNodes()
        var hasDomainMappings = false
        for (node in nodes.value) {
            if (node.domains.isNotEmpty()) {
                for (domain in node.domains) {
                    addLog("Adding domain mapping: '$domain' -> nodeId: ${node.nodeId}")
                    val result = IrohProxy.nativeAddDomainMapping(domain, node.nodeId)
                    if (result != 0) {
                        addLog("Failed to add domain mapping: $domain")
                    } else {
                        hasDomainMappings = true
                    }
                }
            }
        }
        if (!hasDomainMappings) {
            throw Exception(AppStrings.get(R.string.error_no_domain_mappings))
        }
        return nodes.value.flatMap { it.domains }
    }

    /**
     * Builds the endpoint group the tunnel runs on. nativeStopProxy runs first so a
     * previous attempt cannot leave half of one behind.
     *
     * Nothing is bound on loopback: on Android every app shares 127.0.0.1, so a
     * local proxy port hands any of them an already-authenticated tunnel without
     * the user being asked. The tunnel is entered through the TUN fd alone
     * (nativeStartTunProxy), which is what the VPN permission covers.
     *
     * There is nothing to retry here: a failure is either a configuration error
     * (malformed endpoint ID, no domains) or a group that could not be built,
     * and both fail identically on every attempt. Either way the real reason is
     * on the native side, so it leads the message instead of a generic string.
     */
    private suspend fun startEndpointGroup() {
        addLog("Starting endpoint group...")
        IrohProxy.nativeStopProxy()
        val result = IrohProxy.nativeStartProxy()
        if (result != 0) {
            val reason = nativeFailureReason()
            throw Exception(
                AppStrings.get(R.string.error_invalid_proxy_config) +
                    if (reason != null) ": $reason" else ""
            )
        }
        addLog("Endpoint group started")
    }

    /**
     * Human-readable reason for a failed native pre-connect.
     *
     * `nativePreconnect` returns the number of backends that answered. Zero means
     * every configured endpoint ID was unreachable (wrong ID, server offline, or
     * the relay/network blocks it). A negative value means the check itself could
     * not run, e.g. no endpoint group or it exceeded its timeout.
     */
    private fun preconnectFailureReason(result: Int): String {
        val targets = nodes.value
            .map { it.nodeId }
            .ifEmpty { listOf(AppStrings.get(R.string.error_configured_backends)) }
            .joinToString(", ")
        val base = if (result == 0) {
            AppStrings.get(R.string.error_no_backend_reachable, targets)
        } else {
            AppStrings.get(R.string.error_preconnect_failed, result)
        }
        // A server that answered and then refused the connection (2FA, most
        // often) leaves its reason on the native side. Without it a refusal
        // looks exactly like an offline server.
        val detail = nativeFailureReason()
        return if (detail != null) {
            "$base ${AppStrings.get(R.string.error_cause, detail)}"
        } else {
            base
        }
    }

    /** Reason behind the last failed native call, or null when there is none. */
    private fun nativeFailureReason(): String? = try {
        IrohProxy.nativeTakeLastError()
    } catch (e: Exception) {
        addLog("Could not read the native error: ${e.message}")
        null
    }

    /**
     * Null when [id] is a valid endpoint ID, otherwise a message for the user.
     *
     * The check runs through the native parser, so it can never disagree with the
     * connection path. Best-effort by design: when the native library is not loaded the
     * ID is accepted here and the connect-time pre-flight reports the problem instead.
     */
    private fun nodeIdFormatError(id: String): String? {
        if (!IrohProxy.isNativeLoaded()) return null
        val reason = try {
            IrohProxy.nativeValidateNodeId(id)
        } catch (e: Exception) {
            addLog("Node ID validation unavailable: ${e.message}")
            return null
        } ?: return null
        return AppStrings.get(R.string.error_invalid_endpoint_id, id, reason)
    }

    /**
     * Validates every configured node before a connect attempt starts.
     *
     * Without this a malformed ID only surfaced from deep inside the native proxy start:
     * the native layer returns a bare -1 for every failure, the caller read that as
     * "port in use", and the user got "Failed to start proxy on ports 8080..8089" after
     * 10 ports x 3 attempts — a message that named neither the node nor the real cause.
     *
     * @return null when every ID parses, otherwise the reason for the first invalid one.
     */
    private fun validateConfiguredNodeIds(): String? {
        for (node in nodes.value) {
            val error = nodeIdFormatError(node.nodeId)
            if (error != null) return error
        }
        return null
    }

    /**
     * Releases every tunnel resource: nativeDestroy (stops the local proxy and
     * drops the iroh endpoint) + resets the state + stops the VPN service.
     * Key point: isIrohStarted is reset to false and nativeDestroy clears the
     * endpoint, so the next connect runs nativeStartIroh again and builds a
     * brand new tunnel instead of reusing the old endpoint.
     * Note: nativeDestroy is used here rather than nativeStopProxy - the latter
     * only stops the proxy and keeps the endpoint, which is what
     * startProxyWithRetries needs when it rebinds the port.
     */
    private suspend fun releaseAllResources(context: Context) {
        stopLinkPolling()
        try {
            IrohProxy.nativeDestroy()
        } catch (e: Exception) {
            addLog("releaseAllResources: nativeDestroy failed: ${e.message}")
        }
        isIrohStarted.value = false
        try {
            val intent = Intent(context, NexaVpnService::class.java).apply {
                action = NexaVpnService.ACTION_STOP
            }
            context.startService(intent)
        } catch (_: Exception) {}
        isVpnRunning.value = false
    }

    /**
     * Who owns the platform VPN slot, as seen from the UI.
     *
     * Runs off the main thread: both reads go through a binder. Our own session
     * is [VpnSlot.OwnSession] — the set of VPN networks does not say which one
     * is ours, and the service is the only side that can tell, so a connect
     * that starts while our tunnel is up is never treated as a takeover.
     */
    private suspend fun vpnSlot(context: Context): VpnSlot = withContext(Dispatchers.IO) {
        if (NexaVpnService.isServiceActive) return@withContext VpnSlot.OwnSession
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return@withContext VpnSlot.Free
        if (UnderlyingNetworkSelector.vpnNetworks(cm).isEmpty()) {
            return@withContext VpnSlot.Free
        }
        val alwaysOn = UnderlyingNetworkSelector.alwaysOnVpnPackage(context)
            ?: return@withContext VpnSlot.ForeignVpn
        if (VpnTakeoverPolicy.isForeignAlwaysOn(alwaysOn, context.packageName)) {
            VpnSlot.AlwaysOnVpn(alwaysOn)
        } else {
            VpnSlot.ForeignVpn
        }
    }

    /**
     * What a connect may do about the VPN slot, before anything is started.
     *
     * The refusal cases are reported here as well as returned: the caller only
     * needs to act on [VpnTakeoverDecision.Proceed] and
     * [VpnTakeoverDecision.Ask], the latter being the one that needs a UI.
     */
    suspend fun takeoverCheck(context: Context): VpnTakeoverDecision {
        val decision = VpnTakeoverPolicy.decide(vpnSlot(context), vpnTakeoverChoice.value)
        when (decision) {
            is VpnTakeoverDecision.RefuseAlwaysOn -> {
                errorMessage.value = AppStrings.get(R.string.error_vpn_always_on, decision.packageName)
                addLog("connect aborted: ${decision.packageName} is the always-on VPN")
            }
            is VpnTakeoverDecision.Refuse -> {
                errorMessage.value = AppStrings.get(R.string.error_vpn_taken_over)
                addLog("connect aborted: another VPN app owns the slot")
            }
            is VpnTakeoverDecision.Ask, is VpnTakeoverDecision.Proceed -> Unit
        }
        return decision
    }

    /**
     * Remembers what the user wants done when another VPN app owns the slot.
     *
     * [VpnTakeoverChoice.Ask] is how the setting is taken back: the UI offers
     * it once a choice has been stored, so a remembered Cancel is not a dead
     * end.
     */
    fun rememberVpnTakeoverChoice(choice: VpnTakeoverChoice) {
        vpnTakeoverChoice.value = choice
        settingsManager?.saveVpnTakeoverChoice(choice)
        addLog("VPN takeover choice remembered: $choice")
    }

    /**
     * Connects.
     *
     * [allowTakeover] carries the user's answer to "another VPN app owns the
     * slot; may Nexa disconnect it?". Without it the connect is refused rather
     * than revoking the other app — see [takeoverCheck], which is what puts the
     * question to the user in the first place.
     */
    fun connect(context: Context, allowTakeover: Boolean = false) {
        if (isConnecting.value) return
        connectJob = viewModelScope.launch(Dispatchers.IO) {
            // Mutually exclusive with disconnect; abandon this connect if a
            // disconnect is already in progress.
            if (!connectionMutex.tryLock()) {
                addLog("connect: disconnect in progress, aborting")
                return@launch
            }

            // Enter the connecting state before the old tunnel is touched. The UI keys the status
            // card and the FAB on isConnecting, so flipping it first keeps them in place for the
            // whole reconnect; setting it after the teardown made the UI fall back to
            // "Disconnected", collapse those cards and jump back once connecting actually
            // started.
            isConnecting.value = true
            errorMessage.value = null
            connectionStatusText.value = null

            try {
                // If the VPN is already believed to be running (stale state after
                // activity recreation, or a repeated tap), tear the old tunnel down
                // cleanly first. Otherwise nativeStopProxy stops the TUN proxy while
                // the service skips ACTION_START ("VPN already running, skipping"),
                // leaving a dead tunnel that looks like a disconnect after connecting.
                if (isVpnRunning.value) {
                    addLog("connect: already running, stopping it before reconnecting")
                    releaseAllResources(context)
                }

                if (!IrohProxy.isNativeLoaded()) {
                    throw Exception(AppStrings.get(R.string.error_native_library))
                }
                val vpnPermissionGranted = VpnService.prepare(context) == null
                if (!vpnPermissionGranted) {
                    throw Exception(AppStrings.get(R.string.error_vpn_permission))
                }

                // Mutual-exclusion guard, the last one before the service is
                // told to establish: Android allows only one active VpnService
                // TUN per user, and establish() revokes whatever app holds the
                // slot without asking anybody. The UI asks first
                // (takeoverCheck) and passes the answer down; a connect that
                // arrives without one — a widget, a future entry point, a
                // stale UI — refuses rather than kicking the other VPN off.
                val decision = VpnTakeoverPolicy.decide(
                    vpnSlot(context),
                    if (allowTakeover) VpnTakeoverChoice.TakeOver else VpnTakeoverChoice.Cancel
                )
                if (decision != VpnTakeoverDecision.Proceed) {
                    errorMessage.value = when (decision) {
                        is VpnTakeoverDecision.RefuseAlwaysOn ->
                            AppStrings.get(R.string.error_vpn_always_on, decision.packageName)
                        else -> AppStrings.get(R.string.error_vpn_taken_over)
                    }
                    addLog("connect aborted: another VPN app owns the slot")
                    return@launch
                }

                // Pre-flight the configuration before anything is started: a malformed
                // endpoint ID has to be reported as such, immediately, instead of
                // surfacing after the endpoint group is built.
                validateConfiguredNodeIds()?.let { reason ->
                    addLog("connect aborted: $reason")
                    errorMessage.value = reason
                    return@launch
                }

                var lastError: Exception? = null

                // Retry loop: every attempt has an overall timeout of
                // ATTEMPT_TIMEOUT_MS; on timeout or failure all resources are
                // released before the next attempt.
                for (attempt in 1..MAX_CONNECT_ATTEMPTS) {
                    try {
                        withTimeout(ATTEMPT_TIMEOUT_MS) {
                            // Inject the system DNS into iroh so it does not
                            // fall back to Google DNS after the JNI system-DNS
                            // read fails on Android (unreliable behind
                            // restrictive networks, backends unreachable).
                            // Re-read on every retry because the network may
                            // have changed after releaseAllResources.
                            val dnsServers = getSystemDnsServers(context)
                            if (dnsServers.isNotEmpty()) {
                                addLog("Injecting system DNS servers: $dnsServers")
                                IrohProxy.nativeSetDnsServers(dnsServers)
                            }
                            // Pre-resolve the iroh infrastructure domains
                            // (dns.iroh.link + relays) to work around the GFW
                            // dropping iroh.link UDP DNS responses. Re-resolved
                            // on every retry.
                            val dnsOverrides = resolveIrohDnsOverrides()
                            if (dnsOverrides.isNotEmpty()) {
                                IrohProxy.nativeSetDnsOverride(dnsOverrides)
                            }
                            // Configure the relay mode
                            IrohProxy.nativeSetRelayConfig(
                                relayMode.value,
                                relayUrl.value,
                                relayAuthToken.value
                            )
                            // Configure the 2FA credentials (must be injected
                            // before nativeStartProxy). Every endpoint carries
                            // its own pair, so the native table is cleared
                            // first: without that, an endpoint whose 2FA was
                            // switched off would still hold the credentials of
                            // an earlier connect for as long as the process
                            // lives.
                            IrohProxy.nativeClearNodeTwoFactor()
                            // One name for this install, however many endpoints
                            // it authenticates to, read when the enrollment
                            // below is armed. Before any credential is
                            // registered rather than after: what is in the
                            // native tables at nativeStartProxy is what goes
                            // on the wire.
                            IrohProxy.nativeSetDeviceId(deviceId.value)
                            for (node in nodes.value) {
                                val otp = node.twoFactor?.takeIf { it.enabled } ?: continue
                                IrohProxy.nativeSetTwoFactorForNode(
                                    node.nodeId,
                                    otp.clientId,
                                    otp.secret,
                                    otp.algorithm,
                                    // The device this secret was issued to, or
                                    // empty for one issued to the client —
                                    // which is every pair this app could hold
                                    // before devices existed, and every pair a
                                    // plain invite will ever hand over. Those
                                    // must keep answering unnamed: a server
                                    // asked for a device it does not know
                                    // refuses rather than falling back.
                                    otp.device.orEmpty()
                                )
                            }
                            // A token instead of credentials, for an endpoint that was
                            // invited with one. Only where no secret exists: enrolling
                            // rotates the secret, so an endpoint that already has one
                            // must not spend a token again.
                            for (node in nodes.value) {
                                val enrollment = node.enrollment ?: continue
                                val hasSecret = node.twoFactor?.takeIf { it.enabled }
                                    ?.secret?.isNotBlank() == true
                                if (hasSecret) continue
                                IrohProxy.nativeSetEnrollmentForNode(
                                    node.nodeId,
                                    enrollment.clientId,
                                    enrollment.token
                                )
                            }
                            ensureIrohStarted()
                            val allDomains = addDomainMappings()
                            startEndpointGroup()

                            // Pre-connect: warm up iroh connections directly on the Rust side
                            // and cache them in the shared connection pool. Unlike HTTP-based
                            // warm-up through the local proxy, this does not depend on backends
                            // answering plain HTTP requests, and it does not consume pooled
                            // connections, so warm-up is reliable.
                            //
                            // This is also the only step that validates the configured endpoint
                            // IDs against the network: nativeStartProxy merely parses them, so a
                            // well-formed but nonexistent node ID (or a server that is down)
                            // would sail through and the VPN would come up reporting "connected"
                            // while every proxied request fails.
                            addLog("Pre-connecting to backends (native warm-up)...")
                            val preConnectedCount = IrohProxy.nativePreconnect()
                            if (preConnectedCount <= 0) {
                                // Fail the attempt: the retry loop gets another go, and if every
                                // attempt fails the reason reaches errorMessage instead of a
                                // green "connected" over a tunnel that reaches nothing.
                                throw Exception(preconnectFailureReason(preConnectedCount))
                            }
                            addLog("Pre-connect completed: $preConnectedCount backend(s) warmed")
                            // The pre-connect is what spent the token: read the secret it
                            // bought now, because a second connect has nothing left to spend.
                            collectIssuedCredential()
                            delay(1000)
                        }

                        // Success: start the VPN foreground service.
                        val allDomains = nodes.value.flatMap { it.domains }
                        val intent = Intent(context, NexaVpnService::class.java).apply {
                            action = NexaVpnService.ACTION_START
                            putStringArrayListExtra(NexaVpnService.EXTRA_DOMAINS, ArrayList(allDomains))
                            // Carried through to the service: it is the only
                            // thing that lets establish() past its own guard.
                            putExtra(NexaVpnService.EXTRA_ALLOW_TAKEOVER, allowTakeover)
                        }
                        context.startForegroundService(intent)
                        isVpnRunning.value = true
                        addLog("Connected successfully (attempt $attempt/$MAX_CONNECT_ATTEMPTS)")
                        // The tunnel is up: start reporting how each backend is reached, and
                        // keep doing so — iroh may promote a relayed connection later.
                        startLinkPolling()
                        return@launch
                    } catch (e: TimeoutCancellationException) {
                        // withTimeout expired: retryable.
                        addLog("Attempt $attempt/$MAX_CONNECT_ATTEMPTS timed out after ${ATTEMPT_TIMEOUT_MS}ms")
                        lastError = e
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        // Deliberate cancellation from disconnect: do not
                        // retry, propagate to exit the loop.
                        throw e
                    } catch (e: Exception) {
                        addLog("Attempt $attempt/$MAX_CONNECT_ATTEMPTS failed: ${e.message}")
                        lastError = e
                    }

                    if (attempt < MAX_CONNECT_ATTEMPTS) {
                        addLog("Releasing all resources before retry...")
                        releaseAllResources(context)
                        delay(BACKOFF_MS[attempt])
                    }
                }
                errorMessage.value = lastError?.message
                    ?: AppStrings.get(R.string.error_all_attempts_failed)
                addLog("All $MAX_CONNECT_ATTEMPTS attempts failed")
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Deliberate cancellation from disconnect: propagate quietly;
                // the finally block still releases the mutex.
                throw e
            } catch (e: Exception) {
                // Pre-attempt failures (native library not loaded, VPN
                // permission not granted, ...). Without this catch the
                // exception escapes the coroutine and crashes the app.
                addLog("Connect failed: ${e.message}")
                errorMessage.value = e.message ?: AppStrings.get(R.string.error_connection_failed)
            } finally {
                isConnecting.value = false
                connectionStatusText.value = null
                connectionMutex.unlock()
            }
        }
    }

    fun disconnect(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            // Cancel the in-flight connect: JNI cannot be interrupted, but the
            // next suspension point throws CancellationException and it exits.
            connectJob?.cancel()

            // Wait for connect to release the mutex (its finally block unlocks
            // it). The budget is slightly larger than a single connect timeout.
            val locked = withTimeoutOrNull(DISCONNECT_MUTEX_TIMEOUT_MS) {
                connectionMutex.withLock {
                    releaseAllResources(context)
                }
            }
            if (locked == null) {
                // Edge case: connect is still stuck in JNI past the budget.
                // There is no deadlock on the Rust side anymore, so force the
                // release.
                addLog("disconnect: could not acquire mutex within ${DISCONNECT_MUTEX_TIMEOUT_MS}ms, forcing release")
                releaseAllResources(context)
            }
            addLog("Disconnected")
        }
    }

    fun checkVpnPermission(context: Context): Boolean {
        val granted = VpnService.prepare(context) == null
        vpnPermissionGranted.value = granted
        return granted
    }

    fun checkNotificationPermission(context: Context): Boolean {
        val granted = PermissionManager.checkNotificationPermission(context)
        notificationPermissionGranted.value = granted
        return granted
    }

    fun refreshPermissions(context: Context) {
        checkVpnPermission(context)
        checkNotificationPermission(context)
    }

    /**
     * Adds a node (identified by its endpoint ID). Returns null on success or
     * a human-readable reason when the node is rejected (empty, duplicate, or not a
     * parseable endpoint ID).
     *
     * The new list is always published as a brand-new object: MutableStateFlow
     * skips the emission when the new value equals the previous one, and an
     * in-place mutation would make the structural list comparison succeed, so
     * the UI would never recompose.
     */
    fun addNode(nodeId: String): String? {
        val id = nodeId.trim()
        if (id.isEmpty()) return AppStrings.get(R.string.error_endpoint_id_empty)
        if (nodes.value.any { it.nodeId == id }) {
            return AppStrings.get(R.string.error_endpoint_id_exists, id)
        }
        nodeIdFormatError(id)?.let { return it }

        nodes.value = nodes.value + NodeConfig(id)
        saveSettings()
        addLog("Added node: $id")
        return null
    }

    fun removeNode(nodeId: String) {
        if (nodes.value.none { it.nodeId == nodeId }) return

        nodes.value = nodes.value.filterNot { it.nodeId == nodeId }
        saveSettings()
        if (isIrohStarted.value) {
            IrohProxy.nativeRemoveNode(nodeId)
        }
        addLog("Removed node: $nodeId")
    }

    /**
     * Renames a node, i.e. edits its endpoint ID. The domain list attached to
     * the node is preserved.
     *
     * Returns null on success, or a human-readable reason when the rename is
     * rejected (empty, colliding with another node, or not a parseable endpoint ID).
     *
     * When iroh is already up, the native side is re-pointed immediately: the
     * old node is dropped and every domain of that node is mapped to the new
     * endpoint ID again, so the change takes effect without reconnecting. The
     * proxied domain set is unchanged, so the running TUN proxy still routes
     * the same traffic.
     */
    fun renameNode(oldNodeId: String, newNodeId: String): String? {
        val newId = newNodeId.trim()
        if (newId.isEmpty()) return AppStrings.get(R.string.error_endpoint_id_empty)
        if (newId == oldNodeId) return null

        val index = nodes.value.indexOfFirst { it.nodeId == oldNodeId }
        if (index == -1) return AppStrings.get(R.string.error_endpoint_not_found, oldNodeId)
        if (nodes.value.any { it.nodeId == newId }) {
            return AppStrings.get(R.string.error_endpoint_id_exists, newId)
        }
        nodeIdFormatError(newId)?.let { return it }

        val node = nodes.value[index]
        nodes.value = nodes.value.toMutableList().apply { set(index, node.copy(nodeId = newId)) }
        saveSettings()

        if (isIrohStarted.value) {
            IrohProxy.nativeRemoveNode(oldNodeId)
            for (domain in node.domains) {
                if (IrohProxy.nativeAddDomainMapping(domain, newId) != 0) {
                    addLog("Failed to re-map domain '$domain' to new node: $newId")
                }
            }
        }
        addLog("Renamed node: $oldNodeId -> $newId")
        return null
    }

    fun addDomainToNode(nodeId: String, domain: String) {
        if (domain.isNotEmpty()) {
            val nodeIndex = nodes.value.indexOfFirst { it.nodeId == nodeId }
            if (nodeIndex != -1) {
                val node = nodes.value[nodeIndex]
                if (!node.domains.contains(domain)) {
                    val newDomains = node.domains.toMutableList().apply { add(domain) }
                    val newNode = node.copy(domains = newDomains)
                    val newNodes = nodes.value.toMutableList().apply { set(nodeIndex, newNode) }
                    nodes.value = newNodes
                    saveSettings()
                }
            }
        }
    }

    fun removeDomainFromNode(nodeId: String, domain: String) {
        val nodeIndex = nodes.value.indexOfFirst { it.nodeId == nodeId }
        if (nodeIndex != -1) {
            val node = nodes.value[nodeIndex]
            if (node.domains.contains(domain)) {
                val newDomains = node.domains.toMutableList().apply { remove(domain) }
                val newNode = node.copy(domains = newDomains)
                val newNodes = nodes.value.toMutableList().apply { set(nodeIndex, newNode) }
                nodes.value = newNodes
                saveSettings()
            }
        }
    }

    fun clearLogs() {
        logMessages.value = mutableListOf()
    }

    /**
     * Syncs the ViewModel's isVpnRunning with the actual NexaVpnService state.
     *
     * Scenario: after the Activity/ViewModel is recreated (partial process
     * restore, developer options, ...), isVpnRunning defaults to false while
     * the VPN service may still be running in the foreground. Calling this
     * aligns the UI state with the real service state, so the UI cannot show
     * "Disconnected" while the tunnel is actually usable.
     */
    fun syncVpnServiceState() {
        if (!isVpnRunning.value && !isConnecting.value && NexaVpnService.isServiceActive) {
            isVpnRunning.value = true
            // The native endpoint is up too — the service only becomes active after
            // nativeStartIroh and nativeStartProxy succeeded. Recording it matters when this
            // ViewModel was created *after* the connect that started the session (a background
            // switch that recreated the activity): `removeNode`/`renameNode` re-point the
            // native side only when it is set.
            isIrohStarted.value = true
            addLog("Synced UI state: service is active")
            // ...and the connection types have to be reported again, since the poll that used
            // to run belongs to the ViewModel that is gone.
            startLinkPolling()
        }
        // The VPN slot was lost to another VPN app while this ViewModel had no
        // revoked-listener registered (app was backgrounded or the ViewModel
        // was recreated): align the UI now instead of showing a stale
        // "Connected".
        if (isVpnRunning.value && !isConnecting.value && NexaVpnService.wasRevoked) {
            // Same reason as the revoked listener above: the session is over, so its counters
            // and the poll behind them go with it.
            stopLinkPolling()
            isVpnRunning.value = false
            errorMessage.value = AppStrings.get(R.string.error_vpn_taken_over)
            addLog("Synced UI state: tunnel was revoked by another app")
        }
    }
}
