package com.nexa.pipe.ui

import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.nexa.pipe.PermissionManager
import com.nexa.pipe.otp.OtpAuth
import com.nexa.pipe.otp.OtpAuthConfig
import com.nexa.pipe.otp.OtpAuthParseResult
import com.nexa.pipe.provisioning.EndpointInvite
import com.nexa.pipe.provisioning.EndpointInviteCodec
import com.nexa.pipe.provisioning.InviteParseResult
import com.nexa.pipe.provisioning.InviteTarget
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnControlScreen(viewModel: VpnViewModel = viewModel()) {
    val context = LocalContext.current

    val isVpnRunning by viewModel.isVpnRunning.collectAsState()
    val isConnecting by viewModel.isConnecting.collectAsState()
    val nodes by viewModel.nodes.collectAsState()
    val linkKinds by viewModel.linkKinds.collectAsState()
    val logMessages by viewModel.logMessages.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    val connectionStatusText by viewModel.connectionStatusText.collectAsState()
    val relayMode by viewModel.relayMode.collectAsState()
    val relayUrl by viewModel.relayUrl.collectAsState()
    val forceRelay by viewModel.forceRelay.collectAsState()
    val twoFactorEnabled by viewModel.twoFactorEnabled.collectAsState()
    val twoFactorClientId by viewModel.twoFactorClientId.collectAsState()
    val twoFactorSecret by viewModel.twoFactorSecret.collectAsState()
    val twoFactorAlgorithm by viewModel.twoFactorAlgorithm.collectAsState()

    // The endpoints traffic is actually going through right now, each with the kind of path it
    // is using. Empty until the native side reports a connection, which is also what hides the
    // card: an endpoint nothing is connected to has no link kind to show.
    val connectedEndpoints = nodes.mapNotNull { node ->
        linkKindOf(linkKinds, node.nodeId)?.let { node to it }
    }

    var showLogs by remember { mutableStateOf(false) }
    var showPermissionGuide by remember { mutableStateOf(false) }
    var showAddNodeDialog by remember { mutableStateOf(false) }
    // The endpoint whose detail page is open; null while on the main page.
    // Saveable so a rotation keeps the detail page instead of dropping
    // back to the directory.
    var selectedNodeId by rememberSaveable { mutableStateOf<String?>(null) }
    var showRelaySettings by remember { mutableStateOf(false) }
    var showTwoFactorSettings by remember { mutableStateOf(false) }
    var showTwoFactorScanner by remember { mutableStateOf(false) }
    var showTwoFactorExport by remember { mutableStateOf(false) }
    // Set when a scan succeeded while credentials were already saved, so the
    // user explicitly agrees to replace them.
    var pendingTwoFactorImport by remember { mutableStateOf<OtpAuthConfig?>(null) }
    var twoFactorImportWarning by remember { mutableStateOf<String?>(null) }
    var showInviteScanner by remember { mutableStateOf(false) }
    // An endpoint invite rewrites shared settings, so it is confirmed when it
    // would overwrite something that already works.
    var pendingInviteImport by remember { mutableStateOf<EndpointInvite?>(null) }
    var showSettings by remember { mutableStateOf(true) }

    // Sync the VPN service state whenever this composable becomes visible,
    // covering cases beyond activity recreation (e.g. navigating back from
    // another screen).
    LaunchedEffect(Unit) {
        viewModel.syncVpnServiceState()
    }

    // Second, deliberately redundant channel: the error card sits at the top of the page, but the
    // user may have scrolled down into the settings when a connect attempt fails.
    LaunchedEffect(errorMessage) {
        errorMessage?.let { Toast.makeText(context, it, Toast.LENGTH_LONG).show() }
    }

    fun handleConnect(context: Context) {
        viewModel.checkVpnPermission(context)
        viewModel.checkNotificationPermission(context)

        val vpnGranted = viewModel.vpnPermissionGranted.value
        val notificationGranted = viewModel.notificationPermissionGranted.value

        if (!vpnGranted || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationGranted)) {
            showPermissionGuide = true
            return
        }

        viewModel.connect(context)
    }

    /**
     * Stores credentials that came from a scanned QR code. Scanning is the
     * user's intent to use 2FA, so the switch is turned on as well; mismatched
     * code parameters are surfaced instead of being silently accepted.
     */
    fun applyTwoFactorImport(config: OtpAuthConfig) {
        viewModel.updateTwoFactorConfig(true, config.clientId, config.secret, config.algorithm)
        twoFactorImportWarning = config.warnings.firstOrNull()
        config.warnings.forEach { viewModel.addLog("2FA import: $it") }
        Toast.makeText(context, "2FA imported for \"${config.clientId}\"", Toast.LENGTH_SHORT).show()
    }

    /**
     * Applies a scanned endpoint invite: the node, its domains, the relay it
     * asks for and its 2FA credentials.
     *
     * Returns the message to show when the invite cannot be applied at all.
     */
    fun applyInviteImport(invite: EndpointInvite): String? {
        val nodeId = when (val target = invite.target) {
            is InviteTarget.NodeId -> target.id
            // A ticket bundles addresses the node list has no room for. The
            // server can hand out a Node ID invite instead.
            is InviteTarget.Ticket ->
                return "This invite carries an endpoint ticket, which cannot be stored here. Ask for a Node ID invite."
        }

        if (nodes.none { it.nodeId == nodeId }) {
            viewModel.addNode(nodeId)?.let { return it }
        }
        if (invite.domains.isEmpty()) {
            viewModel.addLog("Invite for $nodeId carried no domains")
        }
        invite.domains.forEach { viewModel.addDomainToNode(nodeId, it) }
        // A relay in the invite is a request to route through it, so the mode
        // follows: a URL is meaningless unless it is the one being used.
        invite.relay?.let { relay -> viewModel.updateRelayConfig("custom", relay, forceRelay) }
        invite.totp?.let { otp ->
            viewModel.updateTwoFactorConfig(true, otp.clientId, otp.secret, otp.algorithm)
            twoFactorImportWarning = invite.warnings().firstOrNull()
            invite.warnings().forEach { viewModel.addLog("Invite import: $it") }
        }
        viewModel.addLog(
            "Imported invite: node=$nodeId domains=${invite.domains.size} " +
                "2FA=${invite.totp?.clientId ?: "none"}"
        )
        Toast.makeText(
            context,
            "Imported endpoint ${invite.name ?: nodeId.take(8)}",
            Toast.LENGTH_SHORT
        ).show()
        return null
    }

    /**
     * The parts of the current setup an invite would overwrite.
     *
     * Empty means the import only adds things, so it can go through without a
     * question; domains merging into an existing node is additive too.
     */
    fun inviteConflicts(invite: EndpointInvite): List<String> = buildList {
        invite.totp?.let { otp ->
            if (twoFactorSecret.isNotBlank() &&
                (twoFactorSecret != otp.secret || twoFactorClientId != otp.clientId)
            ) {
                add("the 2FA credentials for \"${twoFactorClientId.ifBlank { "the current client" }}\"")
            }
        }
        invite.relay?.let { relay ->
            if (relayMode != "custom" || (relayUrl.isNotBlank() && relayUrl != relay)) {
                add("the relay settings")
            }
        }
    }

    /** One line per field, so the confirmation reads like the invite itself. */
    fun inviteSummary(invite: EndpointInvite): String = buildString {
        append("Node: ${invite.target.value}")
        invite.name?.let { append("\nName: $it") }
        append("\nDomains: ${invite.domains.joinToString(", ").ifEmpty { "none" }}")
        val otp = invite.totp
        if (otp == null) {
            append("\n2FA: none")
        } else {
            append("\n2FA: ${otp.clientId} (${otp.algorithm.uppercase(Locale.ROOT)})")
        }
        invite.relay?.let { append("\nRelay: $it") }
    }

    // While an endpoint is open, its page replaces the whole screen: the
    // domain management lives there, keeping the main page a directory. The
    // LaunchedEffects above stay active, so errors (e.g. a revoked VPN)
    // still surface as toasts on the detail page.
    val selectedNode = selectedNodeId?.let { id -> nodes.firstOrNull { it.nodeId == id } }
    if (selectedNode != null) {
        EndpointDetailScreen(
            viewModel = viewModel,
            nodeId = selectedNode.nodeId,
            onBack = { selectedNodeId = null },
            // The page is keyed by node ID, so follow a rename instead of
            // dropping back to the directory.
            onRenamed = { selectedNodeId = it }
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Nexa") },
                actions = {
                    IconButton(onClick = { showLogs = !showLogs }) {
                        Icon(Icons.Default.Info, contentDescription = "Logs")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = {
                    if (isVpnRunning) {
                        viewModel.disconnect(context)
                    } else {
                        handleConnect(context)
                    }
                },
                // A reconnect tears the old session down while the new one comes up, so
                // isVpnRunning briefly goes false. Keying the colour on "running" alone made the
                // button flip red -> primary -> red around every reconnect; "connecting" wins
                // until the new session is actually up.
                containerColor = if (isVpnRunning && !isConnecting) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.primary,
                contentColor = Color.White,
                modifier = Modifier.size(56.dp)
            ) {
                if (isConnecting) {
                    CircularProgressIndicator(
                        color = Color.White,
                        modifier = Modifier.size(24.dp),
                        strokeWidth = 3.dp
                    )
                } else {
                    Icon(
                            imageVector = if (isVpnRunning) Icons.Default.Close else Icons.Default.CheckCircle,
                            contentDescription = if (isVpnRunning) "Disconnect" else "Connect",
                            modifier = Modifier.size(28.dp)
                        )
                }
            }
        },
        floatingActionButtonPosition = FabPosition.End
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(paddingValues)
                .padding(horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(24.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = if (isVpnRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isVpnRunning) "Connected"
                                else if (connectionStatusText != null) connectionStatusText!!
                                else if (isConnecting) "Connecting..."
                                else "Disconnected",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = if (isVpnRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                        )
                        Spacer(modifier = Modifier.weight(1f))
                        Box(
                            modifier = Modifier
                                .size(12.dp)
                                .clip(RoundedCornerShape(50))
                                .background(
                                    if (isVpnRunning) MaterialTheme.colorScheme.primary
                                    else if (isConnecting) MaterialTheme.colorScheme.secondary
                                    else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f)
                                )
                        )
                    }
                    // Always rendered, even when disconnected: a subtitle that comes and goes
                    // changes the card's height, which shifts every card below it (twice per
                    // reconnect - once on teardown, once when the new session comes up).
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = when {
                            isVpnRunning -> "Traffic is being routed through iroh"
                            isConnecting -> "Establishing the tunnel..."
                            else -> "Not connected"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    // ...and through *these* backends, over this kind of path. It belongs to
                    // this card rather than to one of its own: it finishes the sentence the
                    // subtitle starts.
                    AnimatedVisibility(visible = connectedEndpoints.isNotEmpty()) {
                        Column(modifier = Modifier.padding(top = 12.dp)) {
                            Text(
                                text = "Connected endpoints",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                connectedEndpoints.forEach { (node, kind) ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable { selectedNodeId = node.nodeId },
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = shortenNodeId(node.nodeId),
                                            style = MaterialTheme.typography.bodyMedium,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        LinkKindBadge(kind)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Sits directly under the status card: further down it ended up below the whole
            // settings panel, off-screen, so a failed connect looked like a silent disconnect.
            //
            // The card is kept mounted while it animates out, so it has to remember its own
            // message: on the exit frame `errorMessage` is already null and the card would
            // animate away empty (and shrink to nothing before the animation even runs).
            // No explicit enter/exit: the ColumnScope default (fade + expand/shrink) animates the
            // card's height as well, so the cards below slide instead of snapping up.
            var lastErrorMessage by remember { mutableStateOf<String?>(null) }
            LaunchedEffect(errorMessage) {
                errorMessage?.let { lastErrorMessage = it }
            }
            AnimatedVisibility(visible = errorMessage != null) {
                Card(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(12.dp)
                    ) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = lastErrorMessage ?: "",
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Settings, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Configurations", style = MaterialTheme.typography.titleMedium)
                        Spacer(modifier = Modifier.weight(1f))
                        IconButton(onClick = { showSettings = !showSettings }) {
                            Icon(
                                if (showSettings) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                contentDescription = "Toggle"
                            )
                        }
                    }

                    AnimatedVisibility(visible = showSettings) {
                        Column {
                            Spacer(modifier = Modifier.height(16.dp))

                            EndpointsSection(
                                nodes = nodes,
                                onAddNode = { showAddNodeDialog = true },
                                onScanInvite = { showInviteScanner = true },
                                onOpenEndpoint = { selectedNodeId = it }
                            )
                        }
                    }
                }
            }

            // Relay Settings Card
            Spacer(modifier = Modifier.height(16.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Share, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Relay Settings", style = MaterialTheme.typography.titleSmall)
                        Spacer(modifier = Modifier.weight(1f))
                        IconButton(onClick = { showRelaySettings = !showRelaySettings }) {
                            Icon(
                                if (showRelaySettings) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                contentDescription = "Toggle"
                            )
                        }
                    }

                    AnimatedVisibility(visible = showRelaySettings) {
                        Column {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Relay Mode", style = MaterialTheme.typography.labelMedium)
                            Spacer(modifier = Modifier.height(4.dp))

                            val relayModes = listOf(
                                "pinned" to "Pinned (aps1-1, stable)",
                                "default" to "Default (all N0 relays)",
                                "disabled" to "Disabled (direct only)",
                                "custom" to "Custom URL"
                            )
                            relayModes.forEach { (mode, label) ->
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 2.dp)
                                ) {
                                    RadioButton(
                                        selected = relayMode == mode,
                                        onClick = {
                                            viewModel.updateRelayConfig(mode, relayUrl, forceRelay)
                                        }
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(label, style = MaterialTheme.typography.bodySmall)
                                }
                            }

                            if (relayMode == "custom") {
                                Spacer(modifier = Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = relayUrl,
                                    onValueChange = { newUrl ->
                                        viewModel.updateRelayConfig(relayMode, newUrl, forceRelay)
                                    },
                                    label = { Text("Relay URL") },
                                    placeholder = { Text("https://relay.example.com") },
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )
                            }

                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Force Relay", style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                                Switch(
                                    checked = forceRelay,
                                    onCheckedChange = { newForce ->
                                        viewModel.updateRelayConfig(relayMode, relayUrl, newForce)
                                    }
                                )
                            }
                            Text(
                                "When enabled, connections are always routed through relay servers.",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            // 2FA Settings Card
            Spacer(modifier = Modifier.height(16.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("2FA Settings", style = MaterialTheme.typography.titleSmall)
                        Spacer(modifier = Modifier.weight(1f))
                        IconButton(onClick = { showTwoFactorSettings = !showTwoFactorSettings }) {
                            Icon(
                                if (showTwoFactorSettings) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                contentDescription = "Toggle"
                            )
                        }
                    }

                    AnimatedVisibility(visible = showTwoFactorSettings) {
                        Column {
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Enable 2FA", style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                                Switch(
                                    checked = twoFactorEnabled,
                                    onCheckedChange = { enabled ->
                                        viewModel.updateTwoFactorConfig(
                                            enabled,
                                            twoFactorClientId,
                                            twoFactorSecret,
                                            twoFactorAlgorithm
                                        )
                                    }
                                )
                            }

                            // Import/export live outside the "if (enabled)"
                            // block: scanning is the main way to add 2FA, so it
                            // must be reachable before the fields are shown.
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(
                                    onClick = { showTwoFactorScanner = true },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(
                                        Icons.Default.Search,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "Scan QR code",
                                        style = MaterialTheme.typography.labelMedium,
                                        maxLines = 1
                                    )
                                }
                                OutlinedButton(
                                    onClick = { showTwoFactorExport = true },
                                    enabled = twoFactorClientId.isNotBlank() && twoFactorSecret.isNotBlank(),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(
                                        Icons.Default.Share,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "Share as QR",
                                        style = MaterialTheme.typography.labelMedium,
                                        maxLines = 1
                                    )
                                }
                            }

                            if (twoFactorEnabled) {
                                Spacer(modifier = Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = twoFactorClientId,
                                    onValueChange = { newId ->
                                        twoFactorImportWarning = null
                                        viewModel.updateTwoFactorConfig(
                                            twoFactorEnabled,
                                            newId,
                                            twoFactorSecret,
                                            twoFactorAlgorithm
                                        )
                                    },
                                    label = { Text("Client ID") },
                                    placeholder = { Text("client-001") },
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )

                                Spacer(modifier = Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = twoFactorSecret,
                                    onValueChange = { newSecret ->
                                        twoFactorImportWarning = null
                                        viewModel.updateTwoFactorConfig(
                                            twoFactorEnabled,
                                            twoFactorClientId,
                                            newSecret,
                                            twoFactorAlgorithm
                                        )
                                    },
                                    label = { Text("TOTP Secret") },
                                    placeholder = { Text("JBSWY3DPEHPK3PXP") },
                                    visualTransformation = PasswordVisualTransformation(),
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )

                                Spacer(modifier = Modifier.height(8.dp))
                                Text("Algorithm", style = MaterialTheme.typography.labelMedium)
                                Spacer(modifier = Modifier.height(4.dp))
                                listOf("sha1" to "SHA1 (default)", "sha256" to "SHA256", "sha512" to "SHA512")
                                    .forEach { (alg, label) ->
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(vertical = 2.dp)
                                        ) {
                                            RadioButton(
                                                selected = twoFactorAlgorithm == alg,
                                                onClick = {
                                                    twoFactorImportWarning = null
                                                    viewModel.updateTwoFactorConfig(
                                                        twoFactorEnabled,
                                                        twoFactorClientId,
                                                        twoFactorSecret,
                                                        alg
                                                    )
                                                }
                                            )
                                            Spacer(modifier = Modifier.width(8.dp))
                                            Text(label, style = MaterialTheme.typography.bodySmall)
                                        }
                                    }
                            }
                            twoFactorImportWarning?.let { warning ->
                                Spacer(modifier = Modifier.height(8.dp))
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.error,
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = warning,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.error
                                    )
                                }
                            }
                            Text(
                                "2FA authenticates each connection with the server using a TOTP code.",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(80.dp))
        }

        if (showLogs) {
            ModalBottomSheet(
                onDismissRequest = { showLogs = false },
                shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp)
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Logs", style = MaterialTheme.typography.titleLarge)
                        Spacer(modifier = Modifier.weight(1f))
                        IconButton(onClick = { viewModel.clearLogs() }) {
                            Icon(Icons.Default.Delete, contentDescription = "Clear logs")
                        }
                        IconButton(onClick = { showLogs = false }) {
                            Icon(Icons.Default.Close, contentDescription = "Close")
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    LazyColumn(modifier = Modifier.height(300.dp)) {
                        items(logMessages) { message ->
                            Text(message, style = MaterialTheme.typography.bodySmall)
                            Spacer(modifier = Modifier.height(4.dp))
                        }
                    }
                }
            }
        }

        if (showPermissionGuide) {
            ModalBottomSheet(
                onDismissRequest = { showPermissionGuide = false },
                shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
                modifier = Modifier.fillMaxHeight(0.9f)
            ) {
                PermissionGuideScreen(
                    viewModel = viewModel,
                    onComplete = {
                        showPermissionGuide = false
                        viewModel.refreshPermissions(context)
                    }
                )
            }
        }

        if (showAddNodeDialog) {
            AddNodeDialog(
                existingNodeIds = nodes.map { it.nodeId }.toSet(),
                onDismiss = { showAddNodeDialog = false },
                onAdd = { nodeId -> viewModel.addNode(nodeId) }
            )
        }

        if (showTwoFactorScanner) {
            QrScannerDialog(
                onDismiss = { showTwoFactorScanner = false },
                onResult = { scanned ->
                    when (val result = OtpAuth.parse(scanned)) {
                        is OtpAuthParseResult.Failure -> result.message
                        is OtpAuthParseResult.Success -> {
                            // With nothing configured yet the scan is applied
                            // straight away; otherwise replacing working
                            // credentials needs a confirmation.
                            if (twoFactorClientId.isBlank() && twoFactorSecret.isBlank()) {
                                applyTwoFactorImport(result.config)
                            } else {
                                pendingTwoFactorImport = result.config
                            }
                            null
                        }
                    }
                }
            )
        }

        if (showInviteScanner) {
            QrScannerDialog(
                onDismiss = { showInviteScanner = false },
                onResult = { scanned ->
                    when (val result = EndpointInviteCodec.parse(scanned)) {
                        is InviteParseResult.Failure -> result.message
                        is InviteParseResult.Success -> {
                            // With nothing to overwrite the invite is applied
                            // straight away; otherwise replacing working
                            // settings needs a confirmation. A rejected import
                            // (e.g. a ticket invite) is returned as the status
                            // message instead of vanishing.
                            if (inviteConflicts(result.invite).isEmpty()) {
                                applyInviteImport(result.invite)
                            } else {
                                pendingInviteImport = result.invite
                                null
                            }
                        }
                    }
                }
            )
        }

        pendingInviteImport?.let { invite ->
            val conflicts = inviteConflicts(invite)
            AlertDialog(
                onDismissRequest = { pendingInviteImport = null },
                title = { Text("Import Endpoint Invite") },
                text = {
                    Text(
                        inviteSummary(invite) +
                            if (conflicts.isEmpty()) {
                                ""
                            } else {
                                "\n\nThis replaces ${conflicts.joinToString(" and ")}."
                            }
                    )
                },
                confirmButton = {
                    TextButton(
                        onClick = {
                            applyInviteImport(invite)?.let { failure ->
                                Toast.makeText(context, failure, Toast.LENGTH_LONG).show()
                            }
                            pendingInviteImport = null
                        }
                    ) {
                        Text("Import")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { pendingInviteImport = null }) {
                        Text("Cancel")
                    }
                }
            )
        }

        pendingTwoFactorImport?.let { scanned ->
            AlertDialog(
                onDismissRequest = { pendingTwoFactorImport = null },
                title = { Text("Replace 2FA Configuration") },
                text = {
                    Text(
                        "A 2FA configuration is already saved.\n\n" +
                            "Replace it with the scanned one for \"${scanned.clientId}\"?"
                    )
                },
                confirmButton = {
                    TextButton(
                        onClick = {
                            applyTwoFactorImport(scanned)
                            pendingTwoFactorImport = null
                        }
                    ) {
                        Text("Replace")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { pendingTwoFactorImport = null }) {
                        Text("Cancel")
                    }
                }
            )
        }

        if (showTwoFactorExport) {
            TwoFactorExportDialog(
                clientId = twoFactorClientId,
                secret = twoFactorSecret,
                algorithm = twoFactorAlgorithm,
                onDismiss = { showTwoFactorExport = false }
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Configurations > Endpoints
//
// Modelled on a directory: one row per endpoint (monogram + id + domain
// count + chevron); tapping a row opens the endpoint's own page where its
// domains are managed. Keeping management off the list makes every row a
// single touch target and keeps the section compact.
//
// The list itself is a plain Column rather than a nested LazyColumn: it lives
// inside the screen's vertical scroll, and a fixed-height LazyColumn trapped
// scrolling inside a small box while competing with the outer scroll for the
// same gesture.
// ---------------------------------------------------------------------------

/** iroh node IDs are long; keep both ends so the tail stays recognisable. */
internal fun shortenNodeId(nodeId: String): String =
    if (nodeId.length <= 24) nodeId else "${nodeId.take(14)}\u2026${nodeId.takeLast(6)}"

@Composable
private fun EndpointsSection(
    nodes: List<NodeConfig>,
    onAddNode: () -> Unit,
    onScanInvite: () -> Unit,
    onOpenEndpoint: (String) -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Endpoints", style = MaterialTheme.typography.titleSmall)
                Text(
                    text = "Tap an endpoint to manage its domains",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Surface(
                shape = RoundedCornerShape(50),
                color = MaterialTheme.colorScheme.surfaceContainerHighest
            ) {
                Text(
                    text = nodes.size.toString(),
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 2.dp),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilledTonalButton(
                onClick = onAddNode,
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(8.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Add endpoint", maxLines = 1)
            }
            FilledTonalButton(
                onClick = onScanInvite,
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(8.dp)
            ) {
                Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Scan invite", maxLines = 1)
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        if (nodes.isEmpty()) {
            EmptyNodesHint()
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                nodes.forEach { node ->
                    EndpointRow(
                        node = node,
                        onClick = { onOpenEndpoint(node.nodeId) }
                    )
                }
            }
        }
    }
}

/**
 * One endpoint in the configuration directory: its id and the domains routed through it.
 *
 * Purely configuration — no live state. How a connected endpoint is currently reached is shown
 * on the "Connected endpoints" card at the top of the screen, which is only there while a
 * session exists; putting a runtime reading in this list meant state that is usually invisible
 * (the panel starts collapsed) and easy to mistake for something you configured.
 */
@Composable
private fun EndpointRow(
    node: NodeConfig,
    onClick: () -> Unit
) {
    val domainCount = node.domains.size
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = shortenNodeId(node.nodeId),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = when (domainCount) {
                        0 -> "No domains yet"
                        1 -> "1 domain"
                        else -> "$domainCount domains"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (domainCount == 0) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Icon(
                Icons.Default.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun EmptyNodesHint() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            Icons.Default.Add,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(36.dp)
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text("No endpoints yet", style = MaterialTheme.typography.titleSmall)
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Add an endpoint ID or scan an invite to start routing domains.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun AddNodeDialog(
    existingNodeIds: Set<String>,
    onDismiss: () -> Unit,
    onAdd: (String) -> String?
) {
    var nodeId by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add Endpoint") },
        text = {
            OutlinedTextField(
                value = nodeId,
                onValueChange = {
                    nodeId = it
                    error = null
                },
                label = { Text("Endpoint ID") },
                isError = error != null,
                supportingText = error?.let { message -> { Text(message) } },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val id = nodeId.trim()
                    if (id.isEmpty()) {
                        error = "Endpoint ID cannot be empty"
                    } else if (existingNodeIds.contains(id)) {
                        error = "Endpoint ID already exists"
                    } else {
                        val failure = onAdd(id)
                        if (failure != null) error = failure else onDismiss()
                    }
                }
            ) {
                Text("Add")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}
