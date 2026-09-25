package com.nexa.pipe.ui

import android.app.Activity
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.nexa.pipe.PermissionManager
import com.nexa.pipe.R
import com.nexa.pipe.locale.AppLanguage
import com.nexa.pipe.locale.AppLocale
import com.nexa.pipe.locale.label
import com.nexa.pipe.ui.components.NexaDangerButton
import com.nexa.pipe.ui.components.NexaPrimaryButton
import com.nexa.pipe.ui.components.NexaTonalButton
import com.nexa.pipe.ui.components.NexaTextButton
import com.nexa.pipe.ui.theme.Dimens
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
    val relayAuthToken by viewModel.relayAuthToken.collectAsState()

    // The endpoints traffic is actually going through right now, each with the kind of path it
    // is using. Empty until the native side reports a connection, which is also what hides the
    // card: an endpoint nothing is connected to has no link kind to show.
    val connectedEndpoints = nodes.mapNotNull { node ->
        linkKindOf(linkKinds, node.nodeId)?.let { node to it }
    }

    var showLogs by remember { mutableStateOf(false) }
    var showPermissionGuide by remember { mutableStateOf(false) }
    // An endpoint can only be added from an invite, so this is the paste-a-link entry point;
    // the "type an endpoint ID by hand" dialog is gone.
    var showInviteLinkDialog by remember { mutableStateOf(false) }
    // The endpoint whose detail page is open; null while on the main page.
    //
    // Deliberately not saveable. Restoring it brought the app back on the detail page of
    // whatever endpoint was open before — and since that is a state of *this* screen rather
    // than a destination of its own, the back button then looked like it switched to an old
    // state of the app instead of leaving it. The directory is the entry point, every time.
    var selectedNodeId by remember { mutableStateOf<String?>(null) }
    var showRelaySettings by remember { mutableStateOf(false) }
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

    // ...and again every time the screen comes back to the foreground. The session does not
    // wait for this UI: the service rebuilds the tunnel on a network switch, and it may give up
    // and stop it altogether. Re-reading on resume is what keeps the main page from showing the
    // state it last knew instead of the state that is true now.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) viewModel.onForeground()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
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
     * Switches the UI to [language] and rebuilds the Activity.
     *
     * The rebuild is not a shortcut: resources are resolved per context, so the
     * only way every string on screen changes is going through
     * `MainActivity.attachBaseContext` again. `recreate()` keeps the
     * ViewModel (and with it the running session's state) alive, so the UI
     * comes back where it was — only in the new language.
     */
    fun applyLanguage(language: AppLanguage) {
        AppLocale.select(context, language)
        (context as? Activity)?.recreate()
    }

    /**
     * The endpoint an invite refers to, or null when it carries a ticket
     * instead — a ticket bundles addresses the endpoint list has no room for.
     */
    fun inviteNodeId(invite: EndpointInvite): String? =
        (invite.target as? InviteTarget.NodeId)?.id

    /**
     * Applies a scanned endpoint invite: the node, its domains, the relay it
     * asks for and the 2FA credentials of that endpoint.
     *
     * Returns the message to show when the invite cannot be applied at all.
     */
    fun applyInviteImport(invite: EndpointInvite): String? {
        val nodeId = inviteNodeId(invite)
            // A ticket bundles addresses the node list has no room for. The
            // server can hand out a Node ID invite instead.
            ?: return context.getString(R.string.invite_ticket_unsupported)

        if (nodes.none { it.nodeId == nodeId }) {
            viewModel.addNode(nodeId)?.let { return it }
        }
        if (invite.domains.isEmpty()) {
            viewModel.addLog("Invite for $nodeId carried no domains")
        }
        invite.domains.forEach { viewModel.addDomainToNode(nodeId, it) }
        // The relay is global, so an invite only proposes one: it says how
        // *that* endpoint is reachable, not what this phone should use. The
        // change is listed by `inviteConflicts`, which is what puts the
        // confirmation dialog in front of it — a relay that would actually be
        // overwritten is never applied silently.
        invite.relay?.let { relay -> viewModel.updateRelayConfig("custom", relay) }
        invite.totp?.let { otp ->
            viewModel.updateNodeTwoFactor(
                nodeId,
                NodeTwoFactor(
                    enabled = true,
                    clientId = otp.clientId,
                    secret = otp.secret,
                    algorithm = otp.algorithm
                )
            )
            invite.warnings().forEach { viewModel.addLog("Invite import: $it") }
            invite.warnings().firstOrNull()?.let {
                Toast.makeText(context, it, Toast.LENGTH_LONG).show()
            }
        }
        viewModel.addLog(
            "Imported invite: node=$nodeId domains=${invite.domains.size} " +
                "2FA=${invite.totp?.clientId ?: "none"}"
        )
        Toast.makeText(
            context,
            context.getString(R.string.invite_imported, invite.name ?: nodeId.take(8)),
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
            // Only this endpoint's credentials are replaced: 2FA belongs to
            // the endpoint, so every other one is left alone.
            val current = inviteNodeId(invite)?.let { id -> nodes.firstOrNull { it.nodeId == id } }?.twoFactor
            if (current != null && current.secret.isNotBlank() &&
                (current.secret != otp.secret || current.clientId != otp.clientId)
            ) {
                val client = current.clientId.ifBlank {
                    context.getString(R.string.invite_conflict_2fa_current_client)
                }
                add(context.getString(R.string.invite_conflict_2fa, client))
            }
        }
        invite.relay?.let { relay ->
            if (relayMode != "custom" || (relayUrl.isNotBlank() && relayUrl != relay)) {
                add(context.getString(R.string.invite_conflict_relay))
            }
        }
    }

    /** One line per field, so the confirmation reads like the invite itself. */
    fun inviteSummary(invite: EndpointInvite): String = buildList<String> {
        add(context.getString(R.string.invite_summary_node, invite.target.value))
        invite.name?.let { add(context.getString(R.string.invite_summary_name, it)) }
        add(
            context.getString(
                R.string.invite_summary_domains,
                invite.domains.joinToString(", ").ifEmpty {
                    context.getString(R.string.invite_value_none)
                }
            )
        )
        val otp = invite.totp
        add(
            if (otp == null) {
                context.getString(R.string.invite_summary_2fa_none)
            } else {
                context.getString(
                    R.string.invite_summary_2fa,
                    otp.clientId,
                    otp.algorithm.uppercase(Locale.ROOT)
                )
            }
        )
        invite.relay?.let { add(context.getString(R.string.invite_summary_relay, it)) }
    }.joinToString("\n")

    /**
     * Reads one invite and returns the message to show when it cannot be
     * applied at all, or null when it was accepted.
     *
     * Both entry points — the camera and a pasted link — go through here, and
     * that is the point: the confirmation in the middle is what stops an invite
     * from silently overwriting the relay or this endpoint's 2FA. A second code
     * path that skipped it would not be a shortcut, it would be a bug.
     */
    fun handleInviteText(text: String): String? =
        when (val result = EndpointInviteCodec.parse(text)) {
            is InviteParseResult.Failure -> result.message
            is InviteParseResult.Success -> {
                // With nothing to overwrite the invite is applied straight
                // away; otherwise replacing working settings needs a
                // confirmation. A rejected import (e.g. a ticket invite) comes
                // back as the status message instead of vanishing.
                if (inviteConflicts(result.invite).isEmpty()) {
                    applyInviteImport(result.invite)
                } else {
                    pendingInviteImport = result.invite
                    null
                }
            }
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
                title = { Text(stringResource(R.string.app_title)) },
                actions = {
                    IconButton(onClick = { showLogs = !showLogs }) {
                        Icon(
                            Icons.Default.Info,
                            contentDescription = stringResource(R.string.logs_title)
                        )
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
                            contentDescription = if (isVpnRunning) {
                                stringResource(R.string.action_disconnect)
                            } else {
                                stringResource(R.string.action_connect)
                            },
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
                            text = if (isVpnRunning) stringResource(R.string.status_connected)
                                else if (connectionStatusText != null) connectionStatusText!!
                                else if (isConnecting) stringResource(R.string.status_connecting)
                                else stringResource(R.string.status_disconnected),
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
                            isVpnRunning -> stringResource(R.string.status_connected_subtitle)
                            isConnecting -> stringResource(R.string.status_connecting_subtitle)
                            else -> stringResource(R.string.status_disconnected_subtitle)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    // The one action this screen is for, as a labelled button in the card.
                    // It used to live only on the FAB, where a colour and an icon had to stand
                    // in for the words "connect" and "disconnect".
                    Spacer(modifier = Modifier.height(Dimens.Space3))
                    if (isVpnRunning) {
                        NexaDangerButton(
                            text = stringResource(R.string.action_disconnect),
                            onClick = { viewModel.disconnect(context) },
                            icon = Icons.Default.Close,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    } else {
                        NexaPrimaryButton(
                            text = if (isConnecting) {
                                stringResource(R.string.status_connecting)
                            } else {
                                stringResource(R.string.action_connect)
                            },
                            onClick = { handleConnect(context) },
                            icon = Icons.Default.CheckCircle,
                            loading = isConnecting,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }

                    // ...and through *these* backends, over this kind of path. It belongs to
                    // this card rather than to one of its own: it finishes the sentence the
                    // subtitle starts.
                    AnimatedVisibility(visible = connectedEndpoints.isNotEmpty()) {
                        Column(modifier = Modifier.padding(top = 12.dp)) {
                            Text(
                                text = stringResource(R.string.connected_endpoints_title),
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
                        Text(
                            stringResource(R.string.configurations_title),
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.weight(1f))
                        IconButton(onClick = { showSettings = !showSettings }) {
                            Icon(
                                if (showSettings) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                contentDescription = stringResource(R.string.action_toggle)
                            )
                        }
                    }

                    AnimatedVisibility(visible = showSettings) {
                        Column {
                            Spacer(modifier = Modifier.height(16.dp))

                            EndpointsSection(
                                nodes = nodes,
                                onScanInvite = { showInviteScanner = true },
                                onPasteInvite = { showInviteLinkDialog = true },
                                onOpenEndpoint = { selectedNodeId = it }
                            )

                            Spacer(modifier = Modifier.height(Dimens.Space3))

                            LanguageSection(
                                onLanguagePicked = { language -> applyLanguage(language) }
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
                        Text(
                            stringResource(R.string.relay_title),
                            style = MaterialTheme.typography.titleSmall
                        )
                        Spacer(modifier = Modifier.weight(1f))
                        IconButton(onClick = { showRelaySettings = !showRelaySettings }) {
                            Icon(
                                if (showRelaySettings) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                contentDescription = stringResource(R.string.action_toggle)
                            )
                        }
                    }

                    AnimatedVisibility(visible = showRelaySettings) {
                        Column {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                stringResource(R.string.relay_mode_title),
                                style = MaterialTheme.typography.labelMedium
                            )
                            Spacer(modifier = Modifier.height(4.dp))

                            val relayModes = listOf(
                                "pinned" to R.string.relay_mode_pinned,
                                "default" to R.string.relay_mode_default,
                                "disabled" to R.string.relay_mode_disabled,
                                "custom" to R.string.relay_mode_custom
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
                                            viewModel.updateRelayConfig(mode, relayUrl)
                                        }
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        stringResource(label),
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                            }

                            if (relayMode == "custom") {
                                Spacer(modifier = Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = relayUrl,
                                    onValueChange = { newUrl ->
                                        viewModel.updateRelayConfig(relayMode, newUrl)
                                    },
                                    label = { Text(stringResource(R.string.relay_url_label)) },
                                    placeholder = {
                                        Text(stringResource(R.string.relay_url_placeholder))
                                    },
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = relayAuthToken,
                                    onValueChange = { newToken ->
                                        viewModel.updateRelayConfig(relayMode, relayUrl, newToken)
                                    },
                                    label = { Text(stringResource(R.string.relay_token_label)) },
                                    visualTransformation = PasswordVisualTransformation(),
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )
                                Text(
                                    stringResource(R.string.relay_token_note),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }

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
                        Text(
                            stringResource(R.string.logs_title),
                            style = MaterialTheme.typography.titleLarge
                        )
                        Spacer(modifier = Modifier.weight(1f))
                        IconButton(onClick = { viewModel.clearLogs() }) {
                            Icon(
                                Icons.Default.Delete,
                                contentDescription = stringResource(R.string.logs_clear)
                            )
                        }
                        IconButton(onClick = { showLogs = false }) {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = stringResource(R.string.action_close)
                            )
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

        if (showInviteLinkDialog) {
            InviteLinkDialog(
                onDismiss = { showInviteLinkDialog = false },
                onImport = { link -> handleInviteText(link) }
            )
        }

        if (showInviteScanner) {
            QrScannerDialog(
                onDismiss = { showInviteScanner = false },
                onResult = { scanned -> handleInviteText(scanned) }
            )
        }

        pendingInviteImport?.let { invite ->
            val conflicts = inviteConflicts(invite)
            AlertDialog(
                onDismissRequest = { pendingInviteImport = null },
                title = { Text(stringResource(R.string.invite_import_title)) },
                text = {
                    Text(
                        inviteSummary(invite) +
                            if (conflicts.isEmpty()) {
                                ""
                            } else {
                                stringResource(
                                    R.string.invite_replaces,
                                    conflicts.joinToString(" and ")
                                )
                            }
                    )
                },
                confirmButton = {
                    NexaPrimaryButton(
                        text = stringResource(R.string.action_import),
                        onClick = {
                            applyInviteImport(invite)?.let { failure ->
                                Toast.makeText(context, failure, Toast.LENGTH_LONG).show()
                            }
                            pendingInviteImport = null
                        }
                    )
                },
                dismissButton = {
                    NexaTextButton(
                        text = stringResource(R.string.action_cancel),
                        onClick = { pendingInviteImport = null }
                    )
                }
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
    onScanInvite: () -> Unit,
    onPasteInvite: () -> Unit,
    onOpenEndpoint: (String) -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.endpoints_title),
                    style = MaterialTheme.typography.titleSmall
                )
                Text(
                    text = stringResource(R.string.endpoints_subtitle),
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
            horizontalArrangement = Arrangement.spacedBy(Dimens.Space2)
        ) {
            NexaTonalButton(
                text = stringResource(R.string.endpoints_scan_invite),
                onClick = onScanInvite,
                // `Search` is the wrong glyph for "scan", but the camera icons
                // live in `material-icons-extended`, which cannot be added
                // while the release build has R8 off.
                icon = Icons.Default.Search,
                modifier = Modifier.weight(1f),
            )
            NexaTonalButton(
                text = stringResource(R.string.endpoints_paste_link),
                onClick = onPasteInvite,
                // `ContentPaste` / `ContentCopy` are not in the core icon set
                // either, so this stays on the generic add glyph.
                icon = Icons.Default.Add,
                modifier = Modifier.weight(1f),
            )
        }

        Spacer(modifier = Modifier.height(Dimens.Space3))

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
                    text = if (domainCount == 0) {
                        stringResource(R.string.endpoint_domains_none)
                    } else {
                        pluralStringResource(
                            R.plurals.endpoint_domains_count,
                            domainCount,
                            domainCount
                        )
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (domainCount == 0) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            // 2FA is per endpoint now, so the list says which ones have it.
            if (node.twoFactor?.enabled == true) {
                Icon(
                    Icons.Default.Lock,
                    contentDescription = stringResource(R.string.endpoint_2fa_enabled),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
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
        Text(
            stringResource(R.string.endpoints_empty_title),
            style = MaterialTheme.typography.titleSmall
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.endpoints_empty_body),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
    }
}

/**
 * Paste-an-invite-link entry point, the keyboard equivalent of the scanner.
 *
 * [onImport] returns null when the invite was accepted — the dialog closes — or
 * a message that is shown in place and keeps the dialog open, exactly like the
 * scanner's `(String) -> String?` contract: an invite that was rejected (a
 * ticket invite, a link that will not parse) must not make the user start over.
 */
@Composable
private fun InviteLinkDialog(
    onDismiss: () -> Unit,
    onImport: (String) -> String?
) {
    val context = LocalContext.current
    var link by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.invite_paste_title)) },
        text = {
            OutlinedTextField(
                value = link,
                onValueChange = {
                    link = it
                    error = null
                },
                label = { Text(stringResource(R.string.invite_paste_label)) },
                placeholder = { Text(stringResource(R.string.invite_paste_placeholder)) },
                isError = error != null,
                supportingText = error?.let { message -> { Text(message) } },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        },
        confirmButton = {
            NexaPrimaryButton(
                text = stringResource(R.string.action_import),
                onClick = {
                    val value = link.trim()
                    if (value.isEmpty()) {
                        error = context.getString(R.string.invite_paste_empty)
                        return@NexaPrimaryButton
                    }
                    val failure = onImport(value)
                    if (failure != null) error = failure else onDismiss()
                }
            )
        },
        dismissButton = {
            NexaTextButton(text = stringResource(R.string.action_cancel), onClick = onDismiss)
        }
    )
}

// ---------------------------------------------------------------------------
// Configurations > Language
//
// The picker is where the switch is: the language is a setting of this app,
// not of a session, so it belongs next to the endpoints rather than behind a
// menu item. Picking one rebuilds the Activity (see `applyLanguage`).
// ---------------------------------------------------------------------------

/**
 * The language the UI is in, and the way to change it.
 *
 * The current one is re-read on every composition instead of being remembered:
 * the row is only drawn while the settings panel is expanded, and a change
 * comes back as a new Activity anyway.
 */
@Composable
private fun LanguageSection(
    onLanguagePicked: (AppLanguage) -> Unit
) {
    val context = LocalContext.current
    var showPicker by remember { mutableStateOf(false) }
    val current = AppLocale.selected(context)

    // No leading icon: `material-icons-core` (all the app can use with R8 off)
    // has no glyph for "language", and a wrong one is worse than none. The row
    // matches the endpoints section above it — title, subtitle, chevron.
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { showPicker = true },
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.language_title),
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = current.label(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Icon(
            Icons.Default.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }

    if (showPicker) {
        AlertDialog(
            onDismissRequest = { showPicker = false },
            title = { Text(stringResource(R.string.language_title)) },
            text = {
                Column {
                    AppLanguage.all().forEach { language ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    showPicker = false
                                    if (language != current) onLanguagePicked(language)
                                }
                                .padding(vertical = 2.dp)
                        ) {
                            RadioButton(
                                selected = language == current,
                                onClick = {
                                    showPicker = false
                                    if (language != current) onLanguagePicked(language)
                                }
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(language.label(), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            },
            confirmButton = {
                NexaTextButton(
                    text = stringResource(R.string.action_close),
                    onClick = { showPicker = false }
                )
            }
        )
    }
}
