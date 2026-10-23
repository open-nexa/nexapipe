package com.nexa.pipe.ui

import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.nexa.pipe.R
import com.nexa.pipe.SecretStore
import com.nexa.pipe.locale.rememberLocalizedContext
import com.nexa.pipe.provisioning.EndpointInvite
import com.nexa.pipe.provisioning.EndpointInviteCodec
import com.nexa.pipe.provisioning.InviteParseResult
import com.nexa.pipe.vpn.VpnTakeoverChoice

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnControlScreen(viewModel: VpnViewModel = viewModel()) {
    val context = LocalContext.current
    val localizedContext = rememberLocalizedContext()

    val isVpnRunning by viewModel.isVpnRunning.collectAsState()
    val isConnecting by viewModel.isConnecting.collectAsState()
    val nodes by viewModel.nodes.collectAsState()
    val linkReadings by viewModel.linkReadings.collectAsState()
    val traffic by viewModel.traffic.collectAsState()
    val totalTraffic by viewModel.totalTraffic.collectAsState()
    val logMessages by viewModel.logMessages.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    val connectionStatusText by viewModel.connectionStatusText.collectAsState()
    val relayMode by viewModel.relayMode.collectAsState()
    val relayUrl by viewModel.relayUrl.collectAsState()
    val discoveryMode by viewModel.discoveryMode.collectAsState()
    // The token as it stands, and the relay it was issued for.
    val relayToken by viewModel.relayToken.collectAsState()
    val relayAuthToken = relayToken.token
    val credentialProtection by viewModel.credentialProtection.collectAsState()
    val plaintextConsentPending by viewModel.plaintextConsentPending.collectAsState()
    val vpnTakeoverChoice by viewModel.vpnTakeoverChoice.collectAsState()
    val autoConnectOnBoot by viewModel.autoConnectOnBoot.collectAsState()
    val vpnConsentMissing by viewModel.vpnConsentMissing.collectAsState()
    val notice by viewModel.notice.collectAsState()
    // For the VPN-slot question asked before a connect: the check reads the
    // platform's VPN state off the main thread.
    val screenScope = rememberCoroutineScope()

    // The endpoints traffic is actually going through right now, each with the kind of path it
    // is using. Empty until the native side reports a connection, which is also what hides the
    // card: an endpoint nothing is connected to has no link kind to show.
    val connectedEndpoints = nodes.mapNotNull { node ->
        linkKindOf(linkReadings.kinds, node.nodeId)?.let { node to it }
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
    // The door in front of the relay configuration. Where the traffic is sent
    // is decided here, so changing it is a credential-grade action even though
    // the URL is not itself a secret.
    val credentialUnlock = rememberCredentialUnlock()
    // An endpoint invite rewrites shared settings, so it is confirmed when it
    // would overwrite something that already works.
    var pendingInviteImport by remember { mutableStateOf<EndpointInvite?>(null) }
    // Another VPN app owns the single slot Android allows: whether to ask about
    // it, and whether the answer should be remembered.
    var showTakeoverDialog by remember { mutableStateOf(false) }
    var takeoverRememberChoice by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(true) }

    // The setup an invite import is measured against: the endpoints, the
    // relay, and the token that relay was issued for.
    val inviteSetup = InviteSetup(
        nodes = nodes,
        relayMode = relayMode,
        relayUrl = relayUrl,
        relayAuthToken = relayAuthToken
    )

    // The one connect path, shared by the button on the status card and the
    // floating button: ask about a foreign VPN first, then about the
    // permissions, then connect.
    val connect = {
        connectWithTakeoverCheck(
            context = context,
            viewModel = viewModel,
            scope = screenScope,
            onPermissionsNeeded = { showPermissionGuide = true },
            onTakeoverQuestion = {
                takeoverRememberChoice = false
                showTakeoverDialog = true
            }
        )
    }

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

    // What the settings did to a credential, rather than what went wrong: a
    // relay change that dropped the token is something the user has to act
    // on, and the settings they were looking at may be a screen away.
    LaunchedEffect(notice) {
        notice?.let {
            Toast.makeText(context, it, Toast.LENGTH_LONG).show()
            // Taken away once shown, so the same message is shown again the
            // next time it is raised.
            viewModel.clearNotice()
        }
    }

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
                if (inviteConflicts(inviteSetup, localizedContext, result.invite).isEmpty()) {
                    applyInviteImport(
                        viewModel,
                        inviteSetup,
                        context,
                        localizedContext,
                        result.invite
                    )
                } else {
                    pendingInviteImport = result.invite
                    null
                }
            }
        }

    // Asked before the credential is written, not reported after: once it is on
    // disk in the clear, telling the user about it does not put it back.
    // Dismissing is the refusal, so the only way to store one is to answer
    // this.
    //
    // In front of the endpoint branch below, not inside the Scaffold: a 2FA
    // edit on the detail screen can raise this, and a dialog rendered after
    // that branch's early return is a question the user cannot reach — the
    // write it is waiting on simply never happens.
    if (plaintextConsentPending) {
        AlertDialog(
            onDismissRequest = { viewModel.declinePlaintextCredentials() },
            title = { Text(stringResource(R.string.plaintext_consent_title)) },
            text = { Text(stringResource(R.string.plaintext_consent_body)) },
            confirmButton = {
                TextButton(onClick = { viewModel.acceptPlaintextCredentials() }) {
                    Text(stringResource(R.string.plaintext_consent_accept))
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.declinePlaintextCredentials() }) {
                    Text(stringResource(R.string.plaintext_consent_decline))
                }
            }
        )
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
            VpnConnectFab(
                isVpnRunning = isVpnRunning,
                isConnecting = isConnecting,
                onConnect = { connect() },
                onDisconnect = { viewModel.disconnect(context) }
            )
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

            VpnStatusCard(
                isVpnRunning = isVpnRunning,
                isConnecting = isConnecting,
                connectionStatusText = connectionStatusText,
                totalTraffic = totalTraffic,
                connectedEndpoints = connectedEndpoints,
                traffic = traffic,
                onDisconnect = { viewModel.disconnect(context) },
                onConnect = { connect() },
                onOpenEndpoint = { selectedNodeId = it }
            )

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

            // Below the error card rather than inside it: a failed connect and a
            // device that cannot encrypt are two different problems, and one
            // must not look like the other's explanation.
            //
            // Shown only when the fallback actually happened. Storing a credential
            // in plaintext is deliberate — refusing to store it would cut the
            // user off from their own endpoint — but it was silent, which is what
            // made a device with a broken keystore look like a working one.
            AnimatedVisibility(visible = credentialProtection != SecretStore.Protection.Sealed) {
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
                            text = stringResource(R.string.credential_protection_warning),
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            VpnSettingsCard(
                viewModel = viewModel,
                nodes = nodes,
                vpnTakeoverChoice = vpnTakeoverChoice,
                autoConnectOnBoot = autoConnectOnBoot,
                vpnConsentMissing = vpnConsentMissing,
                expanded = showSettings,
                onToggleExpanded = { showSettings = !showSettings },
                onScanInvite = {
                    credentialUnlock.requestIfLocked(
                        localizedContext,
                        R.string.credential_lock_scan_invite_subtitle
                    ) { showInviteScanner = true }
                },
                onPasteInvite = {
                    credentialUnlock.requestIfLocked(
                        localizedContext,
                        R.string.credential_lock_paste_invite_subtitle
                    ) { showInviteLinkDialog = true }
                },
                onOpenEndpoint = { selectedNodeId = it },
                onLanguagePicked = { language -> applyLanguage(context, language) }
            )

            // Relay Settings Card
            Spacer(modifier = Modifier.height(16.dp))
            VpnRelaySettingsCard(
                viewModel = viewModel,
                relayMode = relayMode,
                relayUrl = relayUrl,
                relayAuthToken = relayAuthToken,
                discoveryMode = discoveryMode,
                credentialUnlock = credentialUnlock,
                expanded = showRelaySettings,
                onToggleExpanded = { showRelaySettings = !showRelaySettings },
                localizedContext = localizedContext
            )

            Spacer(modifier = Modifier.height(80.dp))
        }

        if (showLogs) {
            VpnLogsSheet(
                logMessages = logMessages,
                onDismiss = { showLogs = false },
                onClear = { viewModel.clearLogs() }
            )
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

        // A relock has to close what the unlock opened. Both invite entry
        // points — and the confirmation they lead to — outlive the window that
        // opened them: it lapses after two minutes, and coming back from the
        // background closes it on a device that has lost the ability to ask,
        // neither of which the dialog sees. Left open, importing would be a
        // confirmation nobody has been asked for since.
        LaunchedEffect(credentialUnlock.unlocked) {
            if (!credentialUnlock.unlocked) {
                showInviteLinkDialog = false
                showInviteScanner = false
                pendingInviteImport = null
            }
        }

        if (showInviteLinkDialog) {
            InviteLinkDialog(
                onDismiss = { showInviteLinkDialog = false },
                onImport = { link -> handleInviteText(link) }
            )
        }

        if (showTakeoverDialog) {
            VpnTakeoverDialog(
                rememberChoice = takeoverRememberChoice,
                onRememberChoiceChanged = { takeoverRememberChoice = it },
                onConfirm = {
                    showTakeoverDialog = false
                    if (takeoverRememberChoice) {
                        viewModel.rememberVpnTakeoverChoice(VpnTakeoverChoice.TakeOver)
                    }
                    if (permissionsReady(context, viewModel) { showPermissionGuide = true }) {
                        viewModel.connect(context, allowTakeover = true)
                    }
                },
                onDismiss = {
                    showTakeoverDialog = false
                    // Cancel is a choice like any other when it is remembered:
                    // it means "keep using the other VPN", not "ask again".
                    if (takeoverRememberChoice) {
                        viewModel.rememberVpnTakeoverChoice(VpnTakeoverChoice.Cancel)
                    }
                }
            )
        }

        if (showInviteScanner) {
            QrScannerDialog(
                onDismiss = { showInviteScanner = false },
                onResult = { scanned -> handleInviteText(scanned) }
            )
        }

        if (credentialUnlock.unavailable) {
            CredentialUnavailableDialog(credentialUnlock)
        }

        pendingInviteImport?.let { invite ->
            InviteImportDialog(
                summary = inviteSummary(invite, localizedContext),
                conflicts = inviteConflicts(inviteSetup, localizedContext, invite),
                onConfirm = {
                    applyInviteImport(
                        viewModel,
                        inviteSetup,
                        context,
                        localizedContext,
                        invite
                    )?.let { failure ->
                        Toast.makeText(context, failure, Toast.LENGTH_LONG).show()
                    }
                    pendingInviteImport = null
                },
                onDismiss = { pendingInviteImport = null }
            )
        }

    }
}
