package com.nexa.pipe.ui

import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R
import com.nexa.pipe.locale.rememberLocalizedContext
import com.nexa.pipe.otp.OtpAuth
import com.nexa.pipe.otp.OtpAuthConfig
import com.nexa.pipe.otp.OtpAuthParseResult
import kotlinx.coroutines.launch

/**
 * Second-level page for one endpoint: shows its identity and manages the
 * domain list routed through it.
 *
 * Reached from the endpoint list on the main screen; [onBack] returns there
 * (also wired to the system back gesture). [onRenamed] lets the caller keep
 * tracking the node while its endpoint ID is edited here, since the page is
 * keyed by node ID.
 *
 * The page itself is the wiring: the state, the actions, and the order the
 * sections appear in. Each section is its own composable — the identity card,
 * the link card, the 2FA card, the domain list — and each dialog is its own
 * too.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EndpointDetailScreen(
    viewModel: VpnViewModel,
    nodeId: String,
    onBack: () -> Unit,
    onRenamed: (String) -> Unit
) {
    val context = LocalContext.current
    val localizedContext = rememberLocalizedContext()
    val clipboardManager = LocalClipboardManager.current
    val nodes by viewModel.nodes.collectAsState()
    val linkReadings by viewModel.linkReadings.collectAsState()
    val node = nodes.firstOrNull { it.nodeId == nodeId }
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    // The door in front of this endpoint's credentials. Process-wide, so an
    // unlock obtained anywhere counts here for the rest of its window.
    val credentialUnlock = rememberCredentialUnlock()

    var showEditDialog by remember { mutableStateOf(false) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    var showAddDomainDialog by remember { mutableStateOf(false) }
    var menuExpanded by remember { mutableStateOf(false) }
    var showTwoFactorScanner by remember { mutableStateOf(false) }
    var showTwoFactorExport by remember { mutableStateOf(false) }
    // Set when a scan succeeded while this endpoint already had credentials, so
    // the user explicitly agrees to replace them.
    var pendingTwoFactorImport by remember { mutableStateOf<OtpAuthConfig?>(null) }
    var twoFactorImportWarning by remember { mutableStateOf<String?>(null) }
    var showReenrollConfirm by remember { mutableStateOf(false) }

    // The node can disappear while this page is open (deleted from here,
    // which also calls onBack); guard so a stale nodeId never renders an
    // empty page.
    if (node == null) {
        LaunchedEffect(nodeId) { onBack() }
        return
    }

    // `context`, not stringResource(): this runs from click handlers, which are
    // not a composable scope. The context is the (locale-wrapped) Activity one.
    fun copyToClipboard(text: String, label: String) {
        clipboardManager.setText(AnnotatedString(text))
        Toast.makeText(context, localizedContext.getString(R.string.copied_toast, label), Toast.LENGTH_SHORT)
            .show()
    }

    /**
     * Opens the add-domain dialog, behind the credential door.
     *
     * Adding a domain is a routing decision, not a list edit: what is typed
     * here starts going through this endpoint — and with it, whatever this
     * endpoint authenticates as.
     */
    fun addDomainConfirmed() {
        credentialUnlock.requestIfLocked(
            localizedContext,
            R.string.credential_lock_add_domain_subtitle
        ) { showAddDomainDialog = true }
    }

    /**
     * [copyToClipboard] behind the credential door.
     *
     * The clipboard is not private: anything on this device can read it back,
     * so copying the endpoint ID — what this device routes through and what a
     * server identifies it by — is a disclosure, not a shortcut for the user's
     * own typing. A domain is the other half of that sentence, naming what the
     * endpoint serves.
     */
    fun copyConfirmed(text: String, label: String, subtitleRes: Int) {
        credentialUnlock.requestIfLocked(localizedContext, subtitleRes) {
            copyToClipboard(text, label)
        }
    }

    // This endpoint's 2FA; a switched-off one when it has never been set here.
    val twoFactor = node.twoFactor ?: NodeTwoFactor(enabled = false)

    // Whether the endpoint already has a secret in storage, and whether what
    // is in the field now is still that secret rather than something being
    // typed.
    //
    // The gate is in front of reading a secret back, not in front of typing one
    // in. Deciding it from the live field value locked the field the instant it
    // stopped being empty, so a new secret could not be entered at all: the
    // first character turned the mask on and every one after it was discarded.
    // What is in storage is the thing worth hiding; anything typed afterwards
    // is the user's own, and hiding it from them is pointless.
    //
    // Read from the node on every recomposition rather than remembered, because
    // a secret can arrive while this page is open: enrolling spends a token and
    // `VpnViewModel.collectIssuedCredential` writes the issued secret into the
    // same node, and a value remembered by node id would still say there was
    // nothing to hide. Typing stays possible because `onValueChange` sets
    // `secretReplaced` in the same breath it writes the character.
    val storedSecretPresent = node.twoFactor?.secret?.isNotBlank() == true
    var secretReplaced by remember(nodeId) { mutableStateOf(false) }

    /**
     * Writes [transform] over this endpoint's credentials.
     *
     * The record it runs on is read when the write happens, not captured from
     * the composition that scheduled it. A write can now be deferred — the
     * credential prompt stands between the tap and the update — and
     * `VpnViewModel.collectIssuedCredential` can deliver an enrollment secret
     * while it waits. Transforming the record this screen was last drawn with
     * would write that older copy back over the node, taking the secret that
     * just arrived with it.
     */
    fun updateTwoFactor(transform: (NodeTwoFactor) -> NodeTwoFactor) {
        val current = viewModel.nodes.value
            .firstOrNull { it.nodeId == nodeId }?.twoFactor
            ?: NodeTwoFactor(enabled = false)
        viewModel.updateNodeTwoFactor(nodeId, transform(current))
    }

    /**
     * Stores credentials that came from a scanned QR code.
     *
     * Scanning is the user's intent to use 2FA, so it is switched on as well;
     * mismatched code parameters are surfaced instead of being silently
     * accepted. Only this endpoint is touched: every other one keeps whatever
     * it had.
     *
     * The device name survives only a scan of the credential that is already
     * here: see the write below.
     */
    fun applyTwoFactorImport(config: OtpAuthConfig) {
        updateTwoFactor { current ->
            // A QR code carries no device name, so anything it brings is the
            // client's shared secret — unless it is the secret this endpoint
            // already holds, which is what scanning a code exported from
            // here looks like. That one is still filed under the device it
            // was issued to, and dropping the name would answer with it as
            // the shared secret instead, which the server does not have it
            // as. A different client id or secret is a different row in the
            // table, and the name goes with it.
            val sameCredential =
                current.clientId == config.clientId && current.secret == config.secret
            current.copy(
                enabled = true,
                clientId = config.clientId,
                secret = config.secret,
                algorithm = config.algorithm,
                device = if (sameCredential) current.device else null,
                // A scanned code is always a secret, so it replaces whatever
                // credential was here — a key included. The view model drops
                // the key that went with it.
                publicKey = null
            )
        }
        // The secret in the field now came from the camera, not from storage,
        // so it is not something this page has to hide from them.
        secretReplaced = true
        twoFactorImportWarning = config.warnings.firstOrNull()
        config.warnings.forEach { viewModel.addLog("2FA import: $it") }
        Toast.makeText(
            context,
            localizedContext.getString(R.string.two_factor_imported, config.clientId),
            Toast.LENGTH_SHORT
        ).show()
    }

    fun removeDomain(domain: String) {
        viewModel.removeDomainFromNode(nodeId, domain)
        // Removal is one accidental tap away, so offer a quick undo instead
        // of a confirmation dialog in front of every delete.
        scope.launch {
            val result = snackbarHostState.showSnackbar(
                message = localizedContext.getString(R.string.domain_removed, domain),
                actionLabel = localizedContext.getString(R.string.action_undo),
                duration = SnackbarDuration.Short
            )
            if (result == SnackbarResult.ActionPerformed) {
                viewModel.addDomainToNode(nodeId, domain)
            }
        }
    }

    // The system back gesture leaves the page, not the app.
    BackHandler(onBack = onBack)

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.endpoint_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.Default.ArrowBack,
                            contentDescription = stringResource(R.string.action_back)
                        )
                    }
                },
                actions = {
                    Box {
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(
                                Icons.Default.MoreVert,
                                contentDescription = stringResource(R.string.endpoint_options)
                            )
                        }
                        DropdownMenu(
                            expanded = menuExpanded,
                            onDismissRequest = { menuExpanded = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.endpoint_copy_id)) },
                                onClick = {
                                    menuExpanded = false
                                    copyConfirmed(
                                        nodeId,
                                        localizedContext.getString(R.string.clipboard_label_endpoint_id),
                                        R.string.credential_lock_copy_id_subtitle
                                    )
                                },
                                leadingIcon = {
                                    Icon(
                                        Icons.Default.Share,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.endpoint_edit_id)) },
                                onClick = {
                                    menuExpanded = false
                                    // Changing the ID re-points every domain
                                    // on this endpoint at another backend, so
                                    // it is not a label edit.
                                    credentialUnlock.requestIfLocked(
                                        localizedContext,
                                        R.string.credential_lock_edit_id_subtitle
                                    ) { showEditDialog = true }
                                },
                                leadingIcon = {
                                    Icon(
                                        Icons.Default.Edit,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.endpoint_delete)) },
                                onClick = {
                                    menuExpanded = false
                                    // Deleting takes the endpoint's 2FA
                                    // credentials with it, so the door stands
                                    // in front of the confirmation, not just
                                    // behind it.
                                    credentialUnlock.requestIfLocked(
                                        localizedContext,
                                        R.string.credential_lock_delete_subtitle
                                    ) { showDeleteDialog = true }
                                },
                                leadingIcon = {
                                    Icon(
                                        Icons.Default.Delete,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                },
                                colors = MenuDefaults.itemColors(
                                    textColor = MaterialTheme.colorScheme.error,
                                    leadingIconColor = MaterialTheme.colorScheme.error
                                )
                            )
                        }
                    }
                }
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { addDomainConfirmed() },
                icon = { Icon(Icons.Default.Add, contentDescription = null) },
                text = { Text(stringResource(R.string.domain_add)) }
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(
                start = 16.dp, end = 16.dp, top = 16.dp, bottom = 96.dp
            ),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Identity card: the recognisable short form plus the full ID,
            // copyable in one tap.
            item {
                EndpointIdentityCard(
                    nodeId = node.nodeId,
                    onCopy = {
                        copyConfirmed(
                            node.nodeId,
                            localizedContext.getString(R.string.clipboard_label_endpoint_id),
                            R.string.credential_lock_copy_id_subtitle
                        )
                    }
                )
            }

            // How traffic is reaching this backend right now. Only rendered while there is a
            // connection to it: without one there is no link kind to report, and a stale icon
            // would be worse than none.
            linkKindOf(linkReadings.kinds, node.nodeId)?.let { linkKind ->
                item {
                    EndpointLinkCard(
                        linkKind = linkKind,
                        rtt = linkRttOf(linkReadings.rtts, node.nodeId)
                    )
                }
            }

            // 2FA belongs to the endpoint: each server keeps its own
            // [auth.clients] table, so a second server needs its own pair —
            // sharing one secret would mean handing this server's key to it.
            item {
                EndpointTwoFactorCard(
                    twoFactor = twoFactor,
                    enrollment = node.enrollment,
                    storedSecretPresent = storedSecretPresent,
                    secretReplaced = secretReplaced,
                    importWarning = twoFactorImportWarning,
                    credentialUnlock = credentialUnlock,
                    localizedContext = localizedContext,
                    onUpdateTwoFactor = { transform -> updateTwoFactor(transform) },
                    onSecretReplaced = { secretReplaced = true },
                    onImportWarningCleared = { twoFactorImportWarning = null },
                    onCopyToClipboard = { text, label -> copyToClipboard(text, label) },
                    onScanSecret = { showTwoFactorScanner = true },
                    onExportSecret = { showTwoFactorExport = true },
                    onReenroll = { showReenrollConfirm = true }
                )
            }

            item {
                EndpointDomainsHeader(domainCount = node.domains.size)
            }

            if (node.domains.isEmpty()) {
                item {
                    EndpointDomainsEmptyCard(onAdd = { addDomainConfirmed() })
                }
            } else {
                // One list card: rows separated by hairlines that respect the
                // leading monogram so the domains read as a column.
                item {
                    EndpointDomainsCard(
                        domains = node.domains,
                        onCopy = { domain ->
                            copyConfirmed(
                                domain,
                                localizedContext.getString(R.string.clipboard_label_domain),
                                R.string.credential_lock_copy_domain_subtitle
                            )
                        },
                        // Removing changes where this domain goes
                        // as surely as adding does. The undo is a
                        // convenience for the user, not a reason
                        // to leave the door open: what is undone
                        // has already been done once.
                        onRemove = { domain ->
                            credentialUnlock.requestIfLocked(
                                localizedContext,
                                R.string.credential_lock_remove_domain_subtitle
                            ) { removeDomain(domain) }
                        }
                    )
                }
            }
        }
    }

    if (showAddDomainDialog) {
        AddDomainDialog(
            onDismiss = { showAddDomainDialog = false },
            onAdd = { domain -> viewModel.addDomainToNode(nodeId, domain) }
        )
    }

    if (showEditDialog) {
        EditNodeDialog(
            nodeId = nodeId,
            existingNodeIds = nodes.map { it.nodeId }.toSet(),
            onDismiss = { showEditDialog = false },
            onSave = { newNodeId ->
                val failure = viewModel.renameNode(nodeId, newNodeId)
                if (failure == null) {
                    onRenamed(newNodeId)
                    Toast.makeText(
                        context,
                        localizedContext.getString(R.string.endpoint_id_updated),
                        Toast.LENGTH_SHORT
                    ).show()
                }
                failure
            }
        )
    }

    if (showDeleteDialog) {
        EndpointDeleteDialog(
            nodeId = nodeId,
            domainCount = node.domains.size,
            onConfirm = {
                viewModel.removeNode(nodeId)
                showDeleteDialog = false
                onBack()
            },
            onDismiss = { showDeleteDialog = false }
        )
    }

    if (showTwoFactorScanner) {
        QrScannerDialog(
            onDismiss = { showTwoFactorScanner = false },
            onResult = { scanned ->
                when (val result = OtpAuth.parse(scanned)) {
                    is OtpAuthParseResult.Failure -> result.message
                    is OtpAuthParseResult.Success -> {
                        // With nothing on this endpoint the scan is applied
                        // straight away; otherwise replacing working
                        // credentials needs a confirmation.
                        if (twoFactor.clientId.isBlank() && twoFactor.secret.isBlank()) {
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

    pendingTwoFactorImport?.let { scanned ->
        EndpointReplaceCredentialDialog(
            clientId = scanned.clientId,
            onConfirm = {
                applyTwoFactorImport(scanned)
                pendingTwoFactorImport = null
            },
            onDismiss = { pendingTwoFactorImport = null }
        )
    }

    // A relock has to close what the unlock opened, and every surface behind
    // the door outlives the window that opened it: the window lapses after two
    // minutes, and coming back from the background closes it on a device that
    // has lost the ability to ask — neither of which the dialog sees. Anything
    // left open would be a confirmation the user has not been asked for since.
    // Clearing the flags rather than gating each dialog on `unlocked` keeps a
    // later authentication from bringing one back on its own: all of these are
    // things the user asks for, one tap at a time.
    LaunchedEffect(credentialUnlock.unlocked) {
        if (!credentialUnlock.unlocked) {
            showEditDialog = false
            showDeleteDialog = false
            showAddDomainDialog = false
            showTwoFactorScanner = false
            showTwoFactorExport = false
            pendingTwoFactorImport = null
            showReenrollConfirm = false
        }
    }

    if (showReenrollConfirm) {
        EndpointReenrollDialog(
            onConfirm = {
                showReenrollConfirm = false
                // Dropped rather than emptied: an endpoint with no
                // credential at all performs no handshake, so a failure to
                // enroll again leaves a connection that fails closed
                // instead of one that still answers under a shared secret
                // nobody intended to hand out.
                viewModel.updateNodeTwoFactor(nodeId, null)
                viewModel.addLog("Re-enrolling: dropped the credential of " + nodeId.take(8))
            },
            onDismiss = { showReenrollConfirm = false }
        )
    }

    if (showTwoFactorExport) {
        TwoFactorExportDialog(
            clientId = twoFactor.clientId,
            secret = twoFactor.secret,
            algorithm = twoFactor.algorithm,
            onDismiss = { showTwoFactorExport = false }
        )
    }

    if (credentialUnlock.unavailable) {
        CredentialUnavailableDialog(credentialUnlock)
    }
}
