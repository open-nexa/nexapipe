package com.nexa.pipe.ui

import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
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
    val linkKinds by viewModel.linkKinds.collectAsState()
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

    fun updateTwoFactor(transform: (NodeTwoFactor) -> NodeTwoFactor) {
        viewModel.updateNodeTwoFactor(nodeId, transform(twoFactor))
    }

    /**
     * Stores credentials that came from a scanned QR code.
     *
     * Scanning is the user's intent to use 2FA, so it is switched on as well;
     * mismatched code parameters are surfaced instead of being silently
     * accepted. Only this endpoint is touched: every other one keeps whatever
     * it had.
     */
    fun applyTwoFactorImport(config: OtpAuthConfig) {
        updateTwoFactor { current ->
            current.copy(
                enabled = true,
                clientId = config.clientId,
                secret = config.secret,
                algorithm = config.algorithm
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
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                    )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = shortenNodeId(node.nodeId),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = node.nodeId,
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace
                                ),
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        IconButton(
                            onClick = {
                                copyConfirmed(
                                    node.nodeId,
                                    localizedContext.getString(R.string.clipboard_label_endpoint_id),
                                    R.string.credential_lock_copy_id_subtitle
                                )
                            }
                        ) {
                            Icon(
                                Icons.Default.Share,
                                contentDescription = stringResource(R.string.action_copy),
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }
            }

            // How traffic is reaching this backend right now. Only rendered while there is a
            // connection to it: without one there is no link kind to report, and a stale icon
            // would be worse than none.
            linkKindOf(linkKinds, node.nodeId)?.let { linkKind ->
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            LinkKindIcon(linkKind, iconSize = 20.dp)
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = stringResource(R.string.link_title, linkKindLabel(linkKind)),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium
                                )
                                Text(
                                    text = when (linkKind) {
                                        LinkKind.DIRECT -> stringResource(R.string.link_direct_body)
                                        LinkKind.RELAY -> stringResource(R.string.link_relay_body)
                                        LinkKind.UNKNOWN -> stringResource(R.string.link_connecting_body)
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }

            // 2FA belongs to the endpoint: each server keeps its own
            // [auth.clients] table, so a second server needs its own pair —
            // sharing one secret would mean handing this server's key to it.
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Lock, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = stringResource(R.string.two_factor_title),
                                    style = MaterialTheme.typography.titleSmall
                                )
                                Text(
                                    text = if (twoFactor.enabled) {
                                        stringResource(R.string.two_factor_on)
                                    } else {
                                        stringResource(R.string.two_factor_off)
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Switch(
                                checked = twoFactor.enabled,
                                onCheckedChange = { enabled ->
                                    // Switching this off stops the endpoint
                                    // from presenting a token at all, and
                                    // switching it on hands this app's
                                    // credentials to it — both are a change to
                                    // how this endpoint authenticates, so both
                                    // are asked for. The switch still shows
                                    // what the state is; only moving it takes
                                    // a confirmation.
                                    credentialUnlock.requestIfLocked(
                                        localizedContext,
                                        R.string.credential_lock_two_factor_subtitle
                                    ) {
                                        updateTwoFactor { current -> current.copy(enabled = enabled) }
                                    }
                                }
                            )
                        }

                        if (node.enrollment != null) {
                            // A token is waiting to be spent, so there are no credentials to
                            // edit yet: the first connect trades it for the secret this page
                            // then shows.
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = stringResource(
                                    R.string.two_factor_enrollment_pending,
                                    node.enrollment!!.clientId
                                ),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        } else if (!twoFactor.enabled) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = stringResource(R.string.two_factor_off_body),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        } else {
                            Spacer(modifier = Modifier.height(12.dp))
                            OutlinedTextField(
                                value = twoFactor.clientId,
                                onValueChange = { value ->
                                    twoFactorImportWarning = null
                                    updateTwoFactor { current -> current.copy(clientId = value) }
                                },
                                label = { Text(stringResource(R.string.two_factor_client_id)) },
                                placeholder = {
                                    Text(stringResource(R.string.two_factor_client_id_placeholder))
                                },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true
                            )

                            Spacer(modifier = Modifier.height(8.dp))
                            val secretLocked =
                                storedSecretPresent && !secretReplaced && !credentialUnlock.unlocked
                            OutlinedTextField(
                                // Locked only while the field still holds the
                                // secret this page opened with, and only until
                                // the device confirms who is asking. A field
                                // with nothing to disclose — one the user is
                                // typing into — stays editable.
                                value = if (secretLocked) SECRET_MASK else twoFactor.secret,
                                onValueChange = { value ->
                                    if (secretLocked) return@OutlinedTextField
                                    // Whatever is here from now on is theirs.
                                    secretReplaced = true
                                    twoFactorImportWarning = null
                                    updateTwoFactor { current -> current.copy(secret = value) }
                                },
                                label = { Text(stringResource(R.string.two_factor_secret)) },
                                placeholder = {
                                    Text(stringResource(R.string.two_factor_secret_placeholder))
                                },
                                visualTransformation = PasswordVisualTransformation(),
                                trailingIcon = {
                                    if (secretLocked) {
                                        IconButton(
                                            onClick = {
                                                credentialUnlock.request(
                                                    localizedContext.getString(R.string.credential_lock_title),
                                                    localizedContext.getString(
                                                        R.string.credential_lock_secret_subtitle
                                                    )
                                                )
                                            }
                                        ) {
                                            Icon(
                                                Icons.Default.Lock,
                                                contentDescription = stringResource(
                                                    R.string.credential_lock_reveal
                                                ),
                                                modifier = Modifier.size(18.dp)
                                            )
                                        }
                                    }
                                },
                                readOnly = secretLocked,
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true
                            )

                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                stringResource(R.string.two_factor_algorithm),
                                style = MaterialTheme.typography.labelMedium
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            listOf(
                                "sha1" to R.string.two_factor_sha1,
                                "sha256" to R.string.two_factor_sha256,
                                "sha512" to R.string.two_factor_sha512
                            ).forEach { (alg, label) ->
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(vertical = 2.dp)
                                    ) {
                                        RadioButton(
                                            selected = twoFactor.algorithm == alg,
                                            onClick = {
                                                twoFactorImportWarning = null
                                                updateTwoFactor { current -> current.copy(algorithm = alg) }
                                            }
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text(
                                            stringResource(label),
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }
                                }

                            Spacer(modifier = Modifier.height(8.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(
                                    // A scan writes credentials into this
                                    // endpoint, replacing whatever is there
                                    // now — which is the other half of the
                                    // disclosure the field is gated for. The
                                    // camera is asked for only once confirmed.
                                    onClick = {
                                        credentialUnlock.requestIfLocked(
                                            localizedContext,
                                            R.string.credential_lock_scan_secret_subtitle
                                        ) { showTwoFactorScanner = true }
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(
                                        Icons.Default.Search,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = stringResource(R.string.two_factor_scan),
                                        style = MaterialTheme.typography.labelMedium,
                                        maxLines = 1
                                    )
                                }
                                OutlinedButton(
                                    // The QR code carries the secret in full,
                                    // so exporting is the same disclosure as
                                    // showing the field and needs the same
                                    // thing in front of it.
                                    onClick = {
                                        if (credentialUnlock.unlocked) {
                                            showTwoFactorExport = true
                                        } else {
                                            credentialUnlock.request(
                                                localizedContext.getString(R.string.credential_lock_title),
                                                localizedContext.getString(
                                                    R.string.credential_lock_export_subtitle
                                                )
                                            ) {
                                                showTwoFactorExport = true
                                            }
                                        }
                                    },
                                    enabled = twoFactor.clientId.isNotBlank() && twoFactor.secret.isNotBlank(),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(
                                        Icons.Default.Share,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = stringResource(R.string.two_factor_share_qr),
                                        style = MaterialTheme.typography.labelMedium,
                                        maxLines = 1
                                    )
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

                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = stringResource(R.string.two_factor_per_endpoint_note),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        stringResource(R.string.domains_title),
                        style = MaterialTheme.typography.titleMedium
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Surface(
                        shape = RoundedCornerShape(50),
                        color = MaterialTheme.colorScheme.surfaceContainerHighest
                    ) {
                        Text(
                            text = node.domains.size.toString(),
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            if (node.domains.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                        )
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 32.dp),
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
                                stringResource(R.string.endpoint_domains_none),
                                style = MaterialTheme.typography.titleSmall
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = stringResource(R.string.domain_empty_body),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = TextAlign.Center
                            )
                            Spacer(modifier = Modifier.height(16.dp))
                            FilledTonalButton(onClick = { addDomainConfirmed() }) {
                                Icon(
                                    Icons.Default.Add,
                                    contentDescription = null,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(stringResource(R.string.domain_add))
                            }
                        }
                    }
                }
            } else {
                // One list card: rows separated by hairlines that respect the
                // leading monogram so the domains read as a column.
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                        )
                    ) {
                        Column {
                            node.domains.forEachIndexed { index, domain ->
                                DomainRow(
                                    domain = domain,
                                    onCopy = {
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
                                    onRemove = {
                                        credentialUnlock.requestIfLocked(
                                            localizedContext,
                                            R.string.credential_lock_remove_domain_subtitle
                                        ) { removeDomain(domain) }
                                    }
                                )
                                if (index < node.domains.lastIndex) {
                                    HorizontalDivider(
                                        modifier = Modifier.padding(start = 60.dp),
                                        thickness = 1.dp,
                                        color = MaterialTheme.colorScheme.outlineVariant
                                    )
                                }
                            }
                        }
                    }
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
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text(stringResource(R.string.endpoint_delete_title)) },
            text = {
                Text(
                    stringResource(
                        R.string.endpoint_delete_body,
                        nodeId,
                        node.domains.size
                    )
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.removeNode(nodeId)
                        showDeleteDialog = false
                        onBack()
                    },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text(stringResource(R.string.action_delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            }
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
        AlertDialog(
            onDismissRequest = { pendingTwoFactorImport = null },
            title = { Text(stringResource(R.string.two_factor_replace_title)) },
            text = {
                Text(
                    stringResource(R.string.two_factor_replace_body, scanned.clientId)
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        applyTwoFactorImport(scanned)
                        pendingTwoFactorImport = null
                    }
                ) {
                    Text(stringResource(R.string.action_replace))
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingTwoFactorImport = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            }
        )
    }

    // A relock has to close what the unlock opened. The QR carries the secret
    // in full, and the window closes without the dialog knowing: it lapses
    // after two minutes, and coming back from the background closes it on a
    // device that has lost the ability to ask. Clearing the flag rather than
    // gating the dialog on `unlocked` keeps a later authentication from
    // bringing it back on its own — exporting is something the user asks for.
    LaunchedEffect(credentialUnlock.unlocked) {
        if (!credentialUnlock.unlocked) {
            showTwoFactorExport = false
        }
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

/**
 * Stands in for a secret the user has not authenticated to see.
 *
 * Deliberately longer than a real one and of a fixed length, so the field
 * cannot be used to measure the credential behind it.
 */
private val SECRET_MASK = "•".repeat(16)

/**
 * One domain row: a monogram so long lists scan visually, the domain itself
 * (tap to copy), and a trailing remove button.
 */
@Composable
private fun DomainRow(
    domain: String,
    onCopy: () -> Unit,
    onRemove: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onCopy)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.secondaryContainer),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = domain.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
        }
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            text = domain,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        IconButton(onClick = onRemove, modifier = Modifier.size(28.dp)) {
            Icon(
                Icons.Default.Close,
                contentDescription = stringResource(R.string.domain_remove_cd, domain),
                modifier = Modifier.size(16.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun AddDomainDialog(
    onDismiss: () -> Unit,
    onAdd: (String) -> Unit
) {
    var domain by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.domain_add_title)) },
        text = {
            OutlinedTextField(
                value = domain,
                onValueChange = { domain = it },
                label = { Text(stringResource(R.string.domain_label)) },
                placeholder = { Text(stringResource(R.string.domain_placeholder)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val value = domain.trim()
                    if (value.isNotEmpty()) {
                        onAdd(value)
                        onDismiss()
                    }
                }
            ) {
                Text(stringResource(R.string.action_add))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    )
}

/**
 * Edits the endpoint ID of an existing node. The node's domains are kept.
 * [onSave] returns null on success or an error message to be shown inline.
 */
@Composable
private fun EditNodeDialog(
    nodeId: String,
    existingNodeIds: Set<String>,
    onDismiss: () -> Unit,
    onSave: (String) -> String?
) {
    val context = LocalContext.current
    val localizedContext = rememberLocalizedContext()
    var value by remember { mutableStateOf(nodeId) }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.endpoint_edit_id)) },
        text = {
            Column {
                OutlinedTextField(
                    value = value,
                    onValueChange = {
                        value = it
                        error = null
                    },
                    label = { Text(stringResource(R.string.endpoint_id_label)) },
                    isError = error != null,
                    supportingText = error?.let { message -> { Text(message) } },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.endpoint_id_current, nodeId),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val newId = value.trim()
                    if (newId.isEmpty()) {
                        error = localizedContext.getString(R.string.error_endpoint_id_empty)
                    } else if (newId != nodeId && existingNodeIds.contains(newId)) {
                        error = localizedContext.getString(R.string.error_endpoint_id_exists, newId)
                    } else {
                        val failure = onSave(newId)
                        if (failure != null) error = failure else onDismiss()
                    }
                }
            ) {
                Text(stringResource(R.string.action_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    )
}
