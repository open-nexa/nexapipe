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
    val clipboardManager = LocalClipboardManager.current
    val nodes by viewModel.nodes.collectAsState()
    val linkKinds by viewModel.linkKinds.collectAsState()
    val node = nodes.firstOrNull { it.nodeId == nodeId }
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }

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
        Toast.makeText(context, context.getString(R.string.copied_toast, label), Toast.LENGTH_SHORT)
            .show()
    }

    // This endpoint's 2FA; a switched-off one when it has never been set here.
    val twoFactor = node.twoFactor ?: NodeTwoFactor(enabled = false)

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
        twoFactorImportWarning = config.warnings.firstOrNull()
        config.warnings.forEach { viewModel.addLog("2FA import: $it") }
        Toast.makeText(
            context,
            context.getString(R.string.two_factor_imported, config.clientId),
            Toast.LENGTH_SHORT
        ).show()
    }

    fun removeDomain(domain: String) {
        viewModel.removeDomainFromNode(nodeId, domain)
        // Removal is one accidental tap away, so offer a quick undo instead
        // of a confirmation dialog in front of every delete.
        scope.launch {
            val result = snackbarHostState.showSnackbar(
                message = context.getString(R.string.domain_removed, domain),
                actionLabel = context.getString(R.string.action_undo),
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
                                    copyToClipboard(
                                        nodeId,
                                        context.getString(R.string.clipboard_label_endpoint_id)
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
                                    showEditDialog = true
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
                                    showDeleteDialog = true
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
                onClick = { showAddDomainDialog = true },
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
                                copyToClipboard(
                                    node.nodeId,
                                    context.getString(R.string.clipboard_label_endpoint_id)
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
                                    updateTwoFactor { current -> current.copy(enabled = enabled) }
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
                            OutlinedTextField(
                                value = twoFactor.secret,
                                onValueChange = { value ->
                                    twoFactorImportWarning = null
                                    updateTwoFactor { current -> current.copy(secret = value) }
                                },
                                label = { Text(stringResource(R.string.two_factor_secret)) },
                                placeholder = {
                                    Text(stringResource(R.string.two_factor_secret_placeholder))
                                },
                                visualTransformation = PasswordVisualTransformation(),
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
                                        text = stringResource(R.string.two_factor_scan),
                                        style = MaterialTheme.typography.labelMedium,
                                        maxLines = 1
                                    )
                                }
                                OutlinedButton(
                                    onClick = { showTwoFactorExport = true },
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
                            FilledTonalButton(onClick = { showAddDomainDialog = true }) {
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
                                        copyToClipboard(
                                            domain,
                                            context.getString(R.string.clipboard_label_domain)
                                        )
                                    },
                                    onRemove = { removeDomain(domain) }
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
                        context.getString(R.string.endpoint_id_updated),
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

    if (showTwoFactorExport) {
        TwoFactorExportDialog(
            clientId = twoFactor.clientId,
            secret = twoFactor.secret,
            algorithm = twoFactor.algorithm,
            onDismiss = { showTwoFactorExport = false }
        )
    }
}

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
                        error = context.getString(R.string.error_endpoint_id_empty)
                    } else if (newId != nodeId && existingNodeIds.contains(newId)) {
                        error = context.getString(R.string.error_endpoint_id_exists, newId)
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
