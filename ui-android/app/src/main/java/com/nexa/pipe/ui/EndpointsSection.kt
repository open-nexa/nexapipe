package com.nexa.pipe.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R
import com.nexa.pipe.ui.components.NexaTonalButton
import com.nexa.pipe.ui.theme.Dimens

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
internal fun EndpointsSection(
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
internal fun EndpointRow(
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
internal fun EmptyNodesHint() {
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
