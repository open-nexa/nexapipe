package com.nexa.pipe.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.nexa.pipe.NodeTraffic
import com.nexa.pipe.R
import com.nexa.pipe.formatByteCount
import com.nexa.pipe.nodeTrafficOf
import com.nexa.pipe.ui.components.NexaDangerButton
import com.nexa.pipe.ui.components.NexaPrimaryButton
import com.nexa.pipe.ui.theme.Dimens

/**
 * The card at the top of the screen: whether the tunnel is up, what it has
 * carried, and the action that changes that.
 *
 * Everything it shows is passed in, so the card reads the same state the
 * screen reads and renders the same way whatever draws it.
 */
@Composable
internal fun VpnStatusCard(
    isVpnRunning: Boolean,
    isConnecting: Boolean,
    connectionStatusText: String?,
    totalTraffic: NodeTraffic?,
    connectedEndpoints: List<Pair<NodeConfig, LinkKind>>,
    traffic: Map<String, NodeTraffic>,
    onDisconnect: () -> Unit,
    onConnect: () -> Unit,
    onOpenEndpoint: (String) -> Unit
) {
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
                        else if (connectionStatusText != null) connectionStatusText
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

            // What every backend has carried together, not one backend's share: the
            // card answers "is it working", and the next question is always "how much".
            //
            // Hidden until the counters have anything to say. "Nothing counted yet" is
            // not the same as "counted, and the answer is zero" — see `totalTraffic` —
            // and drawing a row of zeroes before the first byte moves would read as a
            // tunnel that connects and carries nothing.
            AnimatedVisibility(visible = totalTraffic != null) {
                val total = totalTraffic
                if (total != null) {
                    Row(
                        modifier = Modifier.padding(top = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = stringResource(
                                R.string.total_traffic_line,
                                formatByteCount(total.sent),
                                formatByteCount(total.received),
                                pluralStringResource(
                                    R.plurals.node_traffic_flows,
                                    total.active.toInt(),
                                    total.active.toInt()
                                )
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                            // Two, not one: on a narrow screen the two byte counts can
                            // fill the first line by themselves, and a single line ends
                            // by trading the flow count — the figure that says whether
                            // the tunnel is carrying anything at all — for an ellipsis.
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }

            // The one action this screen is for, as a labelled button in the card.
            // It used to live only on the FAB, where a colour and an icon had to stand
            // in for the words "connect" and "disconnect".
            Spacer(modifier = Modifier.height(Dimens.Space3))
            if (isVpnRunning) {
                NexaDangerButton(
                    text = stringResource(R.string.action_disconnect),
                    onClick = onDisconnect,
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
                    onClick = onConnect,
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
                                    .clickable { onOpenEndpoint(node.nodeId) },
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = shortenNodeId(node.nodeId),
                                        style = MaterialTheme.typography.bodyMedium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    // What this backend has carried, in the muted
                                    // style the card uses for everything that
                                    // supports the headline. A backend the native
                                    // side says nothing about has carried nothing —
                                    // it is absent, not zero — so that is said
                                    // instead of leaving a gap next to a badge that
                                    // still reads "connected".
                                    val volume = nodeTrafficOf(traffic, node.nodeId)
                                    Text(
                                        text = if (volume != null) {
                                            stringResource(
                                                R.string.node_traffic_line,
                                                formatByteCount(volume.sent),
                                                formatByteCount(volume.received),
                                                pluralStringResource(
                                                    R.plurals.node_traffic_flows,
                                                    volume.active.toInt(),
                                                    volume.active.toInt()
                                                )
                                            )
                                        } else {
                                            stringResource(R.string.node_traffic_none)
                                        },
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                LinkKindBadge(kind)
                            }
                        }
                    }
                }
            }
        }
    }
}
