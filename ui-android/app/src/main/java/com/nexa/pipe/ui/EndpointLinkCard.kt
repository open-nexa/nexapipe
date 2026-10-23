package com.nexa.pipe.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R

/**
 * How traffic is reaching this backend right now.
 *
 * Only rendered while there is a connection to it: without one there is no
 * link kind to report, and a stale icon would be worse than none.
 *
 * [rtt] is null when iroh has measured nothing; a path with no sample says
 * nothing at all rather than "0 ms", which would read as a measurement.
 */
@Composable
internal fun EndpointLinkCard(
    linkKind: LinkKind,
    rtt: Long?
) {
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
                rtt?.let { rtt ->
                    Text(
                        text = stringResource(R.string.link_rtt, rtt),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
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
