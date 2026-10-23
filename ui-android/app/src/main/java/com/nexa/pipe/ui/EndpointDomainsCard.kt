package com.nexa.pipe.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * One list card: rows separated by hairlines that respect the leading
 * monogram so the domains read as a column.
 */
@Composable
internal fun EndpointDomainsCard(
    domains: List<String>,
    onCopy: (String) -> Unit,
    onRemove: (String) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        )
    ) {
        Column {
            domains.forEachIndexed { index, domain ->
                DomainRow(
                    domain = domain,
                    onCopy = { onCopy(domain) },
                    onRemove = { onRemove(domain) }
                )
                if (index < domains.lastIndex) {
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
