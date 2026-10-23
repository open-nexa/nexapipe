package com.nexa.pipe.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R

/**
 * The device this endpoint's credential belongs to, or the absence of one.
 *
 * Read-only, and shown even when there is nothing to say, because "no name" is
 * the answer the user has to be able to see in order to act on it: it is the
 * state that leaves this pair answering as the client rather than as one device
 * of it, which is the one thing on this card re-enrolling changes.
 */
@Composable
internal fun DeviceRow(device: String?) {
    val name = device?.takeIf { it.isNotBlank() }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            text = stringResource(R.string.two_factor_device_label),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = name ?: stringResource(R.string.two_factor_device_none),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
