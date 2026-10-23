package com.nexa.pipe.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.nexa.pipe.R

/**
 * Whether the tunnel should come back on its own after a restart.
 *
 * The switch is the user's answer to "should the proxy be running when this
 * phone is switched on", and it is off until they say so — a proxy that
 * reconnects without being asked forwards traffic without being asked.
 *
 * [consentMissing] says that the last time the app looked, the VPN permission
 * was gone. Android does not promise that the permission survives a restart,
 * so the boot path checks rather than assumes; when the check fails, the
 * tunnel does not come back, and the user is told why instead of finding a
 * switch that is on and nothing that happened.
 */
@Composable
internal fun AutoConnectSection(
    enabled: Boolean,
    consentMissing: Boolean,
    onChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.auto_connect_on_boot_title),
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = stringResource(
                    if (consentMissing) {
                        R.string.auto_connect_on_boot_consent_missing
                    } else {
                        R.string.auto_connect_on_boot_subtitle
                    }
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = enabled,
            onCheckedChange = onChange
        )
    }
}
