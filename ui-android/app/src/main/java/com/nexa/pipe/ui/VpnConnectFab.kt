package com.nexa.pipe.ui

import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R

/**
 * The button that connects and disconnects.
 *
 * The same action the status card offers as a labelled button, kept as a
 * floating button as well because it is the one control the screen is
 * reachable for from anywhere on the page.
 */
@Composable
internal fun VpnConnectFab(
    isVpnRunning: Boolean,
    isConnecting: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit
) {
    FloatingActionButton(
        onClick = {
            if (isVpnRunning) {
                onDisconnect()
            } else {
                onConnect()
            }
        },
        // A reconnect tears the old session down while the new one comes up, so
        // isVpnRunning briefly goes false. Keying the colour on "running" alone made the
        // button flip red -> primary -> red around every reconnect; "connecting" wins
        // until the new session is actually up.
        containerColor = if (isVpnRunning && !isConnecting) MaterialTheme.colorScheme.error
            else MaterialTheme.colorScheme.primary,
        contentColor = Color.White,
        modifier = Modifier.size(56.dp)
    ) {
        if (isConnecting) {
            CircularProgressIndicator(
                color = Color.White,
                modifier = Modifier.size(24.dp),
                strokeWidth = 3.dp
            )
        } else {
            Icon(
                    imageVector = if (isVpnRunning) Icons.Default.Close else Icons.Default.CheckCircle,
                    contentDescription = if (isVpnRunning) {
                        stringResource(R.string.action_disconnect)
                    } else {
                        stringResource(R.string.action_connect)
                    },
                    modifier = Modifier.size(28.dp)
                )
        }
    }
}
