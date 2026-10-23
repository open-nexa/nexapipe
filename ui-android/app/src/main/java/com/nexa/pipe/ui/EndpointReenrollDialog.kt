package com.nexa.pipe.ui

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.nexa.pipe.R

/**
 * Asks before this endpoint's credential is dropped and enrolled again.
 */
@Composable
internal fun EndpointReenrollDialog(
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.two_factor_reenroll_title)) },
        text = { Text(stringResource(R.string.two_factor_reenroll_body)) },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.two_factor_reenroll_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    )
}
