package com.nexa.pipe.ui

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.nexa.pipe.R

/**
 * Asks before a scanned credential replaces the one this endpoint already has.
 */
@Composable
internal fun EndpointReplaceCredentialDialog(
    clientId: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.two_factor_replace_title)) },
        text = {
            Text(
                stringResource(R.string.two_factor_replace_body, clientId)
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.action_replace))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    )
}
