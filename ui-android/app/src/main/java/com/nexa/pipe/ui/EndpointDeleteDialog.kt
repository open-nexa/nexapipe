package com.nexa.pipe.ui

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.nexa.pipe.R

/**
 * Asks before the endpoint is deleted, naming what goes with it.
 */
@Composable
internal fun EndpointDeleteDialog(
    nodeId: String,
    domainCount: Int,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.endpoint_delete_title)) },
        text = {
            Text(
                stringResource(
                    R.string.endpoint_delete_body,
                    nodeId,
                    domainCount
                )
            )
        },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text(stringResource(R.string.action_delete))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    )
}
