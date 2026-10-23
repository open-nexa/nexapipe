package com.nexa.pipe.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R
import com.nexa.pipe.locale.rememberLocalizedContext

/**
 * Edits the endpoint ID of an existing node. The node's domains are kept.
 * [onSave] returns null on success or an error message to be shown inline.
 */
@Composable
internal fun EditNodeDialog(
    nodeId: String,
    existingNodeIds: Set<String>,
    onDismiss: () -> Unit,
    onSave: (String) -> String?
) {
    val context = LocalContext.current
    val localizedContext = rememberLocalizedContext()
    var value by remember { mutableStateOf(nodeId) }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.endpoint_edit_id)) },
        text = {
            Column {
                OutlinedTextField(
                    value = value,
                    onValueChange = {
                        value = it
                        error = null
                    },
                    label = { Text(stringResource(R.string.endpoint_id_label)) },
                    isError = error != null,
                    supportingText = error?.let { message -> { Text(message) } },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.endpoint_id_current, nodeId),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val newId = value.trim()
                    if (newId.isEmpty()) {
                        error = localizedContext.getString(R.string.error_endpoint_id_empty)
                    } else if (newId != nodeId && existingNodeIds.contains(newId)) {
                        error = localizedContext.getString(R.string.error_endpoint_id_exists, newId)
                    } else {
                        val failure = onSave(newId)
                        if (failure != null) error = failure else onDismiss()
                    }
                }
            ) {
                Text(stringResource(R.string.action_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    )
}
