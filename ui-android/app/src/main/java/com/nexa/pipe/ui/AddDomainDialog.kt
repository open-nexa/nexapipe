package com.nexa.pipe.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R

/**
 * Asks for a domain to route through this endpoint.
 */
@Composable
internal fun AddDomainDialog(
    onDismiss: () -> Unit,
    onAdd: (String) -> Unit
) {
    var domain by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.domain_add_title)) },
        text = {
            OutlinedTextField(
                value = domain,
                onValueChange = { domain = it },
                label = { Text(stringResource(R.string.domain_label)) },
                placeholder = { Text(stringResource(R.string.domain_placeholder)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val value = domain.trim()
                    if (value.isNotEmpty()) {
                        onAdd(value)
                        onDismiss()
                    }
                }
            ) {
                Text(stringResource(R.string.action_add))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    )
}
