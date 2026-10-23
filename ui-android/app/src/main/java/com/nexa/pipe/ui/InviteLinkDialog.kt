package com.nexa.pipe.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.nexa.pipe.R
import com.nexa.pipe.locale.label
import com.nexa.pipe.locale.rememberLocalizedContext
import com.nexa.pipe.ui.components.NexaPrimaryButton
import com.nexa.pipe.ui.components.NexaTextButton

/**
 * Paste-an-invite-link entry point, the keyboard equivalent of the scanner.
 *
 * [onImport] returns null when the invite was accepted — the dialog closes — or
 * a message that is shown in place and keeps the dialog open, exactly like the
 * scanner's `(String) -> String?` contract: an invite that was rejected (a
 * ticket invite, a link that will not parse) must not make the user start over.
 */
@Composable
internal fun InviteLinkDialog(
    onDismiss: () -> Unit,
    onImport: (String) -> String?
) {
    val context = LocalContext.current
    val localizedContext = rememberLocalizedContext()
    var link by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.invite_paste_title)) },
        text = {
            OutlinedTextField(
                value = link,
                onValueChange = {
                    link = it
                    error = null
                },
                label = { Text(stringResource(R.string.invite_paste_label)) },
                placeholder = { Text(stringResource(R.string.invite_paste_placeholder)) },
                isError = error != null,
                supportingText = error?.let { message -> { Text(message) } },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        },
        confirmButton = {
            NexaPrimaryButton(
                text = stringResource(R.string.action_import),
                onClick = {
                    val value = link.trim()
                    if (value.isEmpty()) {
                        error = localizedContext.getString(R.string.invite_paste_empty)
                        return@NexaPrimaryButton
                    }
                    val failure = onImport(value)
                    if (failure != null) error = failure else onDismiss()
                }
            )
        },
        dismissButton = {
            NexaTextButton(text = stringResource(R.string.action_cancel), onClick = onDismiss)
        }
    )
}
