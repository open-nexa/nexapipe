package com.nexa.pipe.ui

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.nexa.pipe.R
import com.nexa.pipe.ui.components.NexaPrimaryButton
import com.nexa.pipe.ui.components.NexaTextButton

/**
 * The confirmation an invite needs before it is applied.
 *
 * [summary] is one line per field, so the confirmation reads like the invite
 * itself; [conflicts] says what the import would overwrite, and is empty when
 * the import only adds things.
 */
@Composable
internal fun InviteImportDialog(
    summary: String,
    conflicts: List<String>,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.invite_import_title)) },
        text = {
            Text(
                summary +
                    if (conflicts.isEmpty()) {
                        ""
                    } else {
                        stringResource(
                            R.string.invite_replaces,
                            conflicts.joinToString(" and ")
                        )
                    }
            )
        },
        confirmButton = {
            NexaPrimaryButton(
                text = stringResource(R.string.action_import),
                onClick = onConfirm
            )
        },
        dismissButton = {
            NexaTextButton(
                text = stringResource(R.string.action_cancel),
                onClick = onDismiss
            )
        }
    )
}
