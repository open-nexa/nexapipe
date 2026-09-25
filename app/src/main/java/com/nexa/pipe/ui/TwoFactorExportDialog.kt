package com.nexa.pipe.ui

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R
import com.nexa.pipe.otp.OtpAuth

/**
 * Shows the saved 2FA credentials as an `otpauth://` QR code so another device
 * can import them with the scanner instead of retyping the secret.
 *
 * The secret is displayed in full here — that is the point of the dialog — so
 * the warning about who can read it is not optional.
 */
@Composable
fun TwoFactorExportDialog(
    clientId: String,
    secret: String,
    algorithm: String,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val uri = remember(clientId, secret, algorithm) { OtpAuth.build(clientId, secret, algorithm) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.two_factor_export_title)) },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = stringResource(R.string.two_factor_export_body),
                    style = MaterialTheme.typography.bodySmall
                )

                QrCodeImage(
                    content = uri,
                    modifier = Modifier
                        .fillMaxWidth()
                        .widthIn(max = 260.dp)
                )

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Default.Warning,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = stringResource(R.string.two_factor_export_warning, clientId),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }

                Column(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = stringResource(R.string.two_factor_export_client_id, clientId),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = stringResource(
                            R.string.two_factor_export_algorithm,
                            algorithm.uppercase()
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    clipboardManager.setText(AnnotatedString(uri))
                    Toast.makeText(
                        context,
                        context.getString(R.string.two_factor_export_copied),
                        Toast.LENGTH_SHORT
                    ).show()
                    onDismiss()
                }
            ) {
                Text(stringResource(R.string.two_factor_export_copy))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_close))
            }
        }
    )
}
