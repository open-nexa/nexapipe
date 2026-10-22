package com.nexa.pipe.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R
import com.nexa.pipe.locale.rememberLocalizedContext
import com.nexa.pipe.otp.OtpAuth

/**
 * Puts the export URI on the clipboard, and says that it is sensitive where
 * the platform can be told.
 *
 * The URI carries the seed, and the clipboard is the one place on Android
 * where the value can leave the app: from API 30 on, only the app in the
 * foreground may read it, and from API 33 on the platform also takes a
 * "this is sensitive" flag, which keeps the value out of the keyboard's
 * preview and out of the clipboard's history.
 *
 * Below API 30 there is neither a flag nor a restriction, and the platform
 * has no way to say "this clip is secret". The user asked for the secret to
 * be copied, so it is copied; what is left is that another app on the device
 * could read it before the clipboard changes, and the warning in the dialog
 * is what says so.
 */
private fun copySecretToClipboard(context: Context, uri: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    val clip = ClipData.newPlainText("TOTP", uri)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        // The flag lives in the clip's own description: the platform reads it
        // from there when the clipboard is shown, and it is what keeps the
        // value out of the keyboard's preview and out of the history.
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    clipboard.setPrimaryClip(clip)
}

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
    val localizedContext = rememberLocalizedContext()
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
                    copySecretToClipboard(context, uri)
                    Toast.makeText(
                        context,
                        localizedContext.getString(R.string.two_factor_export_copied),
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
