package com.nexa.pipe.ui

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R

/**
 * Stands in for a secret the user has not authenticated to see.
 *
 * Deliberately longer than a real one and of a fixed length, so the field
 * cannot be used to measure the credential behind it.
 */
private val SECRET_MASK = "•".repeat(16)

/**
 * 2FA belongs to the endpoint: each server keeps its own [auth.clients] table,
 * so a second server needs its own pair — sharing one secret would mean
 * handing this server's key to it.
 *
 * The state this card shows is the caller's: [twoFactor] is what the endpoint
 * holds, [storedSecretPresent] whether it holds a secret at all,
 * [secretReplaced] whether what is in the field now is something the user
 * typed rather than what was there, and [importWarning] the last mismatch a
 * scan reported. The writes go back through [onUpdateTwoFactor] and the
 * reveals through [credentialUnlock].
 */
@Composable
internal fun EndpointTwoFactorCard(
    twoFactor: NodeTwoFactor,
    enrollment: NodeEnrollment?,
    storedSecretPresent: Boolean,
    secretReplaced: Boolean,
    importWarning: String?,
    credentialUnlock: CredentialUnlock,
    localizedContext: Context,
    onUpdateTwoFactor: ((NodeTwoFactor) -> NodeTwoFactor) -> Unit,
    onSecretReplaced: () -> Unit,
    onImportWarningCleared: () -> Unit,
    onCopyToClipboard: (String, String) -> Unit,
    onScanSecret: () -> Unit,
    onExportSecret: () -> Unit,
    onReenroll: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Lock, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.two_factor_title),
                        style = MaterialTheme.typography.titleSmall
                    )
                    Text(
                        text = if (twoFactor.enabled) {
                            stringResource(R.string.two_factor_on)
                        } else {
                            stringResource(R.string.two_factor_off)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(
                    checked = twoFactor.enabled,
                    onCheckedChange = { enabled ->
                        // Switching this off stops the endpoint
                        // from presenting a token at all, and
                        // switching it on hands this app's
                        // credentials to it — both are a change to
                        // how this endpoint authenticates, so both
                        // are asked for. The switch still shows
                        // what the state is; only moving it takes
                        // a confirmation.
                        credentialUnlock.requestIfLocked(
                            localizedContext,
                            R.string.credential_lock_two_factor_subtitle
                        ) {
                            onUpdateTwoFactor { current -> current.copy(enabled = enabled) }
                        }
                    }
                )
            }

            if (enrollment != null) {
                // A token is waiting to be spent, so there are no credentials to
                // edit yet: the first connect trades it for the secret this page
                // then shows.
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(
                        R.string.two_factor_enrollment_pending,
                        enrollment.clientId
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else if (!twoFactor.enabled) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.two_factor_off_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = twoFactor.clientId,
                    onValueChange = { value ->
                        onImportWarningCleared()
                        onUpdateTwoFactor { current -> current.copy(clientId = value) }
                    },
                    label = { Text(stringResource(R.string.two_factor_client_id)) },
                    placeholder = {
                        Text(stringResource(R.string.two_factor_client_id_placeholder))
                    },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                if (twoFactor.publicKey != null) {
                    // A credential that is a key has no secret to
                    // show and no algorithm to choose: the public
                    // half below is what the server holds, and the
                    // private half never leaves this device. The
                    // scan and share buttons are gone with it —
                    // there is nothing here to copy to another
                    // device, and a scanned secret would be a
                    // different kind of credential entirely.
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        stringResource(R.string.two_factor_credential_type),
                        style = MaterialTheme.typography.labelMedium
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.two_factor_type_key),
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.two_factor_public_key),
                        style = MaterialTheme.typography.labelMedium
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    OutlinedTextField(
                        value = twoFactor.publicKey,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text(stringResource(R.string.two_factor_public_key)) },
                        textStyle = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )
                    // A text button rather than a copy glyph: the
                    // core icon set has no copy icon, and the one
                    // this would borrow says "share" instead.
                    TextButton(
                        onClick = {
                            onCopyToClipboard(
                                twoFactor.publicKey,
                                localizedContext.getString(
                                    R.string.two_factor_public_key
                                )
                            )
                        }
                    ) {
                        Text(
                            text = stringResource(R.string.two_factor_public_key_copy),
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.two_factor_key_hint),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    Spacer(modifier = Modifier.height(8.dp))
                    val secretLocked =
                        storedSecretPresent && !secretReplaced && !credentialUnlock.unlocked
                    OutlinedTextField(
                        // Locked only while the field still holds the
                        // secret this page opened with, and only until
                        // the device confirms who is asking. A field
                        // with nothing to disclose — one the user is
                        // typing into — stays editable.
                        value = if (secretLocked) SECRET_MASK else twoFactor.secret,
                        onValueChange = { value ->
                            if (secretLocked) return@OutlinedTextField
                            // Whatever is here from now on is theirs.
                            onSecretReplaced()
                            onImportWarningCleared()
                            onUpdateTwoFactor { current -> current.copy(secret = value) }
                        },
                        label = { Text(stringResource(R.string.two_factor_secret)) },
                        placeholder = {
                            Text(stringResource(R.string.two_factor_secret_placeholder))
                        },
                        visualTransformation = PasswordVisualTransformation(),
                        trailingIcon = {
                            if (secretLocked) {
                                IconButton(
                                    onClick = {
                                        credentialUnlock.request(
                                            localizedContext.getString(R.string.credential_lock_title),
                                            localizedContext.getString(
                                                R.string.credential_lock_secret_subtitle
                                            )
                                        )
                                    }
                                ) {
                                    Icon(
                                        Icons.Default.Lock,
                                        contentDescription = stringResource(
                                            R.string.credential_lock_reveal
                                        ),
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            }
                        },
                        readOnly = secretLocked,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )

                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.two_factor_algorithm),
                        style = MaterialTheme.typography.labelMedium
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    listOf(
                        "sha1" to R.string.two_factor_sha1,
                        "sha256" to R.string.two_factor_sha256,
                        "sha512" to R.string.two_factor_sha512
                    ).forEach { (alg, label) ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp)
                        ) {
                            RadioButton(
                                selected = twoFactor.algorithm == alg,
                                onClick = {
                                    onImportWarningCleared()
                                    onUpdateTwoFactor { current -> current.copy(algorithm = alg) }
                                }
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                stringResource(label),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            // A scan writes credentials into this
                            // endpoint, replacing whatever is there
                            // now — which is the other half of the
                            // disclosure the field is gated for. The
                            // camera is asked for only once confirmed.
                            onClick = {
                                credentialUnlock.requestIfLocked(
                                    localizedContext,
                                    R.string.credential_lock_scan_secret_subtitle
                                ) { onScanSecret() }
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(
                                Icons.Default.Search,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = stringResource(R.string.two_factor_scan),
                                style = MaterialTheme.typography.labelMedium,
                                maxLines = 1
                            )
                        }
                        OutlinedButton(
                            // The QR code carries the secret in full,
                            // so exporting is the same disclosure as
                            // showing the field and needs the same
                            // thing in front of it.
                            onClick = {
                                if (credentialUnlock.unlocked) {
                                    onExportSecret()
                                } else {
                                    credentialUnlock.request(
                                        localizedContext.getString(R.string.credential_lock_title),
                                        localizedContext.getString(
                                            R.string.credential_lock_export_subtitle
                                        )
                                    ) {
                                        onExportSecret()
                                    }
                                }
                            },
                            enabled = twoFactor.clientId.isNotBlank() && twoFactor.secret.isNotBlank(),
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(
                                Icons.Default.Share,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = stringResource(R.string.two_factor_share_qr),
                                style = MaterialTheme.typography.labelMedium,
                                maxLines = 1
                            )
                        }
                    }
                }

                importWarning?.let { warning ->
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = warning,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))
                DeviceRow(device = twoFactor.device)

                if (twoFactor.device.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.two_factor_reenroll_hint),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = {
                            // Credentials are dropped here, not
                            // edited, so the door stands in front
                            // of the tap that asks — the way it
                            // does for every other action on this
                            // page that touches what is saved.
                            // The dialog only confirms it.
                            credentialUnlock.requestIfLocked(
                                localizedContext,
                                R.string.credential_lock_reenroll_subtitle
                            ) { onReenroll() }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = stringResource(R.string.two_factor_reenroll),
                            style = MaterialTheme.typography.labelMedium,
                            maxLines = 1
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.two_factor_per_endpoint_note),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
