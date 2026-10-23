package com.nexa.pipe.ui

import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R
import com.nexa.pipe.ui.components.NexaTonalButton

// ---------------------------------------------------------------------------
// Relay Settings
//
// Where the traffic is sent, and how the endpoints are found. The relay is
// global: it is not part of an endpoint, so it has a card of its own.
// ---------------------------------------------------------------------------

/**
 * The relay settings card: the relay mode, the discovery mode, and the URL
 * and token of a custom relay.
 *
 * [expanded] says whether the settings are showing; [onToggleExpanded] is
 * what the header's arrow calls.
 */
@Composable
internal fun VpnRelaySettingsCard(
    viewModel: VpnViewModel,
    relayMode: String,
    relayUrl: String,
    relayAuthToken: String,
    discoveryMode: String,
    credentialUnlock: CredentialUnlock,
    expanded: Boolean,
    onToggleExpanded: () -> Unit,
    localizedContext: Context
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Share, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    stringResource(R.string.relay_title),
                    style = MaterialTheme.typography.titleSmall
                )
                Spacer(modifier = Modifier.weight(1f))
                IconButton(onClick = onToggleExpanded) {
                    Icon(
                        if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                        contentDescription = stringResource(R.string.action_toggle)
                    )
                }
            }

            AnimatedVisibility(visible = expanded) {
                Column {
                    // Where traffic is sent is decided here, so changing
                    // it is a credential-grade action even though the
                    // URL itself is not a secret: an unlocked phone is
                    // enough to point this device at someone else's
                    // relay. The invite import path is not gated — it
                    // is one deliberate action with its own
                    // confirmation, not a setting left lying around.
                    val relayLocked = !credentialUnlock.unlocked
                    if (relayLocked) {
                        Spacer(modifier = Modifier.height(8.dp))
                        NexaTonalButton(
                            text = stringResource(R.string.credential_lock_relay_action),
                            onClick = {
                                credentialUnlock.request(
                                    localizedContext.getString(R.string.credential_lock_title),
                                    localizedContext.getString(
                                        R.string.credential_lock_relay_subtitle
                                    )
                                )
                            },
                            icon = Icons.Default.Lock,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.relay_mode_title),
                        style = MaterialTheme.typography.labelMedium
                    )
                    Spacer(modifier = Modifier.height(4.dp))

                    val relayModes = listOf(
                        "pinned" to R.string.relay_mode_pinned,
                        "default" to R.string.relay_mode_default,
                        "disabled" to R.string.relay_mode_disabled,
                        "custom" to R.string.relay_mode_custom
                    )
                    relayModes.forEach { (mode, label) ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp)
                        ) {
                            RadioButton(
                                selected = relayMode == mode,
                                onClick = {
                                    if (relayLocked) {
                                        credentialUnlock.request(
                                            localizedContext.getString(R.string.credential_lock_title),
                                            localizedContext.getString(
                                                R.string.credential_lock_relay_subtitle
                                            )
                                        ) {
                                            viewModel.updateRelayConfig(
                                                mode,
                                                relayUrl,
                                                RelayTokenChange.Bound
                                            )
                                        }
                                    } else {
                                        viewModel.updateRelayConfig(
                                            mode,
                                            relayUrl,
                                            RelayTokenChange.Bound
                                        )
                                    }
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
                    Text(
                        stringResource(R.string.discovery_mode_title),
                        style = MaterialTheme.typography.labelMedium
                    )
                    Text(
                        stringResource(R.string.discovery_mode_note),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(4.dp))

                    val discoveryModes = listOf(
                        "n0" to R.string.discovery_mode_n0,
                        "none" to R.string.discovery_mode_none
                    )
                    discoveryModes.forEach { (mode, label) ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp)
                        ) {
                            RadioButton(
                                selected = discoveryMode == mode,
                                onClick = { viewModel.updateDiscoveryMode(mode) }
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                stringResource(label),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }

                    if (relayMode == "custom") {
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = relayUrl,
                            onValueChange = { newUrl ->
                                // The token stays with the relay it was
                                // issued for: a URL that names another
                                // relay takes it with it.
                                if (!relayLocked) {
                                    viewModel.updateRelayConfig(
                                        relayMode,
                                        newUrl,
                                        RelayTokenChange.Bound
                                    )
                                }
                            },
                            label = { Text(stringResource(R.string.relay_url_label)) },
                            placeholder = {
                                Text(stringResource(R.string.relay_url_placeholder))
                            },
                            enabled = !relayLocked,
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = relayAuthToken,
                            onValueChange = { newToken ->
                                // The token the user types belongs to the
                                // relay this screen is configuring.
                                if (!relayLocked) {
                                    viewModel.updateRelayConfig(
                                        relayMode,
                                        relayUrl,
                                        RelayTokenChange.Set(newToken)
                                    )
                                }
                            },
                            label = { Text(stringResource(R.string.relay_token_label)) },
                            visualTransformation = PasswordVisualTransformation(),
                            enabled = !relayLocked,
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                        Text(
                            stringResource(R.string.relay_token_note),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                }
            }
        }
    }
}
