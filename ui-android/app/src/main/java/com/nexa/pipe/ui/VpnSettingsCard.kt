package com.nexa.pipe.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R
import com.nexa.pipe.locale.AppLanguage
import com.nexa.pipe.ui.theme.Dimens
import com.nexa.pipe.vpn.VpnTakeoverChoice

// ---------------------------------------------------------------------------
// Configurations
//
// The card the screen's own sections live in: the endpoints, the language,
// the VPN-slot question and the auto-connect switch. It is a holder for
// sections that already exist, so the state it is given is the state those
// sections read.
// ---------------------------------------------------------------------------

/**
 * The configurations card: the sections below the status card, under a
 * header that folds them away.
 *
 * [expanded] says whether the sections are showing; [onToggleExpanded] is
 * what the header's arrow calls.
 */
@Composable
internal fun VpnSettingsCard(
    viewModel: VpnViewModel,
    nodes: List<NodeConfig>,
    vpnTakeoverChoice: VpnTakeoverChoice,
    autoConnectOnBoot: Boolean,
    vpnConsentMissing: Boolean,
    expanded: Boolean,
    onToggleExpanded: () -> Unit,
    onScanInvite: () -> Unit,
    onPasteInvite: () -> Unit,
    onOpenEndpoint: (String) -> Unit,
    onLanguagePicked: (AppLanguage) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Settings, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    stringResource(R.string.configurations_title),
                    style = MaterialTheme.typography.titleMedium
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
                    Spacer(modifier = Modifier.height(16.dp))

                    EndpointsSection(
                        nodes = nodes,
                        // An invite carries a relay and the 2FA
                        // credentials of an endpoint, so importing one
                        // is credential-grade: what arrives rewrites
                        // settings that already work, and it can carry
                        // a secret of its own. Both entry points — the
                        // camera and a pasted link — ask first, for
                        // the same reason and in the same words.
                        onScanInvite = onScanInvite,
                        onPasteInvite = onPasteInvite,
                        onOpenEndpoint = onOpenEndpoint
                    )

                    Spacer(modifier = Modifier.height(Dimens.Space3))

                    LanguageSection(
                        onLanguagePicked = onLanguagePicked
                    )

                    // Only once a choice exists: "ask every time" is the
                    // default, and offering to take back a decision the
                    // user never made is noise.
                    if (vpnTakeoverChoice != VpnTakeoverChoice.Ask) {
                        Spacer(modifier = Modifier.height(Dimens.Space3))
                        VpnTakeoverSection(
                            choice = vpnTakeoverChoice,
                            onReset = {
                                viewModel.rememberVpnTakeoverChoice(VpnTakeoverChoice.Ask)
                            }
                        )
                    }

                    Spacer(modifier = Modifier.height(Dimens.Space3))

                    AutoConnectSection(
                        enabled = autoConnectOnBoot,
                        consentMissing = vpnConsentMissing,
                        onChange = { viewModel.setAutoConnectOnBoot(it) }
                    )
                }
            }
        }
    }
}
