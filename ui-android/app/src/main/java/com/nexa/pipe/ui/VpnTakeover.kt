package com.nexa.pipe.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.nexa.pipe.R
import com.nexa.pipe.ui.components.NexaDangerButton
import com.nexa.pipe.ui.components.NexaTextButton
import com.nexa.pipe.ui.theme.Dimens
import com.nexa.pipe.vpn.VpnTakeoverChoice

/**
 * Asks before Nexa takes the VPN slot from another VPN app.
 *
 * Android allows one VpnService TUN per user and revokes the other app
 * silently, so the question has to be asked before establish() — and the only
 * place that can ask it is the UI.
 */
@Composable
internal fun VpnTakeoverDialog(
    rememberChoice: Boolean,
    onRememberChoiceChanged: (Boolean) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.vpn_takeover_title)) },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.vpn_takeover_body),
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(modifier = Modifier.height(Dimens.Space2))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onRememberChoiceChanged(!rememberChoice) }
                ) {
                    Checkbox(
                        checked = rememberChoice,
                        onCheckedChange = onRememberChoiceChanged
                    )
                    Spacer(modifier = Modifier.width(Dimens.Space2))
                    Text(
                        text = stringResource(R.string.vpn_takeover_remember),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        // Destructive weight on purpose: this is the button that disconnects
        // the other app, and it must not look like the ordinary "continue".
        confirmButton = {
            NexaDangerButton(
                text = stringResource(R.string.vpn_takeover_confirm),
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

/**
 * The way back from a remembered takeover choice.
 *
 * A stored Cancel means Nexa never connects while another VPN is up, which is
 * not an answer the user should have to reinstall the app to change.
 */
@Composable
internal fun VpnTakeoverSection(
    choice: VpnTakeoverChoice,
    onReset: () -> Unit,
) {
    val remembered = when (choice) {
        VpnTakeoverChoice.TakeOver -> stringResource(R.string.vpn_takeover_choice_take_over)
        VpnTakeoverChoice.Cancel -> stringResource(R.string.vpn_takeover_choice_cancel)
        // Nothing to take back: the section is not drawn in the first place.
        VpnTakeoverChoice.Ask -> return
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onReset() },
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.vpn_takeover_reset_title),
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = stringResource(R.string.vpn_takeover_reset_subtitle, remembered),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
