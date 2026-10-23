package com.nexa.pipe.ui

import android.content.Context
import android.os.Build
import com.nexa.pipe.vpn.VpnTakeoverDecision
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * True when every permission the connect path needs is already granted.
 * Otherwise shows the permission guide and returns false.
 *
 * Only ever called once the slot is ours to take: the guide is the way into
 * Android's preparation dialog, and that dialog is what displaces another
 * VPN app.
 */
internal fun permissionsReady(
    context: Context,
    viewModel: VpnViewModel,
    onGuideNeeded: () -> Unit
): Boolean {
    val vpnGranted = viewModel.checkVpnPermission(context)
    val notificationGranted = viewModel.checkNotificationPermission(context)

    if (!vpnGranted || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationGranted)) {
        onGuideNeeded()
        return false
    }
    return true
}

/**
 * Connects — asking first, when another VPN app owns the single slot
 * Android allows.
 *
 * The question cannot be asked from the service: it has no UI, and calling
 * establish() is itself what revokes the other app. So it is asked here,
 * before anything is started, which is also what makes Cancel free — there
 * is nothing to undo because nothing has happened yet.
 *
 * Permissions come second for the same reason: the permission guide leads
 * to Android's own preparation dialog, and accepting that dialog is what
 * grants Nexa the slot and displaces the other app. Reaching it before the
 * question would leave Cancel unable to keep that app alive.
 */
internal fun connectWithTakeoverCheck(
    context: Context,
    viewModel: VpnViewModel,
    scope: CoroutineScope,
    onPermissionsNeeded: () -> Unit,
    onTakeoverQuestion: () -> Unit
) {
    scope.launch {
        when (viewModel.takeoverCheck(context)) {
            // Nobody else wants the slot, or the user has already said to
            // take it. The flag only matters while a foreign VPN is up.
            is VpnTakeoverDecision.Proceed ->
                if (permissionsReady(context, viewModel, onPermissionsNeeded)) {
                    viewModel.connect(context, allowTakeover = true)
                }
            // The one case that needs a UI: another VPN is running and the
            // user has not yet said what to do about it.
            is VpnTakeoverDecision.Ask -> onTakeoverQuestion()
            // Both refusals are reported by the ViewModel.
            is VpnTakeoverDecision.Refuse,
            is VpnTakeoverDecision.RefuseAlwaysOn -> Unit
        }
    }
}
