package com.nexa.pipe.ui

import android.content.Context
import android.net.ConnectivityManager
import com.nexa.pipe.vpn.NexaVpnService
import com.nexa.pipe.vpn.UnderlyingNetworkSelector
import com.nexa.pipe.vpn.VpnSlot
import com.nexa.pipe.vpn.VpnTakeoverPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Who owns the platform VPN slot, as seen from the UI.
 *
 * Runs off the main thread: both reads go through a binder. Our own session
 * is [VpnSlot.OwnSession] — the set of VPN networks does not say which one
 * is ours, and the service is the only side that can tell, so a connect
 * that starts while our tunnel is up is never treated as a takeover.
 */
internal suspend fun readVpnSlot(context: Context): VpnSlot = withContext(Dispatchers.IO) {
    if (NexaVpnService.isServiceActive) return@withContext VpnSlot.OwnSession
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        ?: return@withContext VpnSlot.Free
    if (UnderlyingNetworkSelector.vpnNetworks(cm).isEmpty()) {
        return@withContext VpnSlot.Free
    }
    val alwaysOn = UnderlyingNetworkSelector.alwaysOnVpnPackage(context)
        ?: return@withContext VpnSlot.ForeignVpn
    if (VpnTakeoverPolicy.isForeignAlwaysOn(alwaysOn, context.packageName)) {
        VpnSlot.AlwaysOnVpn(alwaysOn)
    } else {
        VpnSlot.ForeignVpn
    }
}
