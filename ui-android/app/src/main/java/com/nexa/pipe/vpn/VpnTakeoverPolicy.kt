package com.nexa.pipe.vpn

/**
 * Who owns the single VPN slot Android allows per user.
 *
 * Only one VpnService TUN can be up at a time: calling `establish()` while
 * another app holds the slot makes Android revoke that app, and neither app is
 * asked. Everything in this file exists so that never happens silently.
 */
sealed interface VpnSlot {
    /** No VPN is up. */
    data object Free : VpnSlot

    /** The VPN that is up is our own tunnel. */
    data object OwnSession : VpnSlot

    /** Another app's VPN is up. */
    data object ForeignVpn : VpnSlot

    /**
     * Another app's VPN is up, and it is the device's always-on VPN.
     *
     * Android restores an always-on VPN as soon as it goes away, and it may be
     * a work-profile VPN the user is not allowed to break, so taking this slot
     * is not on offer at all — not even after being asked.
     */
    data class AlwaysOnVpn(val packageName: String) : VpnSlot
}

/**
 * What the user chose the last time a foreign VPN owned the slot.
 *
 * Persisted only when asked to: [Ask] is the default, and a single Cancel is
 * not allowed to become a setting the user cannot find again.
 */
enum class VpnTakeoverChoice {
    /** Nothing stored: ask every time. */
    Ask,

    /** Take the slot; the other VPN is disconnected. */
    TakeOver,

    /** Leave the other VPN alone. */
    Cancel,
}

/** What a connect should do about the slot. */
sealed interface VpnTakeoverDecision {
    /** Establish. */
    data object Proceed : VpnTakeoverDecision

    /** Ask the user first: nothing may be established before the answer. */
    data object Ask : VpnTakeoverDecision

    /** Refuse: another VPN owns the slot and nobody agreed to take it. */
    data object Refuse : VpnTakeoverDecision

    /** Refuse, and say why: the other VPN is the device's always-on VPN. */
    data class RefuseAlwaysOn(val packageName: String) : VpnTakeoverDecision
}

/**
 * The rule that turns who owns the slot into what a connect may do.
 *
 * Pure on purpose: it is the one part of this behaviour that can be unit tested
 * without a ConnectivityManager.
 */
object VpnTakeoverPolicy {
    /**
     * Whether [alwaysOnPackage] names an app other than this one.
     *
     * Nexa being the always-on VPN is not a conflict — it is this app's own
     * tunnel Android is keeping up.
     */
    fun isForeignAlwaysOn(alwaysOnPackage: String?, selfPackageName: String): Boolean =
        !alwaysOnPackage.isNullOrBlank() && alwaysOnPackage != selfPackageName

    /**
     * Decides what a connect may do.
     *
     * The VPN service calls this with [VpnTakeoverChoice.Cancel] whenever it
     * holds no confirmation: it has no UI, so [VpnTakeoverDecision.Ask] is not
     * an answer it can act on, and refusing is the only safe reading of it.
     */
    fun decide(slot: VpnSlot, choice: VpnTakeoverChoice): VpnTakeoverDecision = when (slot) {
        is VpnSlot.Free, is VpnSlot.OwnSession -> VpnTakeoverDecision.Proceed
        is VpnSlot.AlwaysOnVpn -> VpnTakeoverDecision.RefuseAlwaysOn(slot.packageName)
        is VpnSlot.ForeignVpn -> when (choice) {
            VpnTakeoverChoice.TakeOver -> VpnTakeoverDecision.Proceed
            VpnTakeoverChoice.Cancel -> VpnTakeoverDecision.Refuse
            VpnTakeoverChoice.Ask -> VpnTakeoverDecision.Ask
        }
    }
}
