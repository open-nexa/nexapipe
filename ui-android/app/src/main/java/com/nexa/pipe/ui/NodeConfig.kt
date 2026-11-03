package com.nexa.pipe.ui

import kotlinx.serialization.Serializable

/**
 * One endpoint of the configuration: what it is called, what it routes and how
 * it authenticates.
 */
@Serializable
data class NodeConfig(
    val nodeId: String,
    val domains: List<String> = emptyList(),
    val twoFactor: NodeTwoFactor? = null,
    /**
     * A token to spend instead of presenting credentials. Cleared once the
     * issued secret has landed in [twoFactor], so an endpoint never holds both.
     */
    val enrollment: NodeEnrollment? = null,
    /**
     * A full endpoint ticket: the Node ID plus the addresses it was printed
     * with. Kept apart from [nodeId], which stays the stable Endpoint ID this
     * endpoint is keyed by everywhere else (2FA, device keys, link readings).
     *
     * Present only when discovery is off, where a bare Node ID cannot be
     * resolved. It is a credential-like value, so [SettingsManager] seals it
     * into the backup-excluded preferences instead of writing it into the
     * endpoint list.
     *
     * Has a default and sits last so a payload written by an older build —
     * which has no such key — still decodes.
     */
    val ticket: String? = null
)
