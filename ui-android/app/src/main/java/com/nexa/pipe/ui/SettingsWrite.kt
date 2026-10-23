package com.nexa.pipe.ui

/**
 * One settings write, captured whole at the moment it was asked for.
 *
 * A snapshot rather than a re-read on the far side of the queue: this is
 * called between two keystrokes, and a write that re-read the state when
 * it finally ran would store whatever the field held by then rather than
 * what the user typed.
 */
internal data class SettingsWrite(
    val nodes: List<NodeConfig>,
    val relayMode: String,
    val relayUrl: String,
    val relayToken: String,
    val discoveryMode: String,
    /**
     * Set when the user has just answered the consent question, so the
     * re-queued write is the one thing allowed to store a credential in the
     * clear. Carried on the write rather than read from the ViewModel at
     * the moment it runs, because the answer and the write it applies to
     * have to be the same one.
     */
    val allowPlaintextOverride: Boolean = false
)

/**
 * Whether writing these settings would put a credential on disk.
 */
internal fun SettingsWrite.carriesCredential(): Boolean =
    nodes.any {
        !it.enrollment?.token.isNullOrBlank() || !it.twoFactor?.secret.isNullOrBlank()
    } || relayToken.isNotBlank()
