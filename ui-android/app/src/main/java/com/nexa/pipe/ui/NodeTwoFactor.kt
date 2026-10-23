package com.nexa.pipe.ui

import kotlinx.serialization.Serializable

/**
 * The 2FA credentials of one endpoint.
 *
 * They belong to the endpoint, not to the app: every server keeps its own
 * `[auth].clients` table, so a second server either needs its own pair or has
 * to be handed the first one's secret. [secret] is only ever persisted in the
 * prefs file that backup excludes — see `SettingsManager`.
 */
@Serializable
data class NodeTwoFactor(
    val enabled: Boolean = true,
    val clientId: String = "",
    val secret: String = "",
    val algorithm: String = "sha1", // "sha1", "sha256", "sha512"
    /**
     * The device this credential was issued to, when the server said which.
     *
     * Null or blank means it is the client's shared secret rather than one
     * device's — what every pair saved before this existed is, and what the
     * field stays until the endpoint is enrolled under a name. The server
     * cannot revoke one device of a client through a credential nobody owns.
     */
    val device: String? = null,
    /**
     * The public half of this device's own key, when the credential is a key.
     *
     * Null for a credential that is a secret, and that is how the two are told
     * apart. The public half is not a secret — the server holds it too — so it
     * lives here, next to the credential it belongs to, and is shown so an
     * operator can tell which key a server has on file.
     *
     * The private half is the credential and never appears in this model: it is
     * sealed in the file backup excludes, and it is read from there when a
     * connection needs it. A model that is serialized into the backed-up
     * endpoint list is the wrong place for a half that must never leave the
     * device.
     */
    val publicKey: String? = null
)
