package com.nexa.pipe.ui

/**
 * The credential a server issued for an enrollment token.
 *
 * A value rather than the handful of lines the native side hands over: the
 * rules about which of those lines are there — the device the server enrolled,
 * the public half of a device key — belong with the shape they describe.
 */
internal data class IssuedCredential(
    /** The client id the server enrolled the credential under. */
    val clientId: String,
    /** The shared secret, empty for a credential that is a key. */
    val secret: String,
    /** The algorithm of the secret: "sha1", "sha256" or "sha512". */
    val algorithm: String,
    /** The device the server enrolled, when it named one. */
    val device: String?,
    /** The public half of the device key, when the credential is a key. */
    val publicKey: String?
)

/**
 * Reads the answer the server gave to an enrollment token.
 *
 * The answer is a handful of lines: the client id, the secret and the
 * algorithm, then the device the server enrolled — when it names devices at
 * all — and the public half of the device key.
 *
 * Null when the answer is not one this app can read: fewer than three lines
 * is not a credential, and a credential that cannot be read is not one
 * either.
 */
internal fun parseIssuedCredential(encoded: String): IssuedCredential? {
    val parts = encoded.split("\n")
    if (parts.size < 3) return null
    return IssuedCredential(
        clientId = parts[0],
        secret = parts[1],
        algorithm = parts[2],
        // A fourth line names the device the server enrolled; it answers with
        // three when it does not name devices at all. Left null rather than
        // blank, because what it records is "no name was given" — the state
        // that leaves this pair indistinguishable from the client's shared
        // secret, and the one the page offers to re-enroll out of.
        device = parts.getOrNull(3)?.takeIf { it.isNotBlank() },
        // A fifth line carries the public half of a device key. It is what
        // tells a key credential from a secret one: a key answers with an
        // empty secret and an empty algorithm, and the half the server holds
        // is the only thing that says which key it is.
        publicKey = parts.getOrNull(4)?.takeIf { it.isNotBlank() }
    )
}
