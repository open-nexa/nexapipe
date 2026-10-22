package com.nexa.pipe

/**
 * What to do with a relay token an older version left in the backed-up
 * preferences.
 *
 * Split out of the migration so the decision can be tested without a device:
 * what happens to a credential is worth more than a line of bookkeeping.
 */
sealed interface RelayTokenMove {
    /**
     * There is no token — the value saved whenever a relay needs none.
     *
     * Not a credential, so nothing is written anywhere; the key is only
     * removed, so the file does not carry one that looks like a credential.
     */
    data object None : RelayTokenMove

    /** The token moves into the secrets file, sealed. */
    data class Move(val sealed: String) : RelayTokenMove

    /**
     * The token cannot be sealed on this device, so it stays where it is.
     *
     * The alternative is writing it in the clear into the file whose whole
     * point is that it holds ciphertext — and it is removed from the file it
     * came out of only once the sealed copy is written, so the value is never
     * lost.
     */
    data object Keep : RelayTokenMove
}

/**
 * Decides what happens to a relay token on the way out of the backed-up
 * preferences.
 *
 * `seal` returns null when this device cannot seal the value, which is the
 * question the decision turns on: a token that cannot be sealed moves
 * nowhere.
 */
internal fun relayTokenMove(
    token: String,
    seal: (String) -> String?
): RelayTokenMove = when {
    token.isBlank() -> RelayTokenMove.None
    else -> seal(token)?.let { RelayTokenMove.Move(it) } ?: RelayTokenMove.Keep
}
