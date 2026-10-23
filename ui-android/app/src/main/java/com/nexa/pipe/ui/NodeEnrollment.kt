package com.nexa.pipe.ui

import kotlinx.serialization.Serializable

/**
 * A one-time enrollment token, in place of credentials.
 *
 * The token is spent by the first connection, which answers with the secret this
 * device then keeps — and rotates the one the server held, so a code that leaked
 * on its way here stops working the moment it is used.
 */
@Serializable
data class NodeEnrollment(
    val clientId: String = "",
    val token: String = ""
)
