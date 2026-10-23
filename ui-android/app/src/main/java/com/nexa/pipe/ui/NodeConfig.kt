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
    val enrollment: NodeEnrollment? = null
)
