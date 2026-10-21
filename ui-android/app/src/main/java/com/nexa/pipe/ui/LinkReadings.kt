package com.nexa.pipe.ui

/**
 * What the tunnel reports about each backend: the kind of path carrying its traffic, and how
 * far away that path is.
 *
 * One value rather than two flows, because the two come from one answer: a UI that saw a new
 * kind beside an old latency would be showing a reading of a path that no longer exists.
 *
 * Both maps are keyed by endpoint ID, the same key the native side reports.
 */
data class LinkReadings(
    /** Path kind per backend: direct, relay, or unknown while nothing is selected. */
    val kinds: Map<String, LinkKind> = emptyMap(),
    /**
     * Round-trip time per backend, in milliseconds. A backend iroh has no sample for is
     * absent — which is not a round trip of zero.
     */
    val rtts: Map<String, Long> = emptyMap(),
)

/**
 * Reads the answer the native side sends: one `<endpointId>=<kind>/<rttMs>` entry per backend,
 * joined with `;`.
 *
 * Both halves of an entry are optional in the sense that a missing one is not a failure: a
 * backend whose path has not been measured yet has no latency, and the old shape — a kind on
 * its own — still reads. What must not happen is an absent latency turning into a zero, which
 * a UI would draw as a measurement.
 */
fun parseLinkReadings(raw: String): LinkReadings {
    val kinds = linkedMapOf<String, LinkKind>()
    val rtts = linkedMapOf<String, Long>()
    for (entry in raw.split(";")) {
        val separator = entry.indexOf('=')
        if (separator <= 0) continue
        val id = entry.substring(0, separator)
        val value = entry.substring(separator + 1)
        val slash = value.indexOf('/')
        val kind = if (slash < 0) value else value.substring(0, slash)
        kinds[id] = when (kind) {
            "direct" -> LinkKind.DIRECT
            "relay" -> LinkKind.RELAY
            else -> LinkKind.UNKNOWN
        }
        if (slash >= 0) {
            value.substring(slash + 1).toLongOrNull()?.let { rtts[id] = it }
        }
    }
    return LinkReadings(kinds, rtts)
}

/**
 * The link type of [nodeId] in the map the ViewModel publishes, or null when it says nothing
 * about that backend.
 *
 * Callers must read this from a *collected* map, not from `StateFlow.value`, or the UI will
 * never recompose when the link changes. The case-insensitive fallback costs nothing at this
 * size and covers an endpoint ID that came back in a different case than the one configured.
 */
fun linkKindOf(kinds: Map<String, LinkKind>, nodeId: String): LinkKind? =
    kinds[nodeId]
        ?: kinds.entries.firstOrNull { it.key.equals(nodeId, ignoreCase = true) }?.value

/**
 * The round-trip time of the path to [nodeId] in milliseconds, or null when iroh has no sample
 * for that backend.
 *
 * Null is not zero: a path that has just opened has no measurement yet, and a UI that drew "0 ms"
 * would be claiming a measurement it does not have.
 *
 * The lookup is the same as [linkKindOf]'s, including the case-insensitive fallback.
 */
fun linkRttOf(rtts: Map<String, Long>, nodeId: String): Long? =
    rtts[nodeId]
        ?: rtts.entries.firstOrNull { it.key.equals(nodeId, ignoreCase = true) }?.value
