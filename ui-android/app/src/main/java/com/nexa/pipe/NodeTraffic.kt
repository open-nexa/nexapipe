package com.nexa.pipe

import java.util.Locale

/*
 * Per-backend traffic counters, and how to read them out of the native answer.
 *
 * Shared by the two places that show them — the endpoint list on the main screen and the
 * foreground notification — so the encoding is decoded once and both sides quote the same
 * numbers in the same units.
 */

private const val KIBIBYTE = 1024L
private const val MEBIBYTE = KIBIBYTE * 1024L
private const val GIBIBYTE = MEBIBYTE * 1024L

/**
 * What one backend has carried since the proxy was started, as `IrohProxy.nativeTraffic()`
 * reports it.
 *
 * [sent] and [received] are cumulative byte counts, not rates: anything that wants a rate has
 * to sample twice and divide by the time between the samples. [active] is the number of flows
 * open to that backend at the moment of the read, so it does not need two samples to mean
 * anything.
 */
data class NodeTraffic(
    val sent: Long,
    val received: Long,
    val active: Long,
)

/**
 * Decodes `id=sent/received/active;id2=...` — the format the native side writes, and the same
 * entry shape `IrohProxy.nativeLinkKinds()` uses, so both are read the same way.
 *
 * An entry that does not decode is dropped rather than read as zeroes: the native side leaves
 * out a node it has carried nothing for, and a zero invented here would be indistinguishable
 * from a real one — which is exactly the difference the caller has to be able to see.
 */
fun parseNodeTraffic(raw: String): Map<String, NodeTraffic> {
    val parsed = linkedMapOf<String, NodeTraffic>()
    for (entry in raw.split(";")) {
        val separator = entry.indexOf('=')
        if (separator <= 0) continue
        val values = entry.substring(separator + 1).split("/")
        if (values.size != 3) continue
        val sent = values[0].toLongOrNull() ?: continue
        val received = values[1].toLongOrNull() ?: continue
        val active = values[2].toLongOrNull() ?: continue
        parsed[entry.substring(0, separator)] = NodeTraffic(sent, received, active)
    }
    return parsed
}

/**
 * The counters of [nodeId] in a decoded map, or null when the map says nothing about it.
 *
 * Callers must read this from a *collected* map, not from `StateFlow.value`, or the UI will
 * never recompose. The case-insensitive fallback costs nothing at this size and covers an
 * endpoint ID that came back in a different case than the one configured.
 */
fun nodeTrafficOf(traffic: Map<String, NodeTraffic>, nodeId: String): NodeTraffic? =
    traffic[nodeId]
        ?: traffic.entries.firstOrNull { it.key.equals(nodeId, ignoreCase = true) }?.value

/**
 * Renders a byte count the way a transfer is usually quoted: binary units, one decimal, and
 * no unit below 1 KiB so a small transfer is not rounded to "0.0 KiB" and read as broken.
 */
fun formatByteCount(bytes: Long): String {
    val value = if (bytes < 0) 0L else bytes
    return when {
        value < KIBIBYTE -> "$value B"
        value < MEBIBYTE -> String.format(Locale.US, "%.1f KiB", value.toFloat() / KIBIBYTE)
        value < GIBIBYTE -> String.format(Locale.US, "%.1f MiB", value.toFloat() / MEBIBYTE)
        else -> String.format(Locale.US, "%.2f GiB", value.toFloat() / GIBIBYTE)
    }
}

/** [formatByteCount] with the per-second mark, for a rate rather than a total. */
fun formatByteRate(bytesPerSecond: Long): String = "${formatByteCount(bytesPerSecond)}/s"
