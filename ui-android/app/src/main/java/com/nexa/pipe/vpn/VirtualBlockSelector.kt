package com.nexa.pipe.vpn

/**
 * Picks the block the tunnel claims.
 *
 * The policy is the desktop's: walk the candidate blocks in order and keep the
 * first one that nothing else on the device has claimed. A block that overlaps
 * the network the phone is on breaks routing in ways that look like "the
 * internet died" — the device can no longer reach the router that is serving
 * it, and the router cannot answer the queries the tunnel hands out.
 *
 * The candidates live in the native side, so both clients walk the same list.
 *
 * Pure on purpose: it is the part of this behaviour that can be unit tested
 * without a ConnectivityManager.
 */
object VirtualBlockSelector {
    /**
     * A prefix length below which a route is not a claim on a block.
     *
     * A route this wide is a way of taking the default route rather than a
     * claim on an address range: a VPN installs `0.0.0.0/1` and `128.0.0.0/1`
     * to sit in front of every destination without replacing the default route
     * itself. Our /24 is more specific than either, so the two coexist —
     * counting those would disqualify every candidate on such a device.
     */
    const val CLAIM_PREFIX_FLOOR = 8

    /** The range fake-IP tools hand their addresses out of: 198.18.0.0/15. */
    private const val FAKE_IP_BASE = 0xC6120000L

    /** The length of the fake-IP range. */
    private const val FAKE_IP_LENGTH = 15

    /**
     * A prefix something else on the device has claimed.
     *
     * [address] is the prefix's network address and [length] how wide it is.
     */
    data class Prefix(val address: Long, val length: Int) {
        /** Whether this prefix and a block of [blockLength] overlap. */
        fun overlaps(block: Long, blockLength: Int = 24): Boolean =
            Ipv4.overlaps(address, length, block, blockLength)
    }

    /** What the policy decided, and what it passed over on the way. */
    data class Evaluation(
        /** The block in use, or null when every candidate was taken. */
        val base: Long?,
        /** One line per candidate that was not taken. */
        val skipped: List<String>,
    )

    /**
     * The first candidate nothing else has claimed, or null when every one of
     * them is taken.
     *
     * [held] are the addresses the device's interfaces hold and [routed] the
     * prefixes its routes claim. A route too wide to be a claim on a block —
     * the default route and the two halves a VPN installs in front of it — does
     * not count.
     */
    fun choose(
        candidates: List<Long>,
        held: List<Prefix>,
        routed: List<Prefix>,
    ): Long? = evaluate(candidates, held, routed).base

    /** The same decision as [choose], with the reasons the log wants. */
    fun evaluate(
        candidates: List<Long>,
        held: List<Prefix>,
        routed: List<Prefix>,
    ): Evaluation {
        // A fake-IP tool (Clash/mihomo &co) hands out addresses across
        // 198.18.0.0/15 while its own interface holds only a sliver of it, so
        // one address in the range disqualifies both of its halves.
        val fakeIpClaimed = held.any { it.overlaps(FAKE_IP_BASE, FAKE_IP_LENGTH) }
        val skipped = mutableListOf<String>()

        for (base in candidates) {
            val inFakeIpRange = Ipv4.overlaps(base, 24, FAKE_IP_BASE, FAKE_IP_LENGTH)
            if (fakeIpClaimed && inFakeIpRange) {
                skipped += "${Ipv4.format(base)}/24: another interface holds an address in " +
                    "198.18.0.0/15 — a fake-IP tool owns that range"
                continue
            }

            val holder = held.firstOrNull { it.overlaps(base) }
            if (holder != null) {
                skipped += "${Ipv4.format(base)}/24: another interface already holds an " +
                    "address in it"
                continue
            }

            val route = routed.firstOrNull {
                it.length >= CLAIM_PREFIX_FLOOR && it.overlaps(base)
            }
            if (route != null) {
                skipped += "${Ipv4.format(base)}/24: ${Ipv4.format(route.address)}/" +
                    "${route.length} is already routed to another interface"
                continue
            }

            return Evaluation(base, skipped)
        }

        return Evaluation(null, skipped)
    }
}
