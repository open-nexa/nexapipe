package com.nexa.pipe.vpn

/**
 * The addresses inside the block the tunnel claims.
 *
 * The block is a /24 the TUN claims for itself, and everything inside it
 * follows from it: the interface address, the DNS server the system resolver is
 * pointed at, the legacy proxy address, and the IPv6 half the VPN routes for
 * itself.
 *
 * The addresses come from the native side, which is where they are handed out
 * from: the per-domain addresses Rust gives the resolver live in the same
 * block, and a Kotlin side that derived them on its own would be free to
 * disagree with it — which is a tunnel that comes up and carries nothing.
 */
data class VirtualBlock(
    /** The block's network address, e.g. `198.18.0.0`. */
    val base: String,
    /** The block in CIDR form, e.g. `198.18.0.0/24`. */
    val network: String,
    /** The TUN interface's own address, e.g. `198.18.0.1`. */
    val interfaceIp: String,
    /** The DNS server the system resolver is pointed at, e.g. `198.18.0.2`. */
    val dnsIp: String,
    /** The legacy virtual proxy address, e.g. `198.18.0.3`. */
    val legacyProxyIp: String,
    /** The IPv6 half of the block, e.g. `fd00:198:18:0::`. */
    val ipv6Network: String,
    /** The TUN interface's IPv6 address, e.g. `fd00:198:18:0::1`. */
    val ipv6InterfaceIp: String,
) {
    companion object {
        /**
         * Reads the answer the native side sends: `key=value` pairs joined by `;`.
         *
         * Returns null when a key is missing or empty. A half-read block would
         * configure the VPN with an address the tunnel does not use, which is
         * worse than not starting at all.
         */
        fun parse(encoded: String): VirtualBlock? {
            val fields = encoded.split(';').mapNotNull { field ->
                val key = field.substringBefore('=')
                val value = field.substringAfter('=', "")
                if (key.isEmpty() || value.isEmpty()) null else key to value
            }.toMap()

            return VirtualBlock(
                base = fields["base"] ?: return null,
                network = fields["network"] ?: return null,
                interfaceIp = fields["interface"] ?: return null,
                dnsIp = fields["dns"] ?: return null,
                legacyProxyIp = fields["proxy"] ?: return null,
                ipv6Network = fields["ipv6"] ?: return null,
                ipv6InterfaceIp = fields["ipv6Interface"] ?: return null,
            )
        }
    }
}

/**
 * An IPv4 address as the 32-bit number it is written as.
 *
 * The block policy compares addresses with masks, and numbers are easier to
 * compare than strings: a prefix is a number and a length, and two of them
 * overlap when the shorter prefix's mask says so.
 */
object Ipv4 {
    /**
     * The mask of the leading `length` bits.
     *
     * The result is masked down to 32 bits: a Long shift keeps the bits that
     * fell off the top of the address, and a mask that still carries them
     * would compare two addresses by their high bits as well.
     */
    fun mask(length: Int): Long = when {
        length <= 0 -> 0L
        length >= 32 -> 0xFFFF_FFFFL
        else -> (0xFFFF_FFFFL shl (32 - length)) and 0xFFFF_FFFFL
    }

    /**
     * Whether two prefixes overlap, decided on the shorter of the two.
     *
     * A /16 somebody else routes swallows the whole of a /24 inside it, and a
     * /32 inside the block claims only its own address — which is still
     * enough, because it is an address the block would have to stay silent
     * about.
     */
    fun overlaps(a: Long, aLength: Int, b: Long, bLength: Int): Boolean {
        val shared = minOf(aLength, bLength)
        val mask = mask(shared)
        return (a and mask) == (b and mask)
    }

    /**
     * Reads `198.18.0.0` as the number it is written as.
     *
     * Returns null for anything that is not four octets: a block that cannot be
     * read is a block that cannot be used, and a caller that guessed would be
     * guessing about the addresses the tunnel claims.
     */
    fun parse(text: String): Long? {
        val octets = text.trim().split('.')
        if (octets.size != 4) return null
        var bits = 0L
        for (octet in octets) {
            val value = octet.toIntOrNull() ?: return null
            if (value !in 0..255) return null
            bits = (bits shl 8) or value.toLong()
        }
        return bits
    }

    /** Writes the number back as `198.18.0.0`. */
    fun format(bits: Long): String =
        listOf(24, 16, 8, 0).joinToString(".") { ((bits shr it) and 0xFF).toString() }
}
