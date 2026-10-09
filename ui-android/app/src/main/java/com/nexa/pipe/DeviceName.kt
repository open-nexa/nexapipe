package com.nexa.pipe

import java.security.SecureRandom

/**
 * The name this install answers as when it authenticates.
 *
 * A server hands out credentials per client, and every device holding one
 * answers with the same pair. A name is what lets the server tell them apart,
 * and is therefore what makes it possible to revoke one without locking out the
 * rest: without one the only thing on the wire is the shared secret, which is
 * the one credential there is no device-level answer to.
 *
 * Pure on purpose, apart from the random tag: the shape it produces is
 * enforced again on the server, so it is worth being able to pin here.
 */
internal object DeviceName {
    /** The longest name a server accepts. */
    const val MAX = 255

    /** Fallback for a device that will not say what it is. */
    const val FALLBACK = "nexa"

    // Eight hex characters, which is what goes after the model.
    private const val TAG_CHARS = 8
    private val RANDOM = SecureRandom()

    /**
     * A name for a device that reports [model].
     *
     * The model comes from `Build.MODEL`, which is free-form — "Pixel 9 Pro",
     * "SM-S921B", and on some devices nothing at all — so it goes through
     * [sanitize] and a random tag is put behind it: plenty of phones share a
     * model, and a name that collides is a name that cannot be revoked for one
     * of the devices carrying it.
     *
     * The tag is random rather than read off the device, because there is no
     * identifier available to this app that is not either a credential of its
     * own — which would put something worth stealing on every handshake — or a
     * different value after a reinstall.
     */
    fun generate(model: String): String {
        val name = sanitize(model).ifEmpty { FALLBACK }
        return "$name-${tag()}".take(MAX)
    }

    /**
     * A model name, made into something a server will accept.
     *
     * Printable ASCII with the space excluded, because the name ends up as a
     * key in the server's config and in the log line for every handshake.
     * Spaces become dashes rather than being dropped, so "Pixel 9 Pro" still
     * reads as three words.
     */
    fun sanitize(raw: String): String {
        val printable = raw.trim()
            .replace(Regex("\\s+"), "-")
            .filter { it.code in 0x21..0x7e }
        // Room has to be left for the tag that follows, or a long model name
        // would be cut mid-name and the tag lost with it — and the tag is the
        // part that keeps two identical phones apart.
        return printable.trim('-').take(MAX - TAG_CHARS - 1)
    }

    /** A tag long enough that two identical phones do not collide on name. */
    private fun tag(): String {
        val bytes = ByteArray(TAG_CHARS / 2)
        RANDOM.nextBytes(bytes)
        return bytes.joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }
}
