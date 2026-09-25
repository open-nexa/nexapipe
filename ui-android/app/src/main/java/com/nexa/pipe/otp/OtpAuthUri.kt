package com.nexa.pipe.otp

import java.io.ByteArrayOutputStream
import java.util.Locale

/**
 * A TOTP configuration carried by an `otpauth://` URI.
 *
 * [digits] and [period] are reported for validation only: the native client
 * always derives 6-digit codes with a 30-second time step, so a QR code that
 * asks for anything else is imported with a warning instead of a rewritten
 * configuration.
 */
data class OtpAuthConfig(
    val clientId: String,
    val secret: String,
    val algorithm: String,
    val digits: Int,
    val period: Int,
    val issuer: String?,
    /** Non-fatal issues found while parsing, e.g. a non-standard period. */
    val warnings: List<String> = emptyList()
)

/** Outcome of [OtpAuth.parse]. */
sealed interface OtpAuthParseResult {
    /** A configuration that can be handed to the native client as-is. */
    data class Success(val config: OtpAuthConfig) : OtpAuthParseResult

    /** The scanned text is not a usable NexaPipe 2FA code; [message] says why. */
    data class Failure(val message: String) : OtpAuthParseResult
}

/**
 * Reads and writes the standard `otpauth://totp/...` URI format
 * ([Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)).
 *
 * Only TOTP is supported — the handshake implemented by the Rust client is
 * challenge/response over a time based one-time password, so a counter based
 * (`hotp`) URI cannot be used.
 *
 * The label is expected to carry the client ID, either alone (`client-001`) or
 * as the account part of the usual `Issuer:Account` pair
 * (`NexaPipe:client-001`), which is what [build] produces.
 */
object OtpAuth {
    const val SCHEME = "otpauth"
    const val ISSUER = "NexaPipe"
    const val DEFAULT_ALGORITHM = "sha1"
    const val DEFAULT_DIGITS = 6
    const val DEFAULT_PERIOD = 30

    /** Algorithms accepted by the native client. */
    private val SUPPORTED_ALGORITHMS = listOf("sha1", "sha256", "sha512")

    /** Base32 alphabet (RFC 4648) without padding. */
    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /**
     * Lengths modulo 8 that a valid unpadded Base32 string can have.
     * The other residues cannot be produced by the encoder, so they indicate a
     * truncated or mistyped secret.
     */
    private val VALID_BASE32_REMAINDERS = setOf(0, 2, 4, 5, 7)

    /** Parses a scanned QR code. Never throws. */
    fun parse(raw: String): OtpAuthParseResult {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return failure("The scanned code is empty")

        val schemeEnd = trimmed.indexOf("://")
        if (schemeEnd <= 0 || !trimmed.substring(0, schemeEnd).equals(SCHEME, ignoreCase = true)) {
            return failure("Not an $SCHEME:// QR code")
        }

        val rest = trimmed.substring(schemeEnd + 3)
        val queryStart = rest.indexOf('?')
        val target = if (queryStart >= 0) rest.substring(0, queryStart) else rest
        val query = if (queryStart >= 0) rest.substring(queryStart + 1).substringBefore('#') else ""

        val slash = target.indexOf('/')
        // Some generators keep the type in the authority and omit the label
        // entirely; that case is caught by the client ID check below.
        val type = if (slash >= 0) target.substring(0, slash) else target
        val label = if (slash >= 0) percentDecode(target.substring(slash + 1)).trim() else ""

        when (type.lowercase(Locale.ROOT)) {
            "totp" -> Unit
            "hotp" -> return failure("Counter based (HOTP) codes are not supported")
            else -> return failure("Unsupported code type \"$type\"; expected totp")
        }

        val params = parseQuery(query)

        val issuer = params["issuer"]?.trim()?.takeIf { it.isNotEmpty() }
        val clientId = clientIdFrom(label, issuer)
        if (clientId.isEmpty()) {
            return failure("The QR code does not contain a client ID")
        }

        val rawSecret = params["secret"].orEmpty()
        if (rawSecret.isBlank()) {
            return failure("The QR code does not contain a secret")
        }
        val secret = normalizeSecret(rawSecret)
            ?: return failure("The secret is not a valid Base32 string")

        val rawAlgorithm = params["algorithm"]?.trim().orEmpty()
        val algorithm =
            if (rawAlgorithm.isEmpty()) DEFAULT_ALGORITHM else rawAlgorithm.lowercase(Locale.ROOT)
        if (algorithm !in SUPPORTED_ALGORITHMS) {
            return failure("Unsupported algorithm \"$rawAlgorithm\"; expected SHA1, SHA256 or SHA512")
        }

        val digits = readInt(params["digits"], DEFAULT_DIGITS)
            ?: return failure("Invalid digits value \"${params["digits"]}\"")
        val period = readInt(params["period"], DEFAULT_PERIOD)
            ?: return failure("Invalid period value \"${params["period"]}\"")

        val warnings = buildList {
            if (digits != DEFAULT_DIGITS) {
                add("This code asks for $digits digits, but NexaPipe generates $DEFAULT_DIGITS.")
            }
            if (period != DEFAULT_PERIOD) {
                add("This code uses a $period-second step, but NexaPipe uses $DEFAULT_PERIOD seconds.")
            }
            if (secret.length % 8 !in VALID_BASE32_REMAINDERS) {
                add("The secret length (${secret.length} characters) looks unusual — double-check it against the server configuration.")
            }
        }

        return OtpAuthParseResult.Success(
            OtpAuthConfig(
                clientId = clientId,
                secret = secret,
                algorithm = algorithm,
                digits = digits,
                period = period,
                issuer = issuer,
                warnings = warnings
            )
        )
    }

    /**
     * Renders [clientId] / [secret] / [algorithm] as an `otpauth://` URI that
     * [parse] reads back unchanged (round trip), and that any authenticator app
     * can import as well.
     */
    fun build(clientId: String, secret: String, algorithm: String): String {
        val label = percentEncode("$ISSUER:${clientId.trim()}", keep = ":")
        val normalizedSecret = normalizeSecret(secret) ?: secret.filterNot { it.isWhitespace() }
        return buildString {
            append("$SCHEME://totp/").append(label)
            append("?secret=").append(normalizedSecret)
            append("&issuer=").append(percentEncode(ISSUER))
            append("&algorithm=").append(algorithm.trim().uppercase(Locale.ROOT))
            append("&digits=").append(DEFAULT_DIGITS)
            append("&period=").append(DEFAULT_PERIOD)
        }
    }

    /**
     * Normalizes a Base32 secret to the form the native client expects:
     * uppercase, whitespace and padding removed. Returns null when the secret
     * contains characters outside the Base32 alphabet.
     */
    fun normalizeSecret(raw: String): String? {
        val cleaned = raw.filterNot { it.isWhitespace() || it == '=' }.uppercase(Locale.ROOT)
        if (cleaned.isEmpty() || cleaned.any { it !in BASE32_ALPHABET }) return null
        return cleaned
    }

    /**
     * Derives the client ID from an `otpauth` label. Labels follow
     * `Issuer:Account`; when the label carries no issuer prefix the whole label
     * is the client ID. An explicit issuer that disagrees with the label's
     * prefix yields an empty ID — the caller turns that into a failure rather
     * than importing credentials under a label their issuer did not sign.
     */
    private fun clientIdFrom(label: String, issuer: String?): String {
        if (label.isEmpty()) return ""
        val colon = label.indexOf(':')
        if (colon < 0) return label.trim()
        if (issuer == null) {
            return label.substring(colon + 1).trim()
        }
        val prefix = label.substring(0, colon)
        return if (prefix.equals(issuer, ignoreCase = true)) {
            label.substring(colon + 1).trim()
        } else {
            ""
        }
    }

    private fun parseQuery(query: String): Map<String, String> {
        if (query.isEmpty()) return emptyMap()
        val params = mutableMapOf<String, String>()
        for (part in query.split('&')) {
            if (part.isEmpty()) continue
            val equals = part.indexOf('=')
            val key = percentDecode(if (equals >= 0) part.substring(0, equals) else part)
                .lowercase(Locale.ROOT)
            val value = if (equals >= 0) percentDecode(part.substring(equals + 1)) else ""
            // Keep the first occurrence, matching how authenticator apps behave
            // for duplicated parameters.
            if (key.isNotEmpty() && !params.containsKey(key)) params[key] = value
        }
        return params
    }

    private fun readInt(value: String?, fallback: Int): Int? {
        val trimmed = value?.trim().orEmpty()
        if (trimmed.isEmpty()) return fallback
        val parsed = trimmed.toIntOrNull() ?: return null
        return if (parsed > 0) parsed else null
    }

    private fun failure(message: String) = OtpAuthParseResult.Failure(message)

    /**
     * Percent-decodes [value]. Unlike [java.net.URLDecoder] a literal `+` is
     * kept as `+`, which is what URI semantics require.
     */
    private fun percentDecode(value: String): String {
        val bytes = ByteArrayOutputStream(value.length)
        var index = 0
        while (index < value.length) {
            val char = value[index]
            if (char == '%' && index + 3 <= value.length) {
                val code = value.substring(index + 1, index + 3).toIntOrNull(16)
                if (code != null) {
                    bytes.write(code)
                    index += 3
                    continue
                }
            }
            // Re-encode unescaped characters through UTF-8 so non-ASCII labels
            // survive the round trip.
            val encoded = char.toString().toByteArray(Charsets.UTF_8)
            bytes.write(encoded, 0, encoded.size)
            index++
        }
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }

    /**
     * Percent-encodes [value], leaving the unreserved set plus every character
     * in [keep] untouched. `:` is kept in labels because it separates the
     * issuer from the account name.
     */
    private fun percentEncode(value: String, keep: String = ""): String {
        val builder = StringBuilder()
        for (byte in value.toByteArray(Charsets.UTF_8)) {
            val unsigned = byte.toInt() and 0xFF
            val char = unsigned.toChar()
            val unreserved = char in 'a'..'z' || char in 'A'..'Z' || char in '0'..'9' ||
                char == '-' || char == '_' || char == '.' || char == '~'
            if (unreserved || keep.indexOf(char) >= 0) {
                builder.append(char)
            } else {
                builder.append('%').append(String.format(Locale.ROOT, "%02X", unsigned))
            }
        }
        return builder.toString()
    }
}
