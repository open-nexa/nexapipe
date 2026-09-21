package com.nexa.pipe.provisioning

import java.io.ByteArrayOutputStream
import java.net.URI
import java.util.Locale

/**
 * Where an invite points: either a stable Node ID, which needs discovery to
 * become an address, or a ticket that already carries addresses.
 */
sealed class InviteTarget {
    data class NodeId(val id: String) : InviteTarget()
    data class Ticket(val ticket: String) : InviteTarget()

    val value: String
        get() = when (this) {
            is NodeId -> id
            is Ticket -> ticket
        }

    val kind: String
        get() = when (this) {
            is NodeId -> "Node ID"
            is Ticket -> "ticket"
        }
}

/**
 * The 2FA half of an invite.
 *
 * The native client always derives 6-digit codes over a 30-second step, so
 * [digits] and [period] are reported (and warned about) rather than honored.
 */
data class InviteTotp(
    val issuer: String,
    val clientId: String,
    val secret: String,
    val algorithm: String,
    val digits: Int,
    val period: Int
)

/** A complete endpoint invitation. */
data class EndpointInvite(
    val target: InviteTarget,
    val name: String?,
    val domains: List<String>,
    val relay: String?,
    val totp: InviteTotp?
) {
    /** Non-fatal issues to surface right after an import. */
    fun warnings(): List<String> {
        val otp = totp ?: return emptyList()
        val digits = EndpointInviteCodec.DEFAULT_DIGITS
        val period = EndpointInviteCodec.DEFAULT_PERIOD
        return buildList {
            if (otp.digits != digits) {
                add("This invite asks for ${otp.digits} digits, but NexaPipe generates $digits.")
            }
            if (otp.period != period) {
                add("This invite uses a ${otp.period}-second step, but NexaPipe uses $period seconds.")
            }
        }
    }

    /** Renders the canonical `nexapipe://` link; [EndpointInviteCodec.parse] reads it back. */
    fun toUri(): String = EndpointInviteCodec.build(this)
}

/** Outcome of [EndpointInviteCodec.parse]. */
sealed interface InviteParseResult {
    data class Success(val invite: EndpointInvite) : InviteParseResult
    data class Failure(val message: String) : InviteParseResult
}

/**
 * Reads and writes `nexapipe://` endpoint invitations.
 *
 * ```text
 * nexapipe://endpoint/<node-id>?v=1&name=Home&domains=a.example,b.example
 *     &relay=https%3A%2F%2Frelay.example
 *     &client=client-001&issuer=NexaPipe&secret=JBSWY3DPEHPK3PXP
 *     &algorithm=SHA1&digits=6&period=30
 * ```
 *
 * `endpoint` carries a bare Node ID and `ticket` a full endpoint ticket; the
 * rest is shared. Values are percent encoded (everything outside the RFC 3986
 * unreserved set plus the list separator `,`), `+` stays literal, unknown
 * parameters are ignored so newer servers can extend the format, and a repeated
 * parameter keeps its first occurrence.
 *
 * This mirrors `nexapipe_client::provisioning` in the Rust client library; both
 * must accept and reject the same codes.
 */
object EndpointInviteCodec {
    const val SCHEME = "nexapipe"
    const val VERSION = 1
    const val NODE_ID_HOST = "endpoint"
    const val TICKET_HOST = "ticket"
    const val DEFAULT_ISSUER = "NexaPipe"
    const val DEFAULT_ALGORITHM = "sha1"
    const val DEFAULT_DIGITS = 6
    const val DEFAULT_PERIOD = 30

    /** Code length range the Rust client's `InviteTotp::with_params` enforces. */
    const val MIN_DIGITS = 6
    const val MAX_DIGITS = 8

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val SUPPORTED_ALGORITHMS = listOf("sha1", "sha256", "sha512")
    private val NODE_ID_PATTERN = Regex("[0-9a-fA-F]{64}")

    /** All iroh `RelayUrl` accepts is absolute http(s); ws/wss are the same servers. */
    private val RELAY_SCHEMES = setOf("http", "https", "ws", "wss")

    /** Parses a scanned or pasted invite. Never throws. */
    fun parse(raw: String): InviteParseResult {
        val trimmed = raw.trim()
        val prefix = "$SCHEME://"
        if (!trimmed.startsWith(prefix, ignoreCase = true)) {
            return failure("Not a $SCHEME:// invite code")
        }

        val body = trimmed.substring(prefix.length).substringBefore('#')
        val queryStart = body.indexOf('?')
        val path = if (queryStart >= 0) body.substring(0, queryStart) else body
        val query = if (queryStart >= 0) body.substring(queryStart + 1) else ""

        val slash = path.indexOf('/')
        val host = (if (slash >= 0) path.substring(0, slash) else path).trim()
        val rawValue = if (slash >= 0) path.substring(slash + 1) else ""
        // One empty segment is tolerated: links typed into a browser-like field
        // often come back as `.../<node-id>/?v=1`.
        val value = percentDecode(rawValue.trimEnd('/'))

        val target = when {
            host.equals(NODE_ID_HOST, ignoreCase = true) -> {
                if (!NODE_ID_PATTERN.matches(value)) {
                    return failure("\"$value\" is not a Node ID (64 hex characters)")
                }
                InviteTarget.NodeId(value.lowercase(Locale.ROOT))
            }
            host.equals(TICKET_HOST, ignoreCase = true) -> {
                if (value.isEmpty()) return failure("The invite carries no endpoint ticket")
                InviteTarget.Ticket(value)
            }
            else -> return failure("Unknown invite kind \"$host\"; expected endpoint or ticket")
        }

        val params = parseQuery(query)
        val version = params["v"]
        if (version != null) {
            val parsed = version.trim().toIntOrNull()
            if (parsed == null) {
                return failure("Invite version \"$version\" is not a number")
            }
            if (parsed != VERSION) {
                return failure("Unsupported invite version $parsed (this app understands $VERSION)")
            }
        }

        val domains = splitDomains(params["domains"] ?: "")?.let(::normalizeDomains)
            ?: return failure("The domain list contains an invalid entry")

        val relay = params["relay"]?.trim()?.takeIf { it.isNotEmpty() }?.also {
            if (!isValidRelayUrl(it)) {
                // "invalid" is part of the message on purpose: this is the same
                // wording the Rust half uses, and both test suites assert on it.
                return failure("The relay URL \"$it\" is invalid: it is not an http(s) URL")
            }
        }
        val name = params["name"]?.trim()?.takeIf { it.isNotEmpty() }

        val otp = parseTotp(params).getOrElse { return failure(it.message.orEmpty()) }
        return InviteParseResult.Success(
            EndpointInvite(
                target = target,
                name = name,
                domains = domains,
                relay = relay,
                totp = otp
            )
        )
    }

    /** Builds an invite link; [parse] reads it back unchanged. */
    fun build(invite: EndpointInvite): String {
        val params = mutableListOf("v" to VERSION.toString())
        invite.name?.takeIf { it.isNotBlank() }?.let { params += "name" to it }
        if (invite.domains.isNotEmpty()) params += "domains" to invite.domains.joinToString(",")
        invite.relay?.let { params += "relay" to it }
        invite.totp?.let { otp ->
            params += "client" to otp.clientId
            params += "issuer" to otp.issuer
            params += "secret" to otp.secret
            params += "algorithm" to otp.algorithm.uppercase(Locale.ROOT)
            params += "digits" to otp.digits.toString()
            params += "period" to otp.period.toString()
        }

        val query = params.joinToString("&") { (key, value) -> "$key=${percentEncode(value)}" }
        val host = when (invite.target) {
            is InviteTarget.NodeId -> NODE_ID_HOST
            is InviteTarget.Ticket -> TICKET_HOST
        }
        return "$SCHEME://$host/${percentEncode(invite.target.value)}?$query"
    }

    /**
     * Reads the 2FA block, if the invite has one.
     *
     * The failure variant carries the message to show, which is why the result
     * is a [Result] rather than a nullable value.
     */
    private fun parseTotp(params: Map<String, String>): Result<InviteTotp?> {
        val secret = params["secret"]
        if (secret == null) {
            // A nested otpauth:// URI is the interop form: it carries the same
            // fields under their standard names.
            val embedded = params["otpauth"]
                ?: return if (listOf("client", "issuer", "algorithm", "digits", "period").any { it in params }) {
                    Result.failure(invalid("The invite carries 2FA parameters but no secret"))
                } else {
                    Result.success(null)
                }
            return parseEmbeddedOtpauth(embedded)
        }
        if (params["client"].isNullOrBlank()) {
            return Result.failure(invalid("The invite carries a 2FA secret but no client id"))
        }

        val algorithm = params["algorithm"]?.trim().orEmpty().ifEmpty { DEFAULT_ALGORITHM }
        if (algorithm.lowercase(Locale.ROOT) !in SUPPORTED_ALGORITHMS) {
            return Result.failure(
                invalid("Unsupported algorithm \"${params["algorithm"]}\"; expected SHA1, SHA256 or SHA512")
            )
        }
        val normalized = normalizeSecret(secret)
            ?: return Result.failure(invalid("The 2FA secret is not a valid Base32 string"))
        val digits = readInt(params["digits"], DEFAULT_DIGITS)
            ?: return Result.failure(invalid("Invalid digits value \"${params["digits"]}\""))
        if (digits !in MIN_DIGITS..MAX_DIGITS) {
            return Result.failure(
                invalid("This invite asks for $digits digits per code, but only $MIN_DIGITS to $MAX_DIGITS are supported")
            )
        }
        val period = readInt(params["period"], DEFAULT_PERIOD)
            ?: return Result.failure(invalid("Invalid period value \"${params["period"]}\""))

        return Result.success(
            InviteTotp(
                issuer = params["issuer"]?.trim()?.takeIf { it.isNotEmpty() } ?: DEFAULT_ISSUER,
                clientId = params["client"]!!.trim(),
                secret = normalized,
                algorithm = algorithm.lowercase(Locale.ROOT),
                digits = digits,
                period = period
            )
        )
    }

    private fun invalid(message: String) = IllegalArgumentException(message)

    /**
     * A relay must be an absolute `http(s)` URL with a host — anything else is
     * rejected by iroh's `RelayUrl` at connect time, so it is rejected here
     * with a message instead of a silent failure. `URI` (not `URL`) because
     * the `URL` constructor has no handlers for `ws`/`wss`.
     */
    private fun isValidRelayUrl(raw: String): Boolean {
        val uri = runCatching { URI(raw) }.getOrNull() ?: return false
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return false
        if (scheme !in RELAY_SCHEMES) return false
        return !uri.host.isNullOrBlank()
    }

    private fun parseEmbeddedOtpauth(uri: String): Result<InviteTotp?> {
        val trimmed = uri.trim()
        val prefix = "otpauth://"
        if (!trimmed.startsWith(prefix, ignoreCase = true)) {
            return Result.failure(invalid("The embedded otpauth parameter is not an otpauth:// URI"))
        }
        val rest = trimmed.substring(prefix.length)
        val queryStart = rest.indexOf('?')
        val path = if (queryStart >= 0) rest.substring(0, queryStart) else rest
        val query = if (queryStart >= 0) rest.substring(queryStart + 1) else ""

        // `otpauth://totp/Issuer:client?...` — the type segment sits in front
        // of the label.
        val label = percentDecode(path.substringAfterLast('/'))
        val (labelIssuer, clientId) = label.indexOf(':').let { colon ->
            if (colon >= 0) {
                label.substring(0, colon).trim() to label.substring(colon + 1).trim()
            } else {
                null to label.trim()
            }
        }
        if (clientId.isEmpty()) {
            return Result.failure(invalid("The embedded otpauth:// URI does not contain a client id"))
        }

        val params = parseQuery(query)
        val secret = params["secret"]
            ?: return Result.failure(invalid("The embedded otpauth:// URI carries no secret"))
        return parseTotp(
            mapOf(
                "client" to clientId,
                "issuer" to (labelIssuer?.takeIf { it.isNotEmpty() }
                    ?: params["issuer"]?.takeIf { it.isNotBlank() }
                    ?: DEFAULT_ISSUER),
                "secret" to secret,
                "algorithm" to params["algorithm"].orEmpty(),
                "digits" to params["digits"].orEmpty(),
                "period" to params["period"].orEmpty()
            )
        )
    }

    /** Returns null when the list is malformed: an empty entry means a mistyped code. */
    private fun splitDomains(raw: String): List<String>? {
        if (raw.isBlank()) return emptyList()
        val parts = raw.split(',')
        if (parts.any { it.trim().isEmpty() }) return null
        return parts.map { it.trim() }
    }

    /** Returns null when any entry is not a bare hostname. */
    private fun normalizeDomains(domains: List<String>): List<String>? {
        val out = LinkedHashSet<String>()
        for (raw in domains) {
            val domain = raw.trim().trimEnd('.').lowercase(Locale.ROOT)
            if (domain.isEmpty()) return null
            if (domain.any { it.isWhitespace() || it == '/' || it == '?' || it == '#' }) return null
            out += domain
        }
        return out.toList()
    }

    /** Uppercase Base32 without padding, or null when the input is not Base32. */
    private fun normalizeSecret(raw: String): String? {
        val cleaned = raw.filterNot { it.isWhitespace() || it == '=' }.uppercase(Locale.ROOT)
        if (cleaned.isEmpty() || cleaned.length < 8) return null
        if (cleaned.any { it !in BASE32_ALPHABET }) return null
        return cleaned
    }

    private fun readInt(value: String?, fallback: Int): Int? {
        val trimmed = value?.trim().orEmpty()
        if (trimmed.isEmpty()) return fallback
        val parsed = trimmed.toIntOrNull() ?: return null
        return if (parsed > 0) parsed else null
    }

    private fun parseQuery(query: String): Map<String, String> {
        if (query.isEmpty()) return emptyMap()
        val params = mutableMapOf<String, String>()
        for (part in query.split('&')) {
            if (part.isEmpty()) continue
            val equals = part.indexOf('=')
            val key = percentDecode(if (equals >= 0) part.substring(0, equals) else part)
                .lowercase(Locale.ROOT)
            if (key.isEmpty()) continue
            val value = if (equals >= 0) percentDecode(part.substring(equals + 1)) else ""
            // First occurrence wins, as in the Rust parser.
            if (!params.containsKey(key)) params[key] = value
        }
        return params
    }

    /** Keeps the unreserved characters plus the list separator readable. */
    private fun percentEncode(value: String): String {
        val out = StringBuilder(value.length)
        for (byte in value.toByteArray(Charsets.UTF_8)) {
            val char = byte.toInt().toChar()
            val keep = char.isLetterOrDigit() || char == '-' || char == '.' || char == '_' ||
                char == '~' || char == ','
            if (keep) out.append(char) else out.append('%').append(String.format("%02X", byte.toInt() and 0xFF))
        }
        return out.toString()
    }

    /** The inverse of [percentEncode]; `+` stays literal. */
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
            val encoded = char.toString().toByteArray(Charsets.UTF_8)
            bytes.write(encoded, 0, encoded.size)
            index++
        }
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }

    private fun failure(message: String) = InviteParseResult.Failure(message)
}
