package com.httpfreekit.protocol

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.time.format.ResolverStyle
import java.util.Base64
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

/** Draft 0.4 syntax/profile-shape codec only. No enrollment authorization, clock or I/O. */
object DraftEnrollmentCodec {
    const val MAX_BODY_BYTES = 16384
    private val json = Json { isLenient = false }
    private val schemas = mapOf(
        "pair" to "desktopId invitationId invitationSecret csrDer deviceName capabilities",
        "pair_challenge_request" to "desktopId invitationId enrollmentId purpose",
        "pair_status" to "desktopId invitationId enrollmentId challengeId signature",
        "pair_cancel" to "desktopId invitationId enrollmentId challengeId signature",
        "pair_registered" to "desktopId invitationId enrollmentId deviceSpkiSha256 reservationExpiresAt resultExpiresAt",
        "pair_challenge_response" to "desktopId gatewaySpkiSha256 invitationId enrollmentId challengeId deviceSpkiSha256 purpose nonce expiresAt",
        "pair_pending" to "desktopId enrollmentId reservationExpiresAt retryAfterMillis",
        "pair_approved" to "desktopId enrollmentId deviceId clientCertificateDer enrollmentAuthorityDer interceptionCaCertificateSha256 capabilities credentialExpiresAt resultExpiresAt",
        "pair_ended" to "desktopId enrollmentId code", "pair_error" to "code",
    )
    private val errorCodes = setOf("invalid_message", "message_too_large", "unsupported_version", "unsupported_capability",
        "authentication_failed", "invitation_expired", "invitation_used", "pairing_limit", "pairing_unavailable")
    private val endedCodes = setOf("pairing_rejected", "pairing_cancelled", "invitation_expired", "device_revoked", "credential_expired", "result_expired")

    fun decode(channel: DraftEnrollmentChannel, bytes: ByteArray): DraftEnrollmentDecodeResult {
        if (bytes.size > MAX_BODY_BYTES) return DraftEnrollmentDecodeResult.Rejected("message_too_large")
        return try {
            require(bytes.isNotEmpty())
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            require(!text.startsWith('\uFEFF'))
            Guard(text).check()
            val root = json.parseToJsonElement(text) as? JsonObject ?: invalid()
            val version = root.integer("protocolVersion")
            require(version in 1..Int.MAX_VALUE.toLong())
            if (version != 1L) return DraftEnrollmentDecodeResult.Rejected("unsupported_version")
            val type = root.string("type")
            val schema = schema(channel, type)
            val names = listOf("protocolVersion", "type") + schemas.getValue(schema).split(' ')
            require(root.keys == names.toSet())
            root.forEach { (key, _) -> when (key) {
                "desktopId", "invitationId" -> DraftEnrollmentChecks.id(root.string(key))
                "enrollmentId" -> DraftEnrollmentChecks.branded(root.string(key), "enr_")
                "challengeId" -> DraftEnrollmentChecks.branded(root.string(key), "ech_")
                "deviceId" -> DraftEnrollmentChecks.branded(root.string(key), "dev_")
                "invitationSecret", "deviceSpkiSha256", "gatewaySpkiSha256", "nonce", "interceptionCaCertificateSha256" -> DraftEnrollmentChecks.binary(root.string(key), 32, 32)
                "csrDer", "clientCertificateDer", "enrollmentAuthorityDer" -> DraftEnrollmentChecks.binary(root.string(key), 1, 4096)
                "signature" -> signature(root.string(key))
                "deviceName" -> deviceName(root.string(key))
                "capabilities" -> capabilities(root[key])
                "purpose" -> require(root.string(key) in setOf("status", "cancel"))
                "reservationExpiresAt", "resultExpiresAt", "expiresAt", "credentialExpiresAt" -> DraftEnrollmentChecks.date(root.string(key))
                "retryAfterMillis" -> require(root.integer(key) == 1000L)
                "code" -> require(root.string(key) in if (type == "pair_error") errorCodes else endedCodes)
            } }
            // Snapshot into canonical field order; no caller-owned tree/collection is retained.
            val fields = JsonObject(names.associateWith { root.getValue(it) })
            DraftEnrollmentDecodeResult.Accepted(when (schema) {
                "pair" -> DraftEnrollmentMessage.Pair(fields)
                "pair_challenge_request" -> DraftEnrollmentMessage.ChallengeRequest(fields)
                "pair_status" -> DraftEnrollmentMessage.StatusRequest(fields)
                "pair_cancel" -> DraftEnrollmentMessage.CancelRequest(fields)
                "pair_registered" -> DraftEnrollmentMessage.Registered(fields)
                "pair_challenge_response" -> DraftEnrollmentMessage.Challenge(fields)
                "pair_pending" -> DraftEnrollmentMessage.Pending(fields)
                "pair_approved" -> DraftEnrollmentMessage.Approved(fields)
                "pair_ended" -> DraftEnrollmentMessage.Ended(channel, fields)
                else -> DraftEnrollmentMessage.Error(channel, fields)
            })
        } catch (_: IllegalArgumentException) { DraftEnrollmentDecodeResult.Rejected("invalid_message") }
        catch (_: java.nio.charset.CharacterCodingException) { DraftEnrollmentDecodeResult.Rejected("invalid_message") }
        catch (_: java.time.DateTimeException) { DraftEnrollmentDecodeResult.Rejected("invalid_message") }
        catch (_: SerializationException) { DraftEnrollmentDecodeResult.Rejected("invalid_message") }
    }

    fun message(channel: DraftEnrollmentChannel, material: Map<String, *>): DraftEnrollmentMessage = fixed {
        var stringBytes = 0
        fun value(input: Any?, depth: Int): JsonElement {
            return when (input) {
                null -> JsonNull
                is String -> { require(input.length <= MAX_BODY_BYTES); DraftEnrollmentChecks.unicode(input)
                    stringBytes += input.toByteArray(Charsets.UTF_8).size; require(stringBytes <= MAX_BODY_BYTES); JsonPrimitive(input) }
                is Int -> JsonPrimitive(input)
                is Long -> JsonPrimitive(input)
                is Boolean -> JsonPrimitive(input)
                is Map<*, *> -> { require(depth <= 3 && input.size in 0..16)
                    val fields = linkedMapOf<String, JsonElement>()
                    var count = 0
                    for (entry in input.entries) {
                        require(++count <= 16)
                        val key = entry.key as? String ?: invalid()
                        require(key !in fields); value(key, depth + 1)
                        fields[key] = value(entry.value, depth + 1)
                    }
                    JsonObject(fields) }
                is List<*> -> { require(depth <= 3 && input.size in 0..16)
                    val elements = ArrayList<JsonElement>(); for (element in input) {
                        require(elements.size < 16); elements.add(value(element, depth + 1))
                    }
                    JsonArray(elements) }
                else -> invalid()
            }
        }
        val bytes = value(material, 1).toString().toByteArray(Charsets.UTF_8)
        val decoded = decode(channel, bytes) as? DraftEnrollmentDecodeResult.Accepted ?: invalid()
        decoded.message
    }

    fun encode(message: DraftEnrollmentMessage): ByteArray = fixed {
        val material = message.material()
        val fields = linkedMapOf<String, JsonElement>()
        material.forEach { (name, value) -> fields[name] = when (value) {
            is String -> JsonPrimitive(value)
            is Int -> JsonPrimitive(value)
            is List<*> -> JsonArray(value.map { it as String }.sorted().map(::JsonPrimitive))
            else -> invalid()
        } }
        val bytes = JsonObject(fields).toString().toByteArray(Charsets.UTF_8)
        require(decode(message.channel, bytes) is DraftEnrollmentDecodeResult.Accepted)
        bytes
    }

    private fun schema(channel: DraftEnrollmentChannel, type: String): String {
        if (channel.ordinal >= DraftEnrollmentChannel.PAIR_RESPONSE.ordinal && type == "pair_error") return type
        return when (channel) {
            DraftEnrollmentChannel.PAIR_REQUEST -> "pair".also { require(type == it) }
            DraftEnrollmentChannel.CHALLENGE_REQUEST -> "pair_challenge_request".also { require(type == "pair_challenge") }
            DraftEnrollmentChannel.STATUS_REQUEST -> "pair_status".also { require(type == it) }
            DraftEnrollmentChannel.CANCEL_REQUEST -> "pair_cancel".also { require(type == it) }
            DraftEnrollmentChannel.PAIR_RESPONSE -> "pair_registered".also { require(type == it) }
            DraftEnrollmentChannel.CHALLENGE_RESPONSE -> "pair_challenge_response".also { require(type == "pair_challenge") }
            DraftEnrollmentChannel.STATUS_RESPONSE -> type.also { require(it in setOf("pair_pending", "pair_approved", "pair_ended")) }
            DraftEnrollmentChannel.CANCEL_RESPONSE -> "pair_ended".also { require(type == it) }
        }
    }
    private fun JsonObject.string(key: String): String = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()
    private fun JsonObject.integer(key: String): Long = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull() ?: invalid()
    private fun capabilities(value: JsonElement?) {
        val array = value as? JsonArray ?: invalid()
        require(array.size in 1..16)
        val names = array.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: invalid() }
        require(names.distinct().size == names.size && names.all { Regex("[a-z][a-z0-9-]{0,31}").matches(it) })
    }
    private fun deviceName(value: String) {
        require(value.toByteArray(Charsets.UTF_8).size in 1..128 && !value.startsWith(' ') && !value.endsWith(' '))
        require(value.codePoints().noneMatch { it in 0..31 || it in 127..159 || it in 0x2028..0x2029 || it in 0x202a..0x202e || it in 0x2066..0x2069 || it == 0xfeff })
    }
    private fun signature(value: String) {
        val bytes = DraftEnrollmentChecks.binary(value, 8, 72)
        var at = 0
        fun byte() = bytes.getOrNull(at++)?.toInt()?.and(255) ?: invalid()
        require(byte() == 0x30 && byte() == bytes.size - 2)
        repeat(2) {
            require(byte() == 2)
            val length = byte(); require(length in 1..33 && at + length <= bytes.size)
            val scalar = bytes.copyOfRange(at, at + length); at += length
            require(scalar[0].toInt() >= 0 && !(scalar.size > 1 && scalar[0] == 0.toByte() && scalar[1].toInt() >= 0))
            val number = BigInteger(1, scalar)
            require(number > BigInteger.ZERO && number < DraftEnrollmentChecks.ORDER)
        }
        require(at == bytes.size)
    }

    /** Full bounded structural pass before tree allocation/version precedence. No unstated key-token cap. */
    private class Guard(private val text: String) {
        private var at = 0
        fun check() { whitespace(); value(1); whitespace(); require(at == text.length) }
        private fun whitespace() { while (at < text.length && text[at] in " \t\r\n") at++ }
        private fun take(char: Char) { require(at < text.length && text[at++] == char); whitespace() }
        private fun string(): String {
            val start = at; require(at < text.length && text[at++] == '"')
            var closed = false
            while (at < text.length) {
                val char = text[at++]
                if (char == '\\') { require(at < text.length); at++ }
                else if (char == '"') { closed = true; break }
            }
            require(closed)
            val decoded = json.parseToJsonElement(text.substring(start, at)).jsonPrimitive.content
            DraftEnrollmentChecks.unicode(decoded)
            return decoded
        }
        private fun value(depth: Int) {
            whitespace(); require(at < text.length)
            when (text[at]) {
                '{' -> {
                    require(depth <= 3); take('{'); val keys = HashSet<String>()
                    if (at < text.length && text[at] == '}') { take('}'); return }
                    while (true) {
                        require(keys.size < 16 && keys.add(string())); whitespace(); take(':'); value(depth + 1); whitespace()
                        if (at < text.length && text[at] == '}') { take('}'); return }; take(',')
                    }
                }
                '[' -> {
                    require(depth <= 3); take('['); var count = 0
                    if (at < text.length && text[at] == ']') { take(']'); return }
                    while (true) {
                        require(++count <= 16); value(depth + 1); whitespace()
                        if (at < text.length && text[at] == ']') { take(']'); return }; take(',')
                    }
                }
                '"' -> string()
                't', 'f', 'n' -> {
                    val literal = when (text[at]) { 't' -> "true"; 'f' -> "false"; else -> "null" }
                    require(text.startsWith(literal, at)); at += literal.length
                }
                else -> {
                    val start = at
                    while (at < text.length && text[at] !in " \t\r\n,]}") at++
                    require(Regex("0|[1-9][0-9]{0,9}").matches(text.substring(start, at)))
                }
            }
        }
    }
    internal fun <T> fixed(action: () -> T): T = try { action() }
        catch (_: Exception) { throw DraftEnrollmentException() }
    private fun invalid(): Nothing = throw IllegalArgumentException("invalid_message")
}

internal object DraftEnrollmentChecks {
    val ORDER = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    fun id(value: String) { require(Regex("[A-Za-z0-9_-]{1,128}").matches(value)) }
    fun branded(value: String, prefix: String) { require(value.startsWith(prefix)); binary(value.removePrefix(prefix), 32, 32) }
    fun binary(value: String, min: Int, max: Int): ByteArray {
        require(value.length in 1..((max + 2) / 3 * 4) && Regex("[A-Za-z0-9_-]+").matches(value))
        return Base64.getUrlDecoder().decode(value).also {
            require(it.size in min..max && Base64.getUrlEncoder().withoutPadding().encodeToString(it) == value)
        }
    }
    fun date(value: String) {
        require(Regex("20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z").matches(value))
        LocalDateTime.parse(value, DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss'Z'").withResolverStyle(ResolverStyle.STRICT))
    }
    fun unicode(value: String) {
        var at = 0
        while (at < value.length) {
            val char = value[at++]
            if (char.isHighSurrogate()) require(at < value.length && value[at++].isLowSurrogate())
            else require(!char.isLowSurrogate())
        }
    }
}
