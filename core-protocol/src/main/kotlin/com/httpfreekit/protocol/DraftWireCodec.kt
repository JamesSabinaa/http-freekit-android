package com.httpfreekit.protocol

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.ResolverStyle
import java.util.Base64
import java.util.Collections
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

enum class DraftChannel { CONTROL, STREAM }
enum class DraftDirection { CLIENT, GATEWAY }

/** Fixed local results; no untrusted text is retained in an exception. */
class DraftProtocolException(val code: String) : IllegalArgumentException(code)

data class DraftLimits(
    val maxFrameBytes: Int = 65536,
    val maxQueuedBytesPerStream: Int = 1048576,
    val maxQueuedBytesPerDevice: Int = 4194304,
    val maxConcurrentStreams: Int = 64,
    val maxQueuedFramesPerStream: Int = 64,
    val maxOpenedStreamsPerSession: Int = 4096,
) {
    internal fun valid() = maxFrameBytes in 1..65536 &&
        maxQueuedBytesPerStream in maxFrameBytes..1048576 &&
        maxQueuedBytesPerDevice in maxQueuedBytesPerStream..4194304 &&
        maxConcurrentStreams in 1..64 && maxQueuedFramesPerStream in 1..64 &&
        maxOpenedStreamsPerSession in maxConcurrentStreams..4096
}

/** Values are intended for explicit wire/header access, never default diagnostics. */
sealed class DraftMessage(val protocolVersion: Int, val type: String) {
    final override fun toString() = "DraftMessage(fields=[REDACTED])"
    class Hello(capabilities: Collection<String>, requiredCapabilities: Collection<String>, version: Int = 1) : DraftMessage(version, "hello") {
        val capabilities = immutable(capabilities)
        val requiredCapabilities = immutable(requiredCapabilities)
    }
    class SessionReady(capabilities: Collection<String>, val desktopId: String, val expiresAt: Instant,
        val limits: DraftLimits, val sessionId: String, version: Int = 1) : DraftMessage(version, "session_ready") {
        val capabilities = immutable(capabilities)
    }
    class ControlCancel(version: Int = 1) : DraftMessage(version, "cancel")
    class ControlEnd(type: String, val code: String, version: Int = 1) : DraftMessage(version, type)
    class Stream(type: String, val streamId: String, val code: String? = null, version: Int = 1) : DraftMessage(version, type)

    companion object {
        private fun immutable(values: Collection<String>): List<String> = Collections.unmodifiableList(ArrayList(values))
    }
}

sealed interface DraftDecodeResult {
    data class Accepted(val message: DraftMessage) : DraftDecodeResult
    data class Rejected(val code: String) : DraftDecodeResult
}

/** Draft 0.3 only. This codec neither authenticates a peer nor performs transport I/O. */
object DraftWireCodec {
    const val MAX_TEXT_BYTES = 16384
    private val json = Json { isLenient = false }
    private val identifier = Regex("[A-Za-z0-9_-]{1,128}")
    private val streamIdentifier = Regex("[A-Za-z0-9_-]{1,64}")
    private val capability = Regex("[a-z][a-z0-9-]{0,31}")
    private val integer = Regex("0|[1-9][0-9]*")
    private val utc = Regex("20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
    private val dateFormat = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss'Z'").withResolverStyle(ResolverStyle.STRICT)
    internal val controlErrors = setOf("unsupported_version", "unsupported_capability", "authentication_failed", "device_revoked",
        "proxy_unavailable", "session_limit", "stream_limit", "invalid_message", "network_unreachable", "session_expired")
    internal val streamErrors = setOf("proxy_unavailable", "stream_limit", "invalid_message", "network_unreachable", "device_revoked", "session_expired")
    private val disconnects = setOf("desktop_stopped", "device_revoked", "session_expired")

    fun decode(channel: DraftChannel, bytes: ByteArray): DraftDecodeResult {
        if (bytes.size > MAX_TEXT_BYTES) return DraftDecodeResult.Rejected("message_too_large")
        if (bytes.isEmpty()) return DraftDecodeResult.Rejected("invalid_message")
        return try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            require(!text.startsWith('\uFEFF'))
            structuralGuard(text)
            val root = json.parseToJsonElement(text) as? JsonObject ?: invalid()
            val version = root.number("protocolVersion", 1, Int.MAX_VALUE)
            val type = root.string("type")
            val message = when (channel) {
                DraftChannel.CONTROL -> when (type) {
                    "hello" -> {
                        root.exact("capabilities", "requiredCapabilities")
                        val offered = root.capabilities("capabilities")
                        val required = root.capabilities("requiredCapabilities", true)
                        require(offered.containsAll(required))
                        DraftMessage.Hello(offered, required, version)
                    }
                    "session_ready" -> {
                        root.exact("capabilities", "desktopId", "expiresAt", "limits", "sessionId")
                        DraftMessage.SessionReady(root.capabilities("capabilities"),
                            root.string("desktopId").also { require(identifier.matches(it)) },
                            parseDate(root.string("expiresAt")), limits(root["limits"]),
                            root.string("sessionId").also { require(validSessionId(it)) }, version)
                    }
                    "cancel" -> { root.exact(); DraftMessage.ControlCancel(version) }
                    "disconnect", "error" -> {
                        root.exact("code")
                        val code = root.string("code").also { require(it in if (type == "disconnect") disconnects else controlErrors) }
                        DraftMessage.ControlEnd(type, code, version)
                    }
                    else -> invalid()
                }
                DraftChannel.STREAM -> {
                    require(type in setOf("open", "ready", "end_write", "cancel", "error"))
                    if (type == "error") root.exact("streamId", "code") else root.exact("streamId")
                    val id = root.string("streamId").also { require(streamIdentifier.matches(it)) }
                    val code = if (type == "error") root.string("code").also { require(it in streamErrors) } else null
                    DraftMessage.Stream(type, id, code, version)
                }
            }
            if (version != 1) DraftDecodeResult.Rejected("unsupported_version") else DraftDecodeResult.Accepted(message)
        } catch (_: IllegalArgumentException) {
            DraftDecodeResult.Rejected("invalid_message")
        } catch (_: java.nio.charset.CharacterCodingException) {
            DraftDecodeResult.Rejected("invalid_message")
        } catch (_: java.time.DateTimeException) {
            DraftDecodeResult.Rejected("invalid_message")
        } catch (_: SerializationException) {
            DraftDecodeResult.Rejected("invalid_message")
        }
    }

    /** Validates constructed values with the same schema before producing deterministic wire bytes. */
    fun encode(message: DraftMessage): ByteArray {
        val fields = linkedMapOf<String, JsonElement>("protocolVersion" to JsonPrimitive(message.protocolVersion), "type" to JsonPrimitive(message.type))
        fun strings(values: List<String>) = JsonArray(values.sorted().map(::JsonPrimitive))
        val channel = when (message) {
            is DraftMessage.Hello -> {
                fields["capabilities"] = strings(message.capabilities)
                fields["requiredCapabilities"] = strings(message.requiredCapabilities)
                DraftChannel.CONTROL
            }
            is DraftMessage.SessionReady -> {
                fields["capabilities"] = strings(message.capabilities)
                fields["desktopId"] = JsonPrimitive(message.desktopId)
                fields["expiresAt"] = JsonPrimitive(message.expiresAt.toString())
                fields["sessionId"] = JsonPrimitive(message.sessionId)
                fields["limits"] = with(message.limits) { JsonObject(sortedMapOf(
                    "maxFrameBytes" to JsonPrimitive(maxFrameBytes), "maxQueuedBytesPerStream" to JsonPrimitive(maxQueuedBytesPerStream),
                    "maxQueuedBytesPerDevice" to JsonPrimitive(maxQueuedBytesPerDevice), "maxConcurrentStreams" to JsonPrimitive(maxConcurrentStreams),
                    "maxQueuedFramesPerStream" to JsonPrimitive(maxQueuedFramesPerStream), "maxOpenedStreamsPerSession" to JsonPrimitive(maxOpenedStreamsPerSession))) }
                DraftChannel.CONTROL
            }
            is DraftMessage.ControlCancel -> DraftChannel.CONTROL
            is DraftMessage.ControlEnd -> { fields["code"] = JsonPrimitive(message.code); DraftChannel.CONTROL }
            is DraftMessage.Stream -> {
                fields["streamId"] = JsonPrimitive(message.streamId)
                if (message.code != null) fields["code"] = JsonPrimitive(message.code)
                DraftChannel.STREAM
            }
        }
        val bytes = JsonObject(fields.toSortedMap()).toString().toByteArray(Charsets.UTF_8)
        val result = decode(channel, bytes)
        if (result is DraftDecodeResult.Rejected) throw DraftProtocolException(result.code)
        return bytes
    }

    internal fun validSessionId(value: String): Boolean {
        if (!Regex("[A-Za-z0-9_-]{43}").matches(value)) return false
        val bytes = Base64.getUrlDecoder().decode(value)
        return bytes.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == value
    }

    private fun limits(value: JsonElement?): DraftLimits {
        val root = value as? JsonObject ?: invalid()
        require(root.keys == setOf("maxFrameBytes", "maxQueuedBytesPerStream", "maxQueuedBytesPerDevice", "maxConcurrentStreams", "maxQueuedFramesPerStream", "maxOpenedStreamsPerSession"))
        return DraftLimits(root.number("maxFrameBytes", 1, 65536), root.number("maxQueuedBytesPerStream", 1, 1048576),
            root.number("maxQueuedBytesPerDevice", 1, 4194304), root.number("maxConcurrentStreams", 1, 64),
            root.number("maxQueuedFramesPerStream", 1, 64), root.number("maxOpenedStreamsPerSession", 1, 4096)).also { require(it.valid()) }
    }
    private fun parseDate(value: String): Instant {
        require(utc.matches(value))
        return LocalDateTime.parse(value, dateFormat).toInstant(ZoneOffset.UTC)
    }
    private fun JsonObject.exact(vararg extra: String) { require(keys == setOf("protocolVersion", "type", *extra)) }
    private fun JsonObject.string(key: String): String = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()
    private fun JsonObject.number(key: String, minimum: Int, maximum: Int): Int {
        val value = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content ?: invalid()
        require(integer.matches(value) && value.length <= 10)
        return (value.toLongOrNull() ?: invalid()).also { require(it in minimum.toLong()..maximum.toLong()) }.toInt()
    }
    private fun JsonObject.capabilities(key: String, empty: Boolean = false): List<String> {
        val values = this[key] as? JsonArray ?: invalid()
        require(values.size in (if (empty) 0 else 1)..16)
        return values.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: invalid() }
            .also { require(it.all(capability::matches) && it.distinct().size == it.size) }
    }

    /** Resource/duplicate guard only: the established library still validates JSON syntax/strings. */
    private fun structuralGuard(text: String) {
        class Container(val objectKind: Boolean, val keys: MutableSet<String> = HashSet())
        val stack = ArrayList<Container>(3)
        var index = 0
        while (index < text.length) {
            when (text[index]) {
                '{', '[' -> { require(stack.size < 3); stack.add(Container(text[index] == '{')); index++ }
                '}', ']' -> { require(stack.isNotEmpty()); stack.removeAt(stack.lastIndex); index++ }
                '"' -> {
                    val start = index++
                    var ended = false
                    while (index < text.length) {
                        val char = text[index++]
                        if (char == '\\') { require(index < text.length); index++ }
                        else if (char == '"') { ended = true; break }
                    }
                    require(ended)
                    var next = index
                    while (next < text.length && text[next] in " \t\r\n") next++
                    if (next < text.length && text[next] == ':') {
                        require(stack.isNotEmpty() && stack.last().objectKind)
                        val token = text.substring(start, index)
                        require(token.toByteArray(Charsets.UTF_8).size <= 256)
                        val key = (json.parseToJsonElement(token) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()
                        require(stack.last().keys.add(key) && stack.last().keys.size <= 16)
                    }
                }
                '-', in '0'..'9' -> {
                    val start = index++
                    while (index < text.length && text[index] !in " \t\r\n,]}:") index++
                    require(integer.matches(text.substring(start, index)))
                }
                else -> index++
            }
        }
        require(stack.isEmpty())
    }
    private fun invalid(): Nothing = throw IllegalArgumentException("invalid_message")
}
