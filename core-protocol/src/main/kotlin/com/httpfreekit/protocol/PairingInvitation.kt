package com.httpfreekit.protocol

import java.net.Inet6Address
import java.net.InetAddress
import java.time.Instant
import java.time.format.DateTimeParseException
import java.util.Base64
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

/** Draft v1 parsing only. Acceptance does not authorize enrollment or interception. */
class PairingInvitation internal constructor(
    val invitationId: String,
    val invitationSecret: PairingSecret,
    val expiresAt: Instant,
    val desktopId: String,
    val displayName: String,
    val serverName: String,
    val gatewaySpkiSha256: String,
    val endpoints: List<GatewayEndpoint>,
) {
    override fun toString(): String = "PairingInvitation(protocolVersion=1, credentials=[REDACTED])"
}

class PairingSecret internal constructor(private val value: String) {
    /** Only use when constructing the authenticated enrollment request body. */
    fun forEnrollment(): String = value
    override fun toString(): String = "[REDACTED]"
}

enum class TransportMode { USB, LAN, WAN }

data class GatewayEndpoint(val mode: TransportMode, val host: String, val port: Int)

enum class PairingError {
    INVALID_MESSAGE,
    MESSAGE_TOO_LARGE,
    UNSUPPORTED_VERSION,
    INVITATION_EXPIRED,
}

sealed interface PairingParseResult {
    data class Accepted(val invitation: PairingInvitation) : PairingParseResult
    data class Rejected(val error: PairingError) : PairingParseResult
}

object PairingInvitationParser {
    const val MAX_PAYLOAD_BYTES = 16 * 1024
    private val json = Json { isLenient = false }
    private val idPattern = Regex("[A-Za-z0-9_-]{1,128}")
    private val base64Pattern = Regex("[A-Za-z0-9_-]{43}")
    private val dnsLabel = Regex("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    private val fields = setOf(
        "kind", "protocolVersion", "invitationId", "invitationSecret", "expiresAt",
        "desktopId", "displayName", "serverName", "gatewaySpkiSha256", "endpoints",
    )

    fun parse(payload: String, now: Instant = Instant.now()): PairingParseResult {
        // Bound characters before allocating an encoded copy of untrusted input.
        if (payload.length > MAX_PAYLOAD_BYTES || payload.toByteArray(Charsets.UTF_8).size > MAX_PAYLOAD_BYTES) {
            return PairingParseResult.Rejected(PairingError.MESSAGE_TOO_LARGE)
        }
        return try {
            val root = json.parseToJsonElement(payload) as? JsonObject ?: invalid()
            val version = root.integer("protocolVersion")
            if (version != 1) return PairingParseResult.Rejected(PairingError.UNSUPPORTED_VERSION)
            require(root.keys == fields)
            require(root.string("kind") == "http-freekit-pairing")
            val invitationId = root.string("invitationId").also { require(idPattern.matches(it)) }
            val secret = root.string("invitationSecret").also { require(isSha256Value(it)) }
            val desktopId = root.string("desktopId").also { require(idPattern.matches(it)) }
            val displayName = root.string("displayName").also {
                require(it.isNotBlank() && it.length <= 128 && it.none { c -> Character.isISOControl(c) })
            }
            val serverName = root.string("serverName").also { require(isDnsName(it) && '.' in it) }
            val pin = root.string("gatewaySpkiSha256").also { require(isSha256Value(it)) }
            val expiryText = root.string("expiresAt").also { require(it.endsWith('Z') && it.length <= 40) }
            val expiresAt = Instant.parse(expiryText)
            val rawEndpoints = root["endpoints"] as? JsonArray ?: invalid()
            require(rawEndpoints.size in 1..8)
            val endpoints = rawEndpoints.map { element ->
                val endpoint = element as? JsonObject ?: invalid()
                require(endpoint.keys == setOf("mode", "host", "port"))
                val mode = when (endpoint.string("mode")) {
                    "usb" -> TransportMode.USB
                    "lan" -> TransportMode.LAN
                    "wan" -> TransportMode.WAN
                    else -> invalid()
                }
                val host = endpoint.string("host").also { require(isHost(it)) }
                require(mode != TransportMode.USB || host == "127.0.0.1" || host == "::1")
                val port = endpoint.integer("port").also { require(it in 1..65535) }
                GatewayEndpoint(mode, host, port)
            }
            require(endpoints.distinct().size == endpoints.size)
            if (!expiresAt.isAfter(now)) return PairingParseResult.Rejected(PairingError.INVITATION_EXPIRED)
            PairingParseResult.Accepted(
                PairingInvitation(invitationId, PairingSecret(secret), expiresAt, desktopId, displayName, serverName, pin, endpoints),
            )
        } catch (_: SerializationException) {
            PairingParseResult.Rejected(PairingError.INVALID_MESSAGE)
        } catch (_: IllegalArgumentException) {
            PairingParseResult.Rejected(PairingError.INVALID_MESSAGE)
        } catch (_: DateTimeParseException) {
            PairingParseResult.Rejected(PairingError.INVALID_MESSAGE)
        }
    }

    private fun JsonObject.string(key: String): String {
        val value = this[key] as? JsonPrimitive ?: invalid()
        require(value.isString)
        return value.content
    }

    private fun JsonObject.integer(key: String): Int {
        val value = this[key] as? JsonPrimitive ?: invalid()
        require(!value.isString)
        return value.intOrNull ?: invalid()
    }

    private fun isSha256Value(value: String): Boolean {
        if (!base64Pattern.matches(value)) return false
        val decoded = Base64.getUrlDecoder().decode(value)
        return decoded.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == value
    }

    private fun isDnsName(host: String): Boolean =
        host.length in 1..253 && host.split('.').all { dnsLabel.matches(it) }

    private fun isHost(host: String): Boolean {
        if (host.isEmpty() || host.length > 253) return false
        if (':' in host) {
            // Numeric IPv6 only: never perform DNS or accept scoped/interface addresses.
            if (!host.all { it in "0123456789abcdefABCDEF:." }) return false
            return try { InetAddress.getByName(host) is Inet6Address } catch (_: java.net.UnknownHostException) { false }
        }
        if (host.all { it.isDigit() || it == '.' }) {
            val parts = host.split('.')
            return parts.size == 4 && parts.all {
                it.isNotEmpty() && (it.length == 1 || !it.startsWith('0')) && (it.toIntOrNull() ?: -1) in 0..255
            }
        }
        return isDnsName(host)
    }

    private fun invalid(): Nothing = throw IllegalArgumentException("Invalid pairing payload")
}
