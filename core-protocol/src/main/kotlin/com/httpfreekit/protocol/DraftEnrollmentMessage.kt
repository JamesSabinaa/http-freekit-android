package com.httpfreekit.protocol

import java.util.Collections
import kotlinx.serialization.json.*

enum class DraftEnrollmentChannel {
    PAIR_REQUEST, CHALLENGE_REQUEST, STATUS_REQUEST, CANCEL_REQUEST,
    PAIR_RESPONSE, CHALLENGE_RESPONSE, STATUS_RESPONSE, CANCEL_RESPONSE,
}

enum class DraftEnrollmentPurpose(val wire: String) { STATUS("status"), CANCEL("cancel") }

/** Fixed local misuse result, without untrusted detail or a retained cause. */
class DraftEnrollmentException internal constructor() : IllegalArgumentException("invalid_message") {
    val code: String = "invalid_message"
}

sealed interface DraftEnrollmentDecodeResult {
    data class Accepted(val message: DraftEnrollmentMessage) : DraftEnrollmentDecodeResult
    data class Rejected(val code: String) : DraftEnrollmentDecodeResult
}

/** Validated immutable draft 0.4 value. Only explicit material/wire access reveals its fields. */
sealed class DraftEnrollmentMessage protected constructor(
    val channel: DraftEnrollmentChannel,
    val type: String,
    private val fields: JsonObject,
) {
    val protocolVersion: Int = 1
    final override fun toString(): String = "DraftEnrollmentMessage([REDACTED])"
    protected fun text(name: String): String = fields.getValue(name).jsonPrimitive.content
    protected fun capabilities(): List<String> = Collections.unmodifiableList(fields.getValue("capabilities").jsonArray.map { it.jsonPrimitive.content })
    /** Fresh wire-shaped snapshot; binary material remains canonical base64url. */
    fun material(): Map<String, Any> = Collections.unmodifiableMap(LinkedHashMap<String, Any>().apply {
        fields.forEach { (name, value) -> put(name, when (value) {
            is JsonArray -> Collections.unmodifiableList(value.map { it.jsonPrimitive.content })
            is JsonPrimitive -> if (value.isString) value.content else value.content.toInt()
            else -> error("Invalid validated enrollment value")
        }) }
    })

    class Pair internal constructor(fields: JsonObject) : DraftEnrollmentMessage(DraftEnrollmentChannel.PAIR_REQUEST, "pair", fields) {
        val desktopId get() = text("desktopId")
        val invitationId get() = text("invitationId")
        val invitationSecret get() = text("invitationSecret")
        val csrDer get() = text("csrDer")
        val deviceName get() = text("deviceName")
        val capabilities get() = capabilities()
    }
    class ChallengeRequest internal constructor(fields: JsonObject) : DraftEnrollmentMessage(DraftEnrollmentChannel.CHALLENGE_REQUEST, "pair_challenge", fields) {
        val desktopId get() = text("desktopId")
        val invitationId get() = text("invitationId")
        val enrollmentId get() = text("enrollmentId")
        val purpose get() = DraftEnrollmentPurpose.entries.single { it.wire == text("purpose") }
    }
    class StatusRequest internal constructor(fields: JsonObject) : DraftEnrollmentMessage(DraftEnrollmentChannel.STATUS_REQUEST, "pair_status", fields) {
        val desktopId get() = text("desktopId")
        val invitationId get() = text("invitationId")
        val enrollmentId get() = text("enrollmentId")
        val challengeId get() = text("challengeId")
        val signature get() = text("signature")
    }
    class CancelRequest internal constructor(fields: JsonObject) : DraftEnrollmentMessage(DraftEnrollmentChannel.CANCEL_REQUEST, "pair_cancel", fields) {
        val desktopId get() = text("desktopId")
        val invitationId get() = text("invitationId")
        val enrollmentId get() = text("enrollmentId")
        val challengeId get() = text("challengeId")
        val signature get() = text("signature")
    }
    class Registered internal constructor(fields: JsonObject) : DraftEnrollmentMessage(DraftEnrollmentChannel.PAIR_RESPONSE, "pair_registered", fields) {
        val desktopId get() = text("desktopId")
        val invitationId get() = text("invitationId")
        val enrollmentId get() = text("enrollmentId")
        val deviceSpkiSha256 get() = text("deviceSpkiSha256")
        val reservationExpiresAt get() = text("reservationExpiresAt")
        val resultExpiresAt get() = text("resultExpiresAt")
    }
    class Challenge internal constructor(fields: JsonObject) : DraftEnrollmentMessage(DraftEnrollmentChannel.CHALLENGE_RESPONSE, "pair_challenge", fields) {
        val desktopId get() = text("desktopId")
        val gatewaySpkiSha256 get() = text("gatewaySpkiSha256")
        val invitationId get() = text("invitationId")
        val enrollmentId get() = text("enrollmentId")
        val challengeId get() = text("challengeId")
        val deviceSpkiSha256 get() = text("deviceSpkiSha256")
        val purpose get() = DraftEnrollmentPurpose.entries.single { it.wire == text("purpose") }
        val nonce get() = text("nonce")
        val expiresAt get() = text("expiresAt")
    }
    class Pending internal constructor(fields: JsonObject) : DraftEnrollmentMessage(DraftEnrollmentChannel.STATUS_RESPONSE, "pair_pending", fields) {
        val desktopId get() = text("desktopId")
        val enrollmentId get() = text("enrollmentId")
        val reservationExpiresAt get() = text("reservationExpiresAt")
        val retryAfterMillis: Int = 1000
    }
    class Approved internal constructor(fields: JsonObject) : DraftEnrollmentMessage(DraftEnrollmentChannel.STATUS_RESPONSE, "pair_approved", fields) {
        val desktopId get() = text("desktopId")
        val enrollmentId get() = text("enrollmentId")
        val deviceId get() = text("deviceId")
        val clientCertificateDer get() = text("clientCertificateDer")
        val enrollmentAuthorityDer get() = text("enrollmentAuthorityDer")
        val interceptionCaCertificateSha256 get() = text("interceptionCaCertificateSha256")
        val capabilities get() = capabilities()
        val credentialExpiresAt get() = text("credentialExpiresAt")
        val resultExpiresAt get() = text("resultExpiresAt")
    }
    class Ended internal constructor(channel: DraftEnrollmentChannel, fields: JsonObject) : DraftEnrollmentMessage(channel, "pair_ended", fields) {
        val desktopId get() = text("desktopId")
        val enrollmentId get() = text("enrollmentId")
        val code get() = text("code")
    }
    class Error internal constructor(channel: DraftEnrollmentChannel, fields: JsonObject) : DraftEnrollmentMessage(channel, "pair_error", fields) {
        val code get() = text("code")
    }
}
