package com.httpfreekit.protocol

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest

class DraftEnrollmentProofContext(val desktopId: String, val gatewaySpkiSha256: String, val invitationId: String,
    val enrollmentId: String, val deviceSpkiSha256: String, val purpose: DraftEnrollmentPurpose) {
    init { DraftEnrollmentCodec.fixed {
        DraftEnrollmentChecks.id(desktopId); DraftEnrollmentChecks.id(invitationId)
        DraftEnrollmentChecks.branded(enrollmentId, "enr_")
        DraftEnrollmentChecks.binary(gatewaySpkiSha256, 32, 32); DraftEnrollmentChecks.binary(deviceSpkiSha256, 32, 32)
    } }
    override fun toString(): String = "DraftEnrollmentProofContext([REDACTED])"
}

/** Constructs bytes only; callers explicitly pass them to the existing nonexportable-key signer. */
object DraftEnrollmentProof {
    fun payload(context: DraftEnrollmentProofContext, challenge: DraftEnrollmentMessage.Challenge): ByteArray = DraftEnrollmentCodec.fixed {
        require(context.desktopId == challenge.desktopId && context.gatewaySpkiSha256 == challenge.gatewaySpkiSha256 &&
            context.invitationId == challenge.invitationId && context.enrollmentId == challenge.enrollmentId &&
            context.deviceSpkiSha256 == challenge.deviceSpkiSha256 && context.purpose == challenge.purpose)
        val bytes = ByteArrayOutputStream()
        val output = DataOutputStream(bytes)
        output.write("HTTP FreeKit enrollment proof v1\u0000".toByteArray(Charsets.US_ASCII))
        val path = if (context.purpose == DraftEnrollmentPurpose.STATUS) "/companion/v1/pair/status" else "/companion/v1/pair/cancel"
        for (value in listOf(context.purpose.wire, "POST", path, context.desktopId, context.invitationId,
            context.enrollmentId, challenge.challengeId, challenge.expiresAt)) {
            val utf8 = value.toByteArray(Charsets.UTF_8); output.writeShort(utf8.size); output.write(utf8)
        }
        for (value in listOf(context.gatewaySpkiSha256, context.deviceSpkiSha256, challenge.nonce)) output.write(DraftEnrollmentChecks.binary(value, 32, 32))
        bytes.toByteArray().also { require(it.size <= 1024) }
    }

    fun comparisonCode(gatewayPin: String, deviceHash: String): String = DraftEnrollmentCodec.fixed {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("HTTP FreeKit pairing comparison v1\u0000".toByteArray(Charsets.US_ASCII))
        digest.update(DraftEnrollmentChecks.binary(gatewayPin, 32, 32)); digest.update(DraftEnrollmentChecks.binary(deviceHash, 32, 32))
        digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }.chunked(8).joinToString("-")
    }
}
