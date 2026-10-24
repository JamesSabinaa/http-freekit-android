package com.httpfreekit.interop

import com.httpfreekit.protocol.*
import com.httpfreekit.security.DeviceIdentity
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import java.util.Collections
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.b64
import com.httpfreekit.interop.DraftEnrollmentResearchChecks.hash

/** Shared research enrollment checks; no transport, key or certificate-entry replacement. */
internal object DraftEnrollmentResearchChecks {
    val REQUESTED = listOf("tcp-http", "tcp-https-connect")
    fun pair(seed: DraftEnrollmentSeed, identity: DeviceIdentity): DraftEnrollmentMessage {
        val csr = identity.enrollmentRequest().also { check(it.size in 1..4096) }
        return DraftEnrollmentCodec.message(DraftEnrollmentChannel.PAIR_REQUEST, linkedMapOf(
            "protocolVersion" to 1, "type" to "pair", "desktopId" to seed.desktopId, "invitationId" to seed.invitationId,
            "invitationSecret" to seed.secretForEnrollment(), "csrDer" to b64(csr), "deviceName" to "Android enrollment research",
            "capabilities" to REQUESTED))
    }
    fun validateApproved(value: DraftEnrollmentMessage.Approved, identity: DeviceIdentity, desktop: String,
        enrollment: String, resultDeadline: String): Pair<X509Certificate, X509Certificate> {
        check(value.desktopId == desktop && value.enrollmentId == enrollment && value.resultExpiresAt == resultDeadline &&
            Instant.now().isBefore(Instant.parse(value.resultExpiresAt)) && value.capabilities.isNotEmpty() &&
            REQUESTED.containsAll(value.capabilities)) { "Approved enrollment context changed" }
        val leaf = DraftEnrollmentHttpsClient.certificate(unb64(value.clientCertificateDer))
        val authority = DraftEnrollmentHttpsClient.certificate(unb64(value.enrollmentAuthorityDer))
        check(leaf.publicKey.encoded.contentEquals(identity.publicKey.encoded) && leaf.notAfter.toInstant() == Instant.parse(value.credentialExpiresAt) &&
            leaf.notBefore >= authority.notBefore && leaf.notAfter <= authority.notAfter) { "Approved certificate binding changed" }
        val manager = identity.bindEnrolledClientCertificate(listOf(leaf), authority)
        val alias = checkNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        check(checkNotNull(manager.getPrivateKey(alias)).encoded == null) { "Enrollment key was exportable" }
        return leaf to authority
    }
    fun keyEvidence(identity: DeviceIdentity): List<ByteArray> {
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = Collections.list(keys.aliases()).single { keys.getCertificate(it)?.publicKey?.encoded?.contentEquals(identity.publicKey.encoded) == true }
        val entry = keys.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        check(entry.privateKey.encoded == null) { "Original enrollment key was exportable" }
        val chain = entry.certificateChain.also { check(it.size in 1..4) }
        return chain.map { hash(it.encoded.also { encoded -> check(encoded.size in 1..4096) }) }
    }
    fun sameHashes(before: List<ByteArray>, after: List<ByteArray>) {
        check(before.size == after.size && before.zip(after).all { (a, b) -> a.contentEquals(b) }) { "Keystore certificate entry was replaced" }
    }
    fun b64(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    fun unb64(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
    fun hash(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)
    override fun toString() = "DraftEnrollmentResearchChecks([REDACTED])"
}

internal class DraftEnrollmentProofSession(val client: DraftEnrollmentHttpsClient, val identity: DeviceIdentity,
    val desktop: String, val pin: String, val invitation: String, val enrollment: String, val reservation: String) {
    private var lastReceived = 0L
    fun challenge(purpose: DraftEnrollmentPurpose): DraftEnrollmentMessage.Challenge {
        if (lastReceived != 0L) {
            val remaining = 1_000_000_000 - (System.nanoTime() - lastReceived)
            if (remaining > 0) Thread.sleep((remaining + 999999) / 1_000_000)
        }
        val challenge = client.exchange(DraftEnrollmentCodec.message(DraftEnrollmentChannel.CHALLENGE_REQUEST, linkedMapOf(
            "protocolVersion" to 1, "type" to "pair_challenge", "desktopId" to desktop, "invitationId" to invitation,
            "enrollmentId" to enrollment, "purpose" to purpose.wire))) as? DraftEnrollmentMessage.Challenge
            ?: error("Fresh enrollment challenge was not issued")
        lastReceived = System.nanoTime()
        // Validate against the locally requested purpose before any caller may sign it.
        DraftEnrollmentProof.payload(context(purpose), challenge)
        return challenge
    }
    fun context(purpose: DraftEnrollmentPurpose) = DraftEnrollmentProofContext(desktop, pin, invitation,
        enrollment, b64(hash(identity.publicKey.encoded)), purpose)
    fun signature(challenge: DraftEnrollmentMessage.Challenge): ByteArray =
        identity.signChallenge(DraftEnrollmentProof.payload(context(challenge.purpose), challenge))
    /** Explicit purpose selection is used only by the adversarial purpose-substitution test. */
    fun request(challenge: DraftEnrollmentMessage.Challenge, signature: ByteArray,
        purpose: DraftEnrollmentPurpose = challenge.purpose): DraftEnrollmentMessage =
        DraftEnrollmentCodec.message(if (purpose == DraftEnrollmentPurpose.STATUS) DraftEnrollmentChannel.STATUS_REQUEST else DraftEnrollmentChannel.CANCEL_REQUEST,
            linkedMapOf("protocolVersion" to 1, "type" to if (purpose == DraftEnrollmentPurpose.STATUS) "pair_status" else "pair_cancel",
                "desktopId" to desktop, "invitationId" to invitation, "enrollmentId" to enrollment,
                "challengeId" to challenge.challengeId, "signature" to b64(signature)))
    fun status(): DraftEnrollmentMessage {
        val challenge = challenge(DraftEnrollmentPurpose.STATUS)
        val result = client.exchange(request(challenge, signature(challenge)))
        if (result is DraftEnrollmentMessage.Pending) check(result.desktopId == desktop &&
            result.enrollmentId == enrollment && result.reservationExpiresAt == reservation) { "Pending enrollment context changed" }
        return result
    }
}
