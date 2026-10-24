package com.httpfreekit.protocol

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.*
import org.junit.Test

class DraftEnrollmentProofTest {
    private val d = DraftEnrollmentTestData
    private fun challenge(purpose: String = "status") = DraftEnrollmentCodec.message(DraftEnrollmentChannel.CHALLENGE_RESPONSE, d.challenge(purpose)) as DraftEnrollmentMessage.Challenge

    @Test fun payloadMatchesIndependentLp16ConstructionForBothOperations() {
        for (purpose in DraftEnrollmentPurpose.entries) {
            val message = challenge(purpose.wire)
            val actual = DraftEnrollmentProof.payload(d.context(purpose), message)
            val expected = ByteArrayOutputStream()
            expected.write("HTTP FreeKit enrollment proof v1".toByteArray(Charsets.US_ASCII)); expected.write(0)
            val output = DataOutputStream(expected)
            for (value in listOf(purpose.wire, "POST", "/companion/v1/pair/${if (purpose == DraftEnrollmentPurpose.STATUS) "status" else "cancel"}",
                "desktop", "invite", d.enrollment, d.challenge, d.date)) {
                val bytes = value.toByteArray(Charsets.UTF_8); output.writeShort(bytes.size); output.write(bytes)
            }
            expected.write(ByteArray(32)); expected.write(ByteArray(32) { (it + 1).toByte() }); expected.write(ByteArray(32))
            assertArrayEquals(expected.toByteArray(), actual)
            assertTrue(actual.size <= 1024)
            actual.fill(0)
            assertArrayEquals(expected.toByteArray(), DraftEnrollmentProof.payload(d.context(purpose), message))
        }
        assertFalse(DraftEnrollmentProof.payload(d.context(), challenge()).contentEquals(DraftEnrollmentProof.payload(d.context(DraftEnrollmentPurpose.CANCEL), challenge("cancel"))))
    }

    @Test fun everySavedContextSubstitutionAndPurposeMismatchIsRejected() {
        val contexts = listOf(
            DraftEnrollmentProofContext("other", d.hash, "invite", d.enrollment, d.otherHash, DraftEnrollmentPurpose.STATUS),
            DraftEnrollmentProofContext("desktop", d.otherHash, "invite", d.enrollment, d.otherHash, DraftEnrollmentPurpose.STATUS),
            DraftEnrollmentProofContext("desktop", d.hash, "other", d.enrollment, d.otherHash, DraftEnrollmentPurpose.STATUS),
            DraftEnrollmentProofContext("desktop", d.hash, "invite", "enr_${d.otherHash}", d.otherHash, DraftEnrollmentPurpose.STATUS),
            DraftEnrollmentProofContext("desktop", d.hash, "invite", d.enrollment, d.hash, DraftEnrollmentPurpose.STATUS),
            d.context(DraftEnrollmentPurpose.CANCEL),
        )
        for (context in contexts) assertThrows(DraftEnrollmentException::class.java) { DraftEnrollmentProof.payload(context, challenge()) }
        assertThrows(DraftEnrollmentException::class.java) { DraftEnrollmentProof.payload(d.context(), challenge("cancel")) }
        assertThrows(DraftEnrollmentException::class.java) { DraftEnrollmentProofContext("bad id", d.hash, "invite", d.enrollment, d.otherHash, DraftEnrollmentPurpose.STATUS) }
        assertFalse(d.context().toString().contains(d.hash))
    }

    @Test fun comparisonUsesDomainNulAndOrderedRawHashes() {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("HTTP FreeKit pairing comparison v1".toByteArray(Charsets.US_ASCII)); digest.update(0)
        digest.update(ByteArray(32)); digest.update(ByteArray(32) { (it + 1).toByte() })
        val expected = digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }.chunked(8).joinToString("-")
        assertEquals(expected, DraftEnrollmentProof.comparisonCode(d.hash, d.otherHash))
        assertTrue(expected.matches(Regex("[0-9a-f]{8}(-[0-9a-f]{8}){7}")))
        assertNotEquals(expected, DraftEnrollmentProof.comparisonCode(d.otherHash, d.hash))
        assertThrows(DraftEnrollmentException::class.java) { DraftEnrollmentProof.comparisonCode(d.hash + "=", d.otherHash) }
    }

    @Test fun realP256SignatureIsBoundToExactPayloadAndOperation() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val payload = DraftEnrollmentProof.payload(d.context(), challenge())
        val signature = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(payload); sign() }
        assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(pair.public); update(payload); verify(signature) })
        val cancel = DraftEnrollmentProof.payload(d.context(DraftEnrollmentPurpose.CANCEL), challenge("cancel"))
        assertFalse(Signature.getInstance("SHA256withECDSA").run { initVerify(pair.public); update(cancel); verify(signature) })
    }
}
