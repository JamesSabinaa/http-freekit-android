package com.httpfreekit.security

import java.nio.ByteBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ApprovedEnrolledCredentialCodecTest {
    @Test fun encoderMatchesIndependentBigEndianFrozenLayoutAndSortedCapabilities() {
        val f = ApprovedCredentialTestFixture()
        val record = f.record
        assertEquals(32768, ApprovedEnrolledCredentialCodec.MAX_RECORD_BYTES)
        val encoded = ApprovedEnrolledCredentialCodec.encode(record)
        assertArrayEquals(approvedEnvelope(record), encoded)
        val decoded = ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(record))
        assertArrayEquals(encoded, ApprovedEnrolledCredentialCodec.encode(decoded))
        assertEquals(listOf("capture", "stream"), decoded.approval.capabilities)
        assertArrayEquals(f.keys.public.encoded, decoded.approval.originalDeviceSpki)
        assertArrayEquals(approvedHash(f.original.encoded), decoded.approval.originalKeystoreCertificateHashes.single())
        assertEquals(f.leaf.notAfter.time, decoded.approval.credentialExpiresAtMillis)
    }

    @Test fun decodingSnapshotsInputAndReturnedMaterialRatherThanAliasingEnvelope() {
        val f = ApprovedCredentialTestFixture()
        val encoded = approvedEnvelope(f.record)
        val decoded = ApprovedEnrolledCredentialCodec.decode(encoded)
        encoded.fill(0)
        decoded.approval.originalDeviceSpki.fill(0)
        decoded.approval.originalKeystoreCertificateHashes.single().fill(0)
        decoded.approval.interceptionCaCertificateSha256.fill(0)
        decoded.credential.clientCertificateChain.single().encoded.fill(0)
        assertArrayEquals(approvedEnvelope(f.record), ApprovedEnrolledCredentialCodec.encode(decoded))
        approvedRedacted(decoded.toString(), f)
    }

    @Test fun decoderRejectsWrongMagicVersionEveryTruncationAndTrailingMaterial() {
        val encoded = approvedEnvelope(ApprovedCredentialTestFixture().record)
        for (offset in listOf(0, 4)) {
            val invalid = encoded.copyOf()
            ByteBuffer.wrap(invalid).putInt(offset, 2)
            approvedRejected { ApprovedEnrolledCredentialCodec.decode(invalid) }
        }
        for (length in 0 until encoded.size) {
            approvedRejected { ApprovedEnrolledCredentialCodec.decode(encoded.copyOf(length)) }
        }
        approvedRejected { ApprovedEnrolledCredentialCodec.decode(encoded + byteArrayOf(0)) }
        approvedRejected { ApprovedEnrolledCredentialCodec.decode(encoded + encoded) }
        approvedRejected { ApprovedEnrolledCredentialCodec.decode(ByteArray(32769)) }
    }

    @Test fun allBlobLengthsAndBothCountsAreValidatedBeforeAllocation() {
        val record = ApprovedCredentialTestFixture().record
        val encoded = approvedEnvelope(record)
        val layout = offsets(encoded)
        // Every field, not just the leading legacy blob, is independently adversarial.
        layout.blobs.forEach { offset ->
            for (length in listOf(-1, 0, Int.MIN_VALUE, Int.MAX_VALUE)) {
                val invalid = encoded.copyOf()
                ByteBuffer.wrap(invalid).putInt(offset, length)
                approvedRejected { ApprovedEnrolledCredentialCodec.decode(invalid) }
            }
        }
        for ((offset, maximum) in listOf(layout.originalCount to 4, layout.capabilityCount to 16)) {
            for (count in listOf(-1, 0, maximum + 1, Int.MIN_VALUE, Int.MAX_VALUE)) {
                val invalid = encoded.copyOf()
                ByteBuffer.wrap(invalid).putInt(offset, count)
                approvedRejected { ApprovedEnrolledCredentialCodec.decode(invalid) }
            }
        }
        val oversizedLegacy = approvedEnvelope(record, legacy = ByteArray(EnrolledCredentialCodec.MAX_RECORD_BYTES + 1))
        approvedRejected { ApprovedEnrolledCredentialCodec.decode(oversizedLegacy) }
    }

    @Test fun decoderEnforcesEachFieldBoundAndStrictAsciiNotReplacementDecoding() {
        val record = ApprovedCredentialTestFixture().record
        val bounds = mapOf("desktop" to 128, "name" to 253, "pin" to 43, "enrollment" to 128,
            "device" to 128, "spki" to 91, "originalHash" to 32, "clientHash" to 32,
            "authorityHash" to 32, "caHash" to 32, "capability" to 32)
        for ((name, maximum) in bounds) {
            approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(record,
                fields = mapOf(name to ByteArray(maximum + 1) { 'a'.code.toByte() }))) }
        }
        for (field in listOf("desktop", "name", "pin", "enrollment", "device", "capability")) {
            for (invalid in listOf(byteArrayOf(0), byteArrayOf(10), byteArrayOf(32), byteArrayOf(127), byteArrayOf(0x80.toByte()), "é".toByteArray())) {
                approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(record, fields = mapOf(field to invalid))) }
            }
        }
    }

    @Test fun decoderRejectsNoncanonicalPinSpkiHashesCapabilitiesAndExpiry() {
        val f = ApprovedCredentialTestFixture()
        val record = f.record
        val pin = record.approval.gatewaySpkiSha256
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val alternate = pin.dropLast(1) + alphabet[alphabet.indexOf(pin.last()) xor 1]
        for ((field, value) in listOf(
            "pin" to alternate.toByteArray(), "spki" to (f.keys.public.encoded + byteArrayOf(0)),
            "spki" to ByteArray(91), "originalHash" to ByteArray(31),
            "clientHash" to ByteArray(33), "authorityHash" to ByteArray(31), "caHash" to ByteArray(31),
        )) approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(record, fields = mapOf(field to value))) }
        for (capabilities in listOf(listOf("same", "same"), listOf("stream", "capture"), listOf("Upper"), listOf("a_b"), listOf("1cap"))) {
            approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(record, capabilities = capabilities)) }
        }
        for (expiry in listOf(0L, -1L, f.leaf.notAfter.time + 1)) {
            approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(record, expiry = expiry)) }
        }
    }

    @Test fun mixingAnyCheckableApprovalFieldWithAnotherCredentialFailsClosed() {
        val f = ApprovedCredentialTestFixture()
        val record = f.record
        val substitutions = mapOf(
            "desktop" to "another-owner".toByteArray(),
            "name" to "another.invalid".toByteArray(),
            "pin" to approvedPin(TestEnrollmentCertificates.server().certificate).toByteArray(),
            "spki" to TestEnrollmentCertificates.keyPair().public.encoded,
            "clientHash" to ByteArray(32), "authorityHash" to ByteArray(32),
        )
        substitutions.forEach { (name, bytes) ->
            approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(record, fields = mapOf(name to bytes))) }
        }
        val replacement = f.client()
        approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(record,
            legacy = EnrolledCredentialCodec.encode(f.credential(clientCertificate = replacement)))) }
        val other = ApprovedCredentialTestFixture()
        approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(record,
            legacy = EnrolledCredentialCodec.encode(other.credential()))) }
    }

    @Test fun legacyFkcrIsNotAnApprovalAndTheLegacyDecoderDoesNotAdoptFkar() {
        val f = ApprovedCredentialTestFixture()
        val legacy = EnrolledCredentialCodec.encode(f.credential())
        assertEquals(f.id, EnrolledCredentialCodec.decode(legacy).desktopId)
        approvedRejected { ApprovedEnrolledCredentialCodec.decode(legacy) }
        approvedRejected { EnrolledCredentialCodec.decode(approvedEnvelope(f.record)) }
        approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(f.record, legacy = legacy + byteArrayOf(0))) }
        approvedRejected { ApprovedEnrolledCredentialCodec.decode(approvedEnvelope(f.record, legacy = approvedEnvelope(f.record))) }
    }

    @Test fun malformedDecodeErrorsAreFixedRedactedAndHaveNoProviderCauses() {
        val f = ApprovedCredentialTestFixture()
        val invalid = approvedEnvelope(f.record, fields = mapOf("enrollment" to (f.id + "/private-provider").toByteArray()))
        val failure = approvedRejected { ApprovedEnrolledCredentialCodec.decode(invalid) }
        assertNull(failure.cause)
        approvedRedacted(failure.toString(), f)
        val wrongVersion = approvedEnvelope(f.record).apply { ByteBuffer.wrap(this).putInt(4, 99) }
        val otherFailure = approvedRejected { ApprovedEnrolledCredentialCodec.decode(wrongVersion) }
        assertNull(otherFailure.cause)
        assertEquals(failure.message, otherFailure.message)
    }

    private data class Layout(val blobs: List<Int>, val originalCount: Int, val capabilityCount: Int)
    private fun offsets(encoded: ByteArray): Layout {
        val buffer = ByteBuffer.wrap(encoded)
        val blobs = mutableListOf<Int>()
        buffer.position(8)
        fun blob() { blobs += buffer.position(); val size = buffer.int; buffer.position(buffer.position() + size) }
        repeat(7) { blob() } // legacy, desktop/name/pin/enrollment/device, SPKI
        val originals = buffer.position()
        repeat(buffer.int) { blob() }
        repeat(3) { blob() }
        val capabilities = buffer.position()
        repeat(buffer.int) { blob() }
        assertEquals(encoded.size - 8, buffer.position())
        return Layout(blobs, originals, capabilities)
    }
}
