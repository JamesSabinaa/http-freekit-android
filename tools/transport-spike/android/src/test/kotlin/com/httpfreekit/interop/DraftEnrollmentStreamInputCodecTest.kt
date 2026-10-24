package com.httpfreekit.interop

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class DraftEnrollmentStreamInputCodecTest {
    @Test fun independentlyFramedScenariosDecodeAndDoNotAliasDeliveredBytes() {
        for (scenario in 1..3) {
            val bytes = wrapper(scenario = scenario)
            val value = DraftEnrollmentStreamInputCodec.decode(bytes)
            bytes.fill(0)
            assertEquals(34567, value.streamPort); assertEquals(scenario, value.scenario)
            assertEquals(12345, value.enrollment.setupPort); assertEquals(23456, value.enrollment.credentialPort)
            assertEquals("private-desktop", value.enrollment.desktopId)
            assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 9 }), value.enrollment.secretForEnrollment())
            value.enrollment.clearInvitationSecret()
        }
    }

    @Test fun everyTruncationTrailingDataAndOversizedInputFailsClosed() {
        val bytes = wrapper()
        for (length in bytes.indices) rejected { DraftEnrollmentStreamInputCodec.decode(bytes.copyOf(length)) }
        rejected { DraftEnrollmentStreamInputCodec.decode(bytes + byteArrayOf(0)) }
        rejected { DraftEnrollmentStreamInputCodec.decode(ByteArray(16385)) }
        for (index in 0..7) rejected { DraftEnrollmentStreamInputCodec.decode(bytes.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }) }
    }

    @Test fun onlyFiniteScenariosAndThreeDistinctNonzeroPortsAreAccepted() {
        for (scenario in listOf(0, 4, 255)) rejected { DraftEnrollmentStreamInputCodec.decode(wrapper(scenario = scenario)) }
        for (port in listOf(0, 12345, 23456)) rejected { DraftEnrollmentStreamInputCodec.decode(wrapper(port = port)) }
        assertEquals(65535, DraftEnrollmentStreamInputCodec.decode(wrapper(port = 65535)).streamPort)
    }

    @Test fun embeddedSeedLengthAndItsOwnStrictGrammarAreStillRequired() {
        val bytes = wrapper()
        for (length in listOf(0, bytes.size - 14, bytes.size - 12, 65535)) rejected {
            DraftEnrollmentStreamInputCodec.decode(bytes.copyOf().also { ByteBuffer.wrap(it).putShort(11, length.toShort()) })
        }
        rejected { DraftEnrollmentStreamInputCodec.decode(wrapper(seed = seed().also { it[0] = 0 })) }
        rejected { DraftEnrollmentStreamInputCodec.decode(wrapper(seed = seed().also { ByteBuffer.wrap(it).putShort(8, 23456.toShort()) })) }
    }

    @Test fun wrapperAndRejectedMaterialHaveFixedPrivateDiagnostics() {
        val value = DraftEnrollmentStreamInputCodec.decode(wrapper())
        for (privateValue in listOf("private-desktop", "private-invitation", "private-gateway.invalid", value.enrollment.secretForEnrollment())) {
            assertFalse((value.toString() + value.enrollment.toString()).contains(privateValue))
        }
        rejected { DraftEnrollmentStreamInputCodec.decode("PRIVATE_INPUT_CANARY".toByteArray()) }
    }

    private fun seed(): ByteArray = ByteArrayOutputStream().also { bytes -> DataOutputStream(bytes).use { output ->
        output.write(byteArrayOf(72, 70, 75, 69, 78, 82, 49, 0)); output.writeShort(12345); output.writeShort(23456)
        for (field in listOf(byteArrayOf(1), ByteArray(32) { 8 }, "private-gateway.invalid".toByteArray(),
            "private-desktop".toByteArray(), "private-invitation".toByteArray(), ByteArray(32) { 9 }, "2030-01-02T00:05:00Z".toByteArray())) {
            output.writeShort(field.size); output.write(field)
        }
    } }.toByteArray()
    private fun wrapper(port: Int = 34567, scenario: Int = 1, seed: ByteArray = seed()): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).use { output ->
            output.write(byteArrayOf(72, 70, 75, 83, 84, 82, 49, 0)); output.writeShort(port); output.writeByte(scenario)
            output.writeShort(seed.size); output.write(seed)
        }
    }.toByteArray()
    private fun rejected(action: () -> Unit) {
        try { action(); throw AssertionError("Expected private stream-input rejection") }
        catch (failure: DraftEnrollmentStateException) {
            assertEquals("Invalid enrollment research state", failure.message); assertEquals(null, failure.cause); assertEquals(0, failure.suppressed.size)
        }
    }
}
