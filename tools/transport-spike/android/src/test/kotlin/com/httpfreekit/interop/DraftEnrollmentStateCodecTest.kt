package com.httpfreekit.interop

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import org.junit.Assert.*
import org.junit.Test

class DraftEnrollmentStateCodecTest {
    private fun seed(name: String = "enrollment-research.invalid", desktop: String = "desktop", expiry: String = "2028-02-29T12:00:00Z"): ByteArray {
        val bytes = ByteArrayOutputStream(); val out = DataOutputStream(bytes)
        out.write(byteArrayOf(0x48, 0x46, 0x4b, 0x45, 0x4e, 0x52, 0x31, 0))
        out.writeShort(31234); out.writeShort(31235)
        for (field in listOf(byteArrayOf(1), ByteArray(32) { 7 }, name.toByteArray(), desktop.toByteArray(),
            "invite".toByteArray(), ByteArray(32) { 9 }, expiry.toByteArray())) { out.writeShort(field.size); out.write(field) }
        return bytes.toByteArray()
    }
    private fun record(pin: ByteArray = ByteArray(32), hashes: List<ByteArray> = listOf(ByteArray(32)),
        capabilities: List<String> = listOf("tcp-http", "tcp-https-connect")) = DraftEnrollmentRecovery(
        31234, 31235, "PRIVATE_DESKTOP_CANARY", pin, "enrollment-research.invalid", "invite",
        "enr_" + "A".repeat(43), "dev_" + "A".repeat(43), ByteArray(91) { 1 }, hashes,
        ByteArray(32) { 2 }, ByteArray(32) { 3 }, ByteArray(32) { 4 }, capabilities,
        "2028-02-29T12:00:00Z", "2028-02-29T13:00:00Z", "2028-03-01T12:00:00Z")

    @Test fun independentSeedFramingDecodesExactFieldsAndCopiesMaterial() {
        val input = seed()
        val value = DraftEnrollmentStateCodec.decodeSeed(input)
        input.fill(0)
        assertEquals(31234, value.setupPort); assertEquals(31235, value.credentialPort)
        assertEquals("enrollment-research.invalid", value.logicalName); assertEquals("desktop", value.desktopId)
        assertArrayEquals(byteArrayOf(1), value.gatewayCertificateDer)
        value.gatewayCertificateDer.fill(0)
        assertArrayEquals(byteArrayOf(1), value.gatewayCertificateDer)
        assertNotEquals("A".repeat(43), value.secretForEnrollment())
        value.clearInvitationSecret(); assertEquals("A".repeat(43), value.secretForEnrollment())
        assertFalse(value.toString().contains("desktop"))
    }
    @Test fun seedRejectsEveryTruncationTrailingBytesOversizeAndWrongMagic() {
        val valid = seed()
        for (length in 0 until valid.size) assertThrows(DraftEnrollmentStateException::class.java) { DraftEnrollmentStateCodec.decodeSeed(valid.copyOf(length)) }
        for (bad in listOf(valid + byteArrayOf(0), ByteArray(16385), valid.copyOf().also { it[0] = 0 },
            valid.copyOf().also { it[12] = 0xff.toByte(); it[13] = 0xff.toByte() },
            valid.copyOf().also { it[8] = 0; it[9] = 0 }, valid.copyOf().also { it[11] = it[9] })) {
            assertThrows(DraftEnrollmentStateException::class.java) { DraftEnrollmentStateCodec.decodeSeed(bad) }
        }
    }
    @Test fun seedRejectsNonAsciiIpNamesInvalidIdsAndCalendarValues() {
        for (input in listOf(seed(name = "127.0.0.1"), seed(name = "::1"), seed(name = "invalid name"),
            seed(name = "é.invalid"), seed(desktop = "bad id"), seed(expiry = "2027-02-29T12:00:00Z"),
            seed(expiry = "2100-01-01T00:00:00Z"))) assertThrows(DraftEnrollmentStateException::class.java) { DraftEnrollmentStateCodec.decodeSeed(input) }
    }
    @Test fun recoveryRoundTripRetainsEveryBindingWithoutMutableAliases() {
        val pin = ByteArray(32) { 8 }; val hash = ByteArray(32) { 9 }; val caps = arrayListOf("tcp-http", "tcp-https-connect")
        val value = record(pin, listOf(hash), caps)
        val wire = DraftEnrollmentStateCodec.encodeRecovery(value)
        pin.fill(0); hash.fill(0); caps.clear()
        val restored = DraftEnrollmentStateCodec.decodeRecovery(wire)
        assertArrayEquals(wire, DraftEnrollmentStateCodec.encodeRecovery(restored))
        assertEquals(value.gatewaySpkiSha256, restored.gatewaySpkiSha256)
        assertArrayEquals(value.originalDeviceSpki, restored.originalDeviceSpki)
        assertArrayEquals(ByteArray(32) { 9 }, restored.originalKeystoreCertificateHashes.single())
        restored.originalKeystoreCertificateHashes.single().fill(0)
        assertArrayEquals(ByteArray(32) { 9 }, restored.originalKeystoreCertificateHashes.single())
        assertEquals(listOf("tcp-http", "tcp-https-connect").sorted(), restored.capabilities)
        assertFalse(restored.toString().contains("PRIVATE_DESKTOP_CANARY"))
    }
    @Test fun recoveryRejectsTruncationTrailingCorruptionAndInvalidCollections() {
        val wire = DraftEnrollmentStateCodec.encodeRecovery(record())
        for (length in 0 until wire.size) assertThrows(DraftEnrollmentStateException::class.java) { DraftEnrollmentStateCodec.decodeRecovery(wire.copyOf(length)) }
        for (bad in listOf(wire + byteArrayOf(0), ByteArray(8193), wire.copyOf().also { it[0] = 0 }))
            assertThrows(DraftEnrollmentStateException::class.java) { DraftEnrollmentStateCodec.decodeRecovery(bad) }
        for (hashes in listOf(emptyList(), List(5) { ByteArray(32) }, listOf(ByteArray(31))))
            assertThrows(DraftEnrollmentStateException::class.java) { record(hashes = hashes) }
        for (caps in listOf(emptyList(), listOf("tcp-http", "tcp-http"), listOf("UPPER"), List(17) { "cap-$it" }))
            assertThrows(DraftEnrollmentStateException::class.java) { record(capabilities = caps) }
        val error = assertThrows(DraftEnrollmentStateException::class.java) { record(pin = ByteArray(33)) }
        assertNull(error.cause); assertEquals("Invalid enrollment research state", error.message)
    }
}
