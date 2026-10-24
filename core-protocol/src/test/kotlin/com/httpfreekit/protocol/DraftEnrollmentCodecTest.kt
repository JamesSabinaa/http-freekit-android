package com.httpfreekit.protocol

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

internal object DraftEnrollmentTestData {
    fun b64(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    val hash = b64(ByteArray(32))
    val otherHash = b64(ByteArray(32) { (it + 1).toByte() })
    val enrollment = "enr_$hash"
    val challenge = "ech_$otherHash"
    val device = "dev_$otherHash"
    const val date = "2028-02-29T12:00:00Z"
    val signature = b64(byteArrayOf(0x30, 6, 2, 1, 1, 2, 1, 1))
    fun fields(type: String, vararg fields: Pair<String, Any>): LinkedHashMap<String, Any> =
        linkedMapOf<String, Any>("protocolVersion" to 1, "type" to type).apply { putAll(fields) }
    fun pair() = fields("pair", "desktopId" to "desktop", "invitationId" to "invite", "invitationSecret" to hash,
        "csrDer" to b64(byteArrayOf(1)), "deviceName" to "Development phone", "capabilities" to listOf("tcp-http", "future-feature"))
    fun challenge(purpose: String = "status") = fields("pair_challenge", "desktopId" to "desktop", "gatewaySpkiSha256" to hash,
        "invitationId" to "invite", "enrollmentId" to enrollment, "challengeId" to challenge,
        "deviceSpkiSha256" to otherHash, "purpose" to purpose, "nonce" to hash, "expiresAt" to date)
    fun context(purpose: DraftEnrollmentPurpose = DraftEnrollmentPurpose.STATUS) =
        DraftEnrollmentProofContext("desktop", hash, "invite", enrollment, otherHash, purpose)
}

class DraftEnrollmentCodecTest {
    private fun create(channel: DraftEnrollmentChannel, fields: Map<String, *>) = DraftEnrollmentCodec.message(channel, fields)
    private fun wire(fields: Map<String, *>, channel: DraftEnrollmentChannel = DraftEnrollmentChannel.PAIR_REQUEST) = DraftEnrollmentCodec.encode(create(channel, fields)).toString(Charsets.UTF_8)
    private fun rejected(text: String, code: String = "invalid_message", channel: DraftEnrollmentChannel = DraftEnrollmentChannel.PAIR_REQUEST) =
        assertEquals(DraftEnrollmentDecodeResult.Rejected(code), DraftEnrollmentCodec.decode(channel, text.toByteArray(Charsets.UTF_8)))
    private fun signatureWire(bytes: ByteArray) = wire(DraftEnrollmentTestData.fields("pair_status", "desktopId" to "desktop", "invitationId" to "invite",
        "enrollmentId" to DraftEnrollmentTestData.enrollment, "challengeId" to DraftEnrollmentTestData.challenge,
        "signature" to DraftEnrollmentTestData.b64(bytes)), DraftEnrollmentChannel.STATUS_REQUEST)

    @Test fun allEightChannelsAndSuccessTypesRoundTripWithFixedCanonicalOrder() {
        val d = DraftEnrollmentTestData
        val messages = listOf(
            DraftEnrollmentChannel.PAIR_REQUEST to d.pair(),
            DraftEnrollmentChannel.CHALLENGE_REQUEST to d.fields("pair_challenge", "desktopId" to "desktop", "invitationId" to "invite", "enrollmentId" to d.enrollment, "purpose" to "status"),
            DraftEnrollmentChannel.STATUS_REQUEST to d.fields("pair_status", "desktopId" to "desktop", "invitationId" to "invite", "enrollmentId" to d.enrollment, "challengeId" to d.challenge, "signature" to d.signature),
            DraftEnrollmentChannel.CANCEL_REQUEST to d.fields("pair_cancel", "desktopId" to "desktop", "invitationId" to "invite", "enrollmentId" to d.enrollment, "challengeId" to d.challenge, "signature" to d.signature),
            DraftEnrollmentChannel.PAIR_RESPONSE to d.fields("pair_registered", "desktopId" to "desktop", "invitationId" to "invite", "enrollmentId" to d.enrollment, "deviceSpkiSha256" to d.otherHash, "reservationExpiresAt" to d.date, "resultExpiresAt" to d.date),
            DraftEnrollmentChannel.CHALLENGE_RESPONSE to d.challenge(),
            DraftEnrollmentChannel.STATUS_RESPONSE to d.fields("pair_pending", "desktopId" to "desktop", "enrollmentId" to d.enrollment, "reservationExpiresAt" to d.date, "retryAfterMillis" to 1000),
            DraftEnrollmentChannel.STATUS_RESPONSE to d.fields("pair_approved", "desktopId" to "desktop", "enrollmentId" to d.enrollment, "deviceId" to d.device, "clientCertificateDer" to "AQ", "enrollmentAuthorityDer" to "Ag", "interceptionCaCertificateSha256" to d.hash, "capabilities" to listOf("tcp-http"), "credentialExpiresAt" to d.date, "resultExpiresAt" to d.date),
            DraftEnrollmentChannel.STATUS_RESPONSE to d.fields("pair_ended", "desktopId" to "desktop", "enrollmentId" to d.enrollment, "code" to "device_revoked"),
            DraftEnrollmentChannel.CANCEL_RESPONSE to d.fields("pair_ended", "desktopId" to "desktop", "enrollmentId" to d.enrollment, "code" to "pairing_cancelled"),
        )
        for ((channel, fields) in messages) {
            val original = create(channel, fields.entries.reversed().associate { it.toPair() })
            val encoded = DraftEnrollmentCodec.encode(original)
            val decoded = DraftEnrollmentCodec.decode(channel, encoded) as DraftEnrollmentDecodeResult.Accepted
            assertArrayEquals(encoded, DraftEnrollmentCodec.encode(decoded.message))
            assertTrue(encoded.toString(Charsets.UTF_8).startsWith("{\"protocolVersion\":1,\"type\":\"${fields["type"]}\""))
            for (other in DraftEnrollmentChannel.entries.filter { it != channel }) {
                if (fields["type"] == "pair_ended" && other in setOf(DraftEnrollmentChannel.STATUS_RESPONSE, DraftEnrollmentChannel.CANCEL_RESPONSE)) continue
                assertEquals(DraftEnrollmentDecodeResult.Rejected("invalid_message"), DraftEnrollmentCodec.decode(other, encoded))
            }
        }
        val encoded = wire(d.pair())
        assertTrue(encoded.indexOf("\"desktopId\"") < encoded.indexOf("\"invitationId\""))
        assertTrue(encoded.endsWith("\"capabilities\":[\"future-feature\",\"tcp-http\"]}"))
    }

    @Test fun errorsAreAcceptedOnEveryResponseChannelButNotRequests() {
        val codes = listOf("invalid_message", "message_too_large", "unsupported_version", "unsupported_capability", "authentication_failed", "invitation_expired", "invitation_used", "pairing_limit", "pairing_unavailable")
        for (code in codes) for (channel in DraftEnrollmentChannel.entries) {
            val text = """{"protocolVersion":1,"type":"pair_error","code":"$code"}"""
            if (channel.ordinal >= 4) assertTrue(DraftEnrollmentCodec.decode(channel, text.toByteArray()) is DraftEnrollmentDecodeResult.Accepted)
            else rejected(text, channel = channel)
        }
        rejected("""{"protocolVersion":1,"type":"pair_error","code":"provider detail"}""", channel = DraftEnrollmentChannel.STATUS_RESPONSE)
    }

    @Test fun versionFollowsStructuralChecksButPrecedesMessageSchema() {
        rejected("""{"protocolVersion":2,"type":null,"unknown":"${"x".repeat(300)}"}""", "unsupported_version")
        rejected("""{"protocolVersion":2,"${"k".repeat(300)}":0}""", "unsupported_version")
        rejected("""{"protocolVersion":2147483647}""", "unsupported_version")
        for (number in listOf("0", "2147483648", "-0", "-1", "01", "1.0", "1e0", "+1", "true", "null", "\"1\"")) rejected("""{"protocolVersion":$number}""")
        for (number in listOf("-0", "1.0", "1e0", "10000000000")) rejected("""{"protocolVersion":2,"extra":$number}""")
    }

    @Test fun bodySizeUtf8BomAndTrailingMaterialAreStrict() {
        val pair = wire(DraftEnrollmentTestData.pair())
        val exact = pair + " ".repeat(16384 - pair.toByteArray().size)
        assertTrue(DraftEnrollmentCodec.decode(DraftEnrollmentChannel.PAIR_REQUEST, exact.toByteArray()) is DraftEnrollmentDecodeResult.Accepted)
        rejected(exact + " ", "message_too_large")
        assertEquals(DraftEnrollmentDecodeResult.Rejected("message_too_large"), DraftEnrollmentCodec.decode(DraftEnrollmentChannel.PAIR_REQUEST, ByteArray(16385) { 0xff.toByte() }))
        for (bytes in listOf(byteArrayOf(0xc0.toByte(), 0xaf.toByte()), byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()), byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + pair.toByteArray()))
            assertEquals(DraftEnrollmentDecodeResult.Rejected("invalid_message"), DraftEnrollmentCodec.decode(DraftEnrollmentChannel.PAIR_REQUEST, bytes))
        for (extra in listOf("{}", "null", "//comment")) rejected(pair + extra)
    }

    @Test fun decodedDuplicateNamesSurrogatesDepthMembersAndArraysPrecedeVersion() {
        rejected("""{"protocolVersion":2,"protocol\u0056ersion":1}""")
        for (value in listOf("\"\\uD800\"", "\"\\uDC00\"", "\"\\uD800x\"")) rejected("{\"protocolVersion\":2,\"extra\":$value}")
        rejected("""{"protocolVersion":2,"extra":[[[0]]]}""")
        rejected("""{"protocolVersion":2,"extra":[""" + (1..17).joinToString(",") { "0" } + "]}")
        rejected("{" + (1..17).joinToString(",") { "\"k$it\":0" } + "}")
        rejected("""{"protocolVersion":2,"extra":[[0]]}""", "unsupported_version")
        rejected("""{"protocolVersion":2,"extra":"\uD83D\uDE00"}""", "unsupported_version")
        rejected("{\"protocolVersion\":2," + (1..15).joinToString(",") { "\"k$it\":0" } + "}", "unsupported_version")
        rejected("{\"protocolVersion\":2," + (1..16).joinToString(",") { "\"k$it\":0" } + "}")
        rejected("""{"protocolVersion":2,"extra":[""" + (1..16).joinToString(",") { "0" } + "]}", "unsupported_version")
    }

    @Test fun unicodeDeviceNamesUseByteBoundsAndExactForbiddenScalars() {
        val d = DraftEnrollmentTestData
        for (name in listOf("é".repeat(64), "😀".repeat(32), "x\"\\/é")) {
            val fields = d.pair().apply { put("deviceName", name) }
            val decoded = create(DraftEnrollmentChannel.PAIR_REQUEST, fields) as DraftEnrollmentMessage.Pair
            assertEquals(name, decoded.deviceName)
        }
        for (name in listOf("", "😀".repeat(33), " x", "x ", "x\u0000", "x\u007f", "x\u0080", "x\u009f", "x\u2028", "x\u202e", "x\u2069", "x\ufeff", "\uD800")) {
            val failure = assertThrows(DraftEnrollmentException::class.java) { create(DraftEnrollmentChannel.PAIR_REQUEST, d.pair().apply { put("deviceName", name) }) }
            assertEquals("invalid_message", failure.code)
        }
    }

    @Test fun binaryIdentityDatesCapabilitiesAndPendingRetryAreBounded() {
        val d = DraftEnrollmentTestData
        for (size in listOf(1, 4096)) create(DraftEnrollmentChannel.PAIR_REQUEST, d.pair().apply { put("csrDer", d.b64(ByteArray(size) { 0xff.toByte() })) })
        for (value in listOf("", "AQ=", "AR", d.b64(ByteArray(4097)))) assertThrows(DraftEnrollmentException::class.java) { create(DraftEnrollmentChannel.PAIR_REQUEST, d.pair().apply { put("csrDer", value) }) }
        for (caps in listOf(emptyList(), listOf("tcp-http", "tcp-http"), listOf("UPPER"), listOf("a".repeat(33)), (1..17).map { "cap-$it" }))
            assertThrows(DraftEnrollmentException::class.java) { create(DraftEnrollmentChannel.PAIR_REQUEST, d.pair().apply { put("capabilities", caps) }) }
        for (date in listOf("2027-02-29T12:00:00Z", "2100-01-01T00:00:00Z", "2028-02-29T24:00:00Z", "2028-02-29T12:00:60Z", "2028-02-29T12:00:00.0Z", "2028-02-29T12:00:00+00:00"))
            assertThrows(DraftEnrollmentException::class.java) { create(DraftEnrollmentChannel.CHALLENGE_RESPONSE, d.challenge().apply { put("expiresAt", date) }) }
        val pending = d.fields("pair_pending", "desktopId" to "desktop", "enrollmentId" to d.enrollment, "reservationExpiresAt" to d.date, "retryAfterMillis" to 999)
        assertThrows(DraftEnrollmentException::class.java) { create(DraftEnrollmentChannel.STATUS_RESPONSE, pending) }
        assertThrows(DraftEnrollmentException::class.java) { create(DraftEnrollmentChannel.CHALLENGE_RESPONSE, d.challenge().apply { put("enrollmentId", "enr_${d.hash}=") }) }
    }

    @Test fun signatureShapeRejectsBerNonminimalNegativeZeroRangeAndTrailingBytes() {
        val invalid = listOf(byteArrayOf(0x30, 6, 2, 1, 0, 2, 1, 1), byteArrayOf(0x30, 6, 2, 1, 1, 2, 1, 0),
            byteArrayOf(0x30, 6, 2, 1, 0x80.toByte(), 2, 1, 1), byteArrayOf(0x30, 7, 2, 2, 0, 1, 2, 1, 1),
            byteArrayOf(0x30, 0x80.toByte(), 2, 1, 1, 2, 1, 1), byteArrayOf(0x30, 6, 2, 1, 1, 2, 1, 1, 0), ByteArray(64))
        for (bytes in invalid) assertThrows(DraftEnrollmentException::class.java) { signatureWire(bytes) }
        fun der(r: BigInteger, s: BigInteger): ByteArray {
            val a = r.toByteArray(); val b = s.toByteArray()
            return byteArrayOf(0x30, (4 + a.size + b.size).toByte(), 2, a.size.toByte()) + a + byteArrayOf(2, b.size.toByte()) + b
        }
        signatureWire(der(DraftEnrollmentChecks.ORDER - BigInteger.ONE, DraftEnrollmentChecks.ORDER - BigInteger.ONE))
        assertThrows(DraftEnrollmentException::class.java) { signatureWire(der(DraftEnrollmentChecks.ORDER, BigInteger.ONE)) }
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val signature = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(byteArrayOf(1, 2, 3)); sign() }
        signatureWire(signature)
        val rLength = signature[3].toInt(); val r = BigInteger(1, signature.copyOfRange(4, 4 + rLength))
        val sAt = 4 + rLength; val s = BigInteger(1, signature.copyOfRange(sAt + 2, signature.size))
        val alternate = der(r, DraftEnrollmentChecks.ORDER - s)
        signatureWire(alternate)
        assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(pair.public); update(byteArrayOf(1, 2, 3)); verify(alternate) })
    }

    @Test fun snapshotsCanonicalWireAndMisuseErrorsExcludeCallerMutationsAndMaterial() {
        val d = DraftEnrollmentTestData
        val caps = arrayListOf("tcp-http")
        val fields = d.pair().apply { put("capabilities", caps); put("deviceName", "PRIVATE_NAME_CANARY") }
        val message = create(DraftEnrollmentChannel.PAIR_REQUEST, fields) as DraftEnrollmentMessage.Pair
        fields.clear(); caps.clear()
        assertEquals(listOf("tcp-http"), message.capabilities)
        assertThrows(UnsupportedOperationException::class.java) { (message.capabilities as MutableList).clear() }
        val first = DraftEnrollmentCodec.encode(message); first.fill(0)
        assertTrue(DraftEnrollmentCodec.encode(message).toString(Charsets.UTF_8).contains("PRIVATE_NAME_CANARY"))
        assertFalse(message.toString().contains("PRIVATE_"))
        assertFalse(DraftEnrollmentDecodeResult.Accepted(message).toString().contains("PRIVATE_"))
        assertNotSame(message.material(), message.material())
        val failure = assertThrows(DraftEnrollmentException::class.java) { create(DraftEnrollmentChannel.PAIR_REQUEST, mapOf("PRIVATE_INPUT_CANARY" to Double.NaN)) }
        assertEquals("invalid_message", failure.message); assertNull(failure.cause)
        assertFalse(failure.toString().contains("PRIVATE_"))
    }

    @Test fun callerCollectionsCannotBypassBoundsOrExposeTheirExceptions() {
        var read = 0
        val misleading = object : AbstractList<String>() {
            override val size = 1
            override fun get(index: Int) = "cap-$index"
            override fun iterator(): Iterator<String> = object : Iterator<String> {
                override fun hasNext() = true
                override fun next(): String { read++; return "cap-$read" }
            }
        }
        assertThrows(DraftEnrollmentException::class.java) { create(DraftEnrollmentChannel.PAIR_REQUEST, DraftEnrollmentTestData.pair().apply { put("capabilities", misleading) }) }
        assertEquals(17, read)
        val failing = object : AbstractMap<String, Any>() {
            override val entries: Set<Map.Entry<String, Any>> get() = throw IllegalStateException("PRIVATE_COLLECTION_CANARY")
        }
        val failure = assertThrows(DraftEnrollmentException::class.java) { create(DraftEnrollmentChannel.PAIR_REQUEST, failing) }
        assertEquals("invalid_message", failure.message); assertNull(failure.cause)
    }
}
