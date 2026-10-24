package com.httpfreekit.protocol

import java.io.File
import java.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingInvitationTest {
    private val now = Instant.parse("2026-10-24T12:00:00Z")
    private val valid = File("protocol/fixtures/pairing-valid.json").readText()

    private fun changed(field: String, value: kotlinx.serialization.json.JsonElement): String {
        val fields = (Json.parseToJsonElement(valid) as JsonObject).toMutableMap()
        fields[field] = value
        return JsonObject(fields).toString()
    }

    private fun rejected(payload: String, error: PairingError = PairingError.INVALID_MESSAGE) {
        assertEquals(PairingParseResult.Rejected(error), PairingInvitationParser.parse(payload, now))
    }

    @Test fun acceptsFixtureWithoutAuthorizingTraffic() {
        val result = PairingInvitationParser.parse(valid, now) as PairingParseResult.Accepted
        assertEquals("Development computer", result.invitation.displayName)
        assertEquals(GatewayEndpoint(TransportMode.USB, "127.0.0.1", 8766), result.invitation.endpoints.single())
        assertEquals(43, result.invitation.invitationSecret.forEnrollment().length)
    }

    @Test fun sharedRejectionFixtures() {
        rejected(File("protocol/fixtures/pairing-malformed.json").readText())
        rejected(File("protocol/fixtures/pairing-version-mismatch.json").readText(), PairingError.UNSUPPORTED_VERSION)
        rejected(File("protocol/fixtures/pairing-expired.json").readText(), PairingError.INVITATION_EXPIRED)
    }

    @Test fun expiryBoundaryIsExclusive() {
        val expiry = Instant.parse("2026-10-24T12:05:00Z")
        assertTrue(PairingInvitationParser.parse(valid, expiry.minusNanos(1)) is PairingParseResult.Accepted)
        assertEquals(PairingParseResult.Rejected(PairingError.INVITATION_EXPIRED), PairingInvitationParser.parse(valid, expiry))
    }

    @Test fun rejectsOversizedCharactersAndUtf8Bytes() {
        rejected(" ".repeat(16385), PairingError.MESSAGE_TOO_LARGE)
        rejected("é".repeat(8193), PairingError.MESSAGE_TOO_LARGE)
    }

    @Test fun rejectsMalformedAndWrongTypes() {
        listOf("null", "[]", "{}", "{", valid + "garbage", valid.replace("\"protocolVersion\": 1", "\"protocolVersion\": \"1\""))
            .forEach { rejected(it) }
        rejected(changed("displayName", JsonPrimitive(1)))
        rejected(changed("kind", JsonPrimitive("other")))
        rejected(changed("unknownRequiredField", JsonPrimitive(true)))
    }

    @Test fun validatesCredentialsAndNamesWithoutEchoingInput() {
        listOf("invitationSecret", "gatewaySpkiSha256").forEach { field ->
            listOf("", "a".repeat(42), "A".repeat(42) + "B", "=".repeat(43), "A".repeat(44))
                .forEach { rejected(changed(field, JsonPrimitive(it))) }
        }
        listOf("", "a\nb", "a".repeat(129)).forEach { rejected(changed("displayName", JsonPrimitive(it))) }
        listOf("https://gateway.invalid", "gateway.invalid/", "*.invalid", "a..invalid").forEach {
            rejected(changed("serverName", JsonPrimitive(it)))
        }
        val result = PairingInvitationParser.parse(valid, now) as PairingParseResult.Accepted
        assertFalse(result.toString().contains(result.invitation.invitationSecret.forEnrollment()))
        assertEquals("[REDACTED]", result.invitation.invitationSecret.toString())
    }

    @Test fun validatesEndpointPortModeAndHost() {
        listOf("0", "65536", "-1", "8766.5", "\"8766\"").forEach {
            rejected(valid.replace("8766", it))
        }
        listOf("http://evil.invalid", "host/path", "user@host", "127.0.0.01", "256.0.0.1", "fe80::1%eth0").forEach {
            rejected(valid.replace("127.0.0.1", it).replace("\"usb\"", "\"lan\""))
        }
        rejected(valid.replace("127.0.0.1", "desktop.invalid"))
        rejected(valid.replace("\"usb\"", "\"relay\""))
        listOf("::1", "2001:db8::1", "192.168.1.2", "desktop.example").forEach {
            assertTrue(PairingInvitationParser.parse(valid.replace("127.0.0.1", it).replace("\"usb\"", "\"lan\""), now) is PairingParseResult.Accepted)
        }
    }

    @Test fun rejectsNestedInputWithoutCrashingAndBoundsEndpointLists() {
        rejected("[".repeat(4000) + "0" + "]".repeat(4000))
        val root = Json.parseToJsonElement(valid) as JsonObject
        val endpoint = (root["endpoints"] as kotlinx.serialization.json.JsonArray).single()
        rejected(changed("endpoints", kotlinx.serialization.json.JsonArray(emptyList())))
        rejected(changed("endpoints", kotlinx.serialization.json.JsonArray(List(9) { endpoint })))
        rejected(changed("endpoints", kotlinx.serialization.json.JsonArray(List(2) { endpoint })))
        listOf("not-a-date", "2026-10-24T12:05:00+01:00", "2026-13-24T12:05:00Z").forEach {
            rejected(changed("expiresAt", JsonPrimitive(it)))
        }
    }
}
