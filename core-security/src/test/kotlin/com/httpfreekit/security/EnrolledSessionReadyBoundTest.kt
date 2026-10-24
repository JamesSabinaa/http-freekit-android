package com.httpfreekit.security

import java.security.MessageDigest
import java.security.cert.CertificateException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrolledSessionReadyBoundTest {
    @Test fun eachCertificateAndTrustedPolicyCanIndependentlyLimitReadiness() {
        for (limiting in 0..4) {
            val endings = LongArray(5) { 300 }.also { it[limiting] = 60 }
            val fixture = fixture(endings)
            val bound = EnrolledSessionReadyBound(fixture, utc + endings[4] * 1000)
            assertEquals(utc + 60000, bound.notAfterMillis)
            bound.requireReady(utc + 60000, utc)
            rejected { bound.requireReady(utc + 60001, utc) }
        }
    }

    @Test fun readinessMustRemainInsideTheUnchangedLiveValidityWindow() {
        val bound = EnrolledSessionReadyBound(fixture(), utc + 120000)
        bound.requireReady(utc + 120000, utc)
        bound.requireReady(utc + 120000, utc + 119999)
        rejected { bound.requireReady(utc + 120000, utc + 120000) }
        rejected { bound.requireReady(utc, utc) }
        rejected { bound.requireReady(utc - 1, utc) }
        rejected { bound.requireReady(utc + 1, utc - 60001) }
        assertEquals(utc + 120000, bound.notAfterMillis)
    }

    @Test fun laterNotBeforeInAnySavedCertificateRejectsAnEarlierObservation() {
        for (later in 0..3) {
            val fixture = fixture(starts = LongArray(4) { -60 }.also { it[later] = 10 }, loadedAt = instant.plusSeconds(10))
            val bound = EnrolledSessionReadyBound(fixture, utc + 120000)
            rejected { bound.requireReady(utc + 120000, utc + 9999) }
            bound.requireReady(utc + 120000, utc + 10000)
        }
    }

    @Test fun unsafeTimesAndAnImpossiblePolicyWindowFailWithFixedDiagnostics() {
        val fixture = fixture()
        for (policy in listOf(Long.MIN_VALUE, Long.MAX_VALUE, utc - 60000)) rejected { EnrolledSessionReadyBound(fixture, policy) }
        val bound = EnrolledSessionReadyBound(fixture, utc + 120000)
        for (time in listOf(Long.MIN_VALUE, Long.MAX_VALUE)) {
            rejected { bound.requireReady(time, utc) }
            rejected { bound.requireReady(utc + 60000, time) }
        }
    }

    @Test fun recordCopiesAndRepeatedInspectionCannotChangeTheCapturedBoundOrExposeMaterial() {
        val fixture = fixture()
        val bound = EnrolledSessionReadyBound(fixture, utc + 120000)
        fixture.record.clientCertificateChain.first().notAfter.time = utc + 1000
        fixture.record.gatewayCertificate.encoded.fill(0)
        repeat(3) { bound.requireReady(utc + 120000, utc) }
        assertEquals(utc + 120000, bound.notAfterMillis)
        val text = bound.toString()
        for (secret in listOf(fixture.record.desktopId, fixture.record.gatewaySpkiSha256, fixture.record.logicalServerName)) assertFalse(text.contains(secret))
        assertTrue(text.contains("REDACTED"))
    }

    private fun fixture(
        endings: LongArray = LongArray(5) { 300 }, starts: LongArray = LongArray(4) { -60 }, loadedAt: Instant = instant,
    ): LoadedEnrolledCredential {
        val gateway = HeldCertificate.Builder().ecdsa256().commonName("lifetime-canary.invalid")
            .addSubjectAlternativeName("lifetime-canary.invalid").validityInterval(utc + starts[0] * 1000, utc + endings[0] * 1000).build().certificate
        val authority = TestEnrollmentCertificates.authority(name = "CN=Readiness root", notBefore = instant.plusSeconds(starts[1]), notAfter = instant.plusSeconds(endings[1]))
        val intermediate = TestEnrollmentCertificates.authority(name = "CN=Readiness intermediate", issuer = authority, pathLength = 0,
            notBefore = instant.plusSeconds(starts[2]), notAfter = instant.plusSeconds(endings[2]))
        val keys = TestEnrollmentCertificates.keyPair()
        val leaf = TestEnrollmentCertificates.client(keys.public, intermediate,
            notBefore = instant.plusSeconds(starts[3]), notAfter = instant.plusSeconds(endings[3]))
        val identity = DeviceIdentity(keys.public, keys.private)
        val chain = listOf(leaf, intermediate.certificate)
        val manager = identity.bindEnrolledClientCertificate(chain, authority.certificate, Clock.fixed(loadedAt, ZoneOffset.UTC))
        val pin = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(gateway.publicKey.encoded))
        return LoadedEnrolledCredential(EnrolledCredentialRecord("bound-private-desktop", gateway, pin,
            "lifetime-canary.invalid", chain, authority.certificate), manager)
    }

    private fun rejected(action: () -> Unit) {
        try { action(); throw AssertionError("Expected fixed readiness rejection") }
        catch (failure: CertificateException) {
            assertEquals("Enrolled session readiness is unavailable", failure.message)
            assertEquals(null, failure.cause)
            assertEquals(0, failure.suppressed.size)
        }
    }
    companion object {
        private val instant = Instant.parse("2026-10-24T12:00:00Z")
        private val utc = instant.toEpochMilli()
    }
}
