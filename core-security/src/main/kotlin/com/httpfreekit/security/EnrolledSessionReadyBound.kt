package com.httpfreekit.security

import java.security.cert.CertificateException

/**
 * Copied public validity bounds from an already validated saved credential and trusted policy.
 * This is a readiness guard, not a registry authorizer, clock, timer or active-session owner.
 * Feed the original accepted readiness to the UTC/monotonic session owner and keep its deadline
 * worker running during blocked I/O. Never replace an overlong peer expiry with this bound.
 */
class EnrolledSessionReadyBound(loaded: LoadedEnrolledCredential, policyExpiresAtMillis: Long) {
    private val notBeforeMillis: Long
    val notAfterMillis: Long

    init {
        try {
            val record = loaded.record
            val certificates = listOf(record.gatewayCertificate, record.authenticatedEnrollmentAuthority) + record.clientCertificateChain
            notBeforeMillis = certificates.maxOf { it.notBefore.time }
            notAfterMillis = minOf(policyExpiresAtMillis, certificates.minOf { it.notAfter.time })
            if (!safe(policyExpiresAtMillis) || !safe(notBeforeMillis) || !safe(notAfterMillis) || notBeforeMillis >= notAfterMillis) invalid()
        } catch (_: Exception) { invalid() }
    }

    /** Inspection only: reads neither time nor key state, and cannot extend or reset a deadline. */
    fun requireReady(expiresAtMillis: Long, observedUtcMillis: Long) {
        if (!safe(expiresAtMillis) || !safe(observedUtcMillis) || observedUtcMillis < notBeforeMillis ||
            observedUtcMillis >= notAfterMillis || expiresAtMillis <= observedUtcMillis || expiresAtMillis > notAfterMillis) invalid()
    }

    override fun toString() = "EnrolledSessionReadyBound([REDACTED])"

    private fun safe(value: Long) = value in -9007199254740991L..9007199254740991L
    private fun invalid(): Nothing = throw CertificateException("Enrolled session readiness is unavailable")
}
