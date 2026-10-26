package com.httpfreekit.security

import java.security.cert.CertificateException
import java.time.Clock
import java.util.Date
import javax.net.ssl.SNIHostName
import javax.net.ssl.X509ExtendedKeyManager

/** Shared legacy credential checks; approval provenance is a separate caller-owned boundary. */
internal object EnrolledCredentialValidation {
    fun validate(record: EnrolledCredentialRecord, identity: DeviceIdentity, clock: Clock): X509ExtendedKeyManager {
        val gateway = record.gatewayCertificate
        GatewayTrust.verifyPinnedCertificate(gateway, record.gatewaySpkiSha256, Date.from(clock.instant()))
        val logicalName = SNIHostName(record.logicalServerName).asciiName
        // The local format requires the dedicated leaf's exact DNS SAN; no CN or wildcard fallback.
        val matches = gateway.subjectAlternativeNames.orEmpty().any { entry ->
            entry.size == 2 && entry[0] == 2 && entry[1] is String &&
                logicalName.equals(entry[1] as String, ignoreCase = true)
        }
        if (!matches) throw CertificateException("Gateway server name mismatch")
        return identity.bindEnrolledClientCertificate(
            record.clientCertificateChain, record.authenticatedEnrollmentAuthority, clock,
        )
    }
}
