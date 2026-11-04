package com.httpfreekit.security

import java.security.cert.X509Certificate
import java.time.Clock
import java.util.Date

/**
 * Validated public CA material only. This snapshot neither installs trust nor establishes
 * authenticated approval provenance, current key possession, Forget state or registry authorization.
 */
class ApprovedInterceptionCa internal constructor(certificate: X509Certificate) {
    private val der = certificate.encoded.copyOf()
    val certificateDer: ByteArray get() = der.copyOf()
    val certificateSha256: ByteArray get() = InterceptionCaValidation.hash(der)
    val certificate: X509Certificate get() = InterceptionCaValidation.fixed {
        InterceptionCaValidation.certificate(der)
    }

    override fun toString(): String = "ApprovedInterceptionCa(publicMaterial=[REDACTED])"
}

/** Local preparation against the loaded approval's commitment; no fetching or trust mutation. */
object ApprovedInterceptionCaPreparation {
    /**
     * Rechecks saved certificate validity, not live authorization or key possession. The loaded
     * approval retains original-chain hashes, so separation from other original-chain keys cannot
     * be rechecked here; the original device SPKI and all saved issued-chain keys are checked.
     */
    fun prepare(
        loaded: LoadedApprovedEnrolledCredential,
        certificateDer: ByteArray,
        clock: Clock = Clock.systemUTC(),
    ): ApprovedInterceptionCa = InterceptionCaValidation.fixed {
        require(certificateDer.size in 1..4096)
        val bytes = certificateDer.copyOf()
        val now = Date.from(clock.instant())
        val certificate = InterceptionCaValidation.validate(loaded.record, bytes, now)
        ApprovedInterceptionCa(certificate)
    }
}
