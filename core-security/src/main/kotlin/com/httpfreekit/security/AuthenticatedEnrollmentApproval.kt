package com.httpfreekit.security

import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Collections
import javax.net.ssl.SNIHostName

/**
 * Immutable public evidence supplied by an already authenticated enrollment caller.
 * Construction and local decoding do not establish the evidence's provenance.
 */
class AuthenticatedEnrollmentApproval private constructor(private val material: ApprovalMaterial) {
    constructor(
        desktopId: String,
        logicalServerName: String,
        gatewaySpkiSha256: String,
        enrollmentId: String,
        deviceId: String,
        originalDeviceSpki: ByteArray,
        originalKeystoreCertificateHashes: List<ByteArray>,
        clientCertificateSha256: ByteArray,
        authorityCertificateSha256: ByteArray,
        interceptionCaCertificateSha256: ByteArray,
        capabilities: List<String>,
        credentialExpiresAtMillis: Long,
    ) : this(snapshot(desktopId, logicalServerName, gatewaySpkiSha256, enrollmentId, deviceId,
        originalDeviceSpki, originalKeystoreCertificateHashes, clientCertificateSha256,
        authorityCertificateSha256, interceptionCaCertificateSha256, capabilities,
        credentialExpiresAtMillis))

    val desktopId: String get() = material.desktopId
    val logicalServerName: String get() = material.logicalServerName
    val gatewaySpkiSha256: String get() = material.gatewaySpkiSha256
    val enrollmentId: String get() = material.enrollmentId
    val deviceId: String get() = material.deviceId
    val originalDeviceSpki: ByteArray get() = material.originalDeviceSpki.copyOf()
    val originalKeystoreCertificateHashes: List<ByteArray>
        get() = Collections.unmodifiableList(material.originalKeystoreCertificateHashes.map { it.copyOf() })
    val clientCertificateSha256: ByteArray get() = material.clientCertificateSha256.copyOf()
    val authorityCertificateSha256: ByteArray get() = material.authorityCertificateSha256.copyOf()
    val interceptionCaCertificateSha256: ByteArray get() = material.interceptionCaCertificateSha256.copyOf()
    val capabilities: List<String> get() = material.capabilities
    val credentialExpiresAtMillis: Long get() = material.credentialExpiresAtMillis

    override fun toString(): String = "AuthenticatedEnrollmentApproval(publicMaterial=[REDACTED])"

    private class ApprovalMaterial(
        val desktopId: String,
        val logicalServerName: String,
        val gatewaySpkiSha256: String,
        val enrollmentId: String,
        val deviceId: String,
        val originalDeviceSpki: ByteArray,
        val originalKeystoreCertificateHashes: List<ByteArray>,
        val clientCertificateSha256: ByteArray,
        val authorityCertificateSha256: ByteArray,
        val interceptionCaCertificateSha256: ByteArray,
        val capabilities: List<String>,
        val credentialExpiresAtMillis: Long,
    )

    private companion object {
        fun snapshot(
            desktopId: String,
            logicalServerName: String,
            gatewaySpkiSha256: String,
            enrollmentId: String,
            deviceId: String,
            originalDeviceSpki: ByteArray,
            originalKeystoreCertificateHashes: List<ByteArray>,
            clientCertificateSha256: ByteArray,
            authorityCertificateSha256: ByteArray,
            interceptionCaCertificateSha256: ByteArray,
            capabilities: List<String>,
            credentialExpiresAtMillis: Long,
        ): ApprovalMaterial = try {
            val idPattern = Regex("[A-Za-z0-9_-]{1,128}")
            require(idPattern.matches(desktopId) && idPattern.matches(enrollmentId) && idPattern.matches(deviceId))
            require(logicalServerName.length in 1..253 && logicalServerName.all { it.code in 33..126 })
            SNIHostName(logicalServerName)
            require(Regex("[A-Za-z0-9_-]{43}").matches(gatewaySpkiSha256))
            val pin = Base64.getUrlDecoder().decode(gatewaySpkiSha256)
            require(pin.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(pin) == gatewaySpkiSha256)
            require(originalDeviceSpki.size == 91)
            val spki = originalDeviceSpki.copyOf()
            requireCanonicalDeviceSpki(spki)
            val hashes = ArrayList<ByteArray>(4)
            val hashIterator = originalKeystoreCertificateHashes.iterator()
            while (hashIterator.hasNext()) {
                require(hashes.size < 4)
                hashes.add(hash(hashIterator.next()))
            }
            require(hashes.isNotEmpty())
            val offered = HashSet<String>()
            val capabilityIterator = capabilities.iterator()
            while (capabilityIterator.hasNext()) {
                require(offered.size < 16)
                val capability = capabilityIterator.next()
                require(Regex("[a-z][a-z0-9-]{0,31}").matches(capability) && offered.add(capability))
            }
            require(offered.isNotEmpty() && credentialExpiresAtMillis > 0)
            ApprovalMaterial(desktopId, logicalServerName, gatewaySpkiSha256, enrollmentId, deviceId,
                spki, hashes, hash(clientCertificateSha256), hash(authorityCertificateSha256),
                hash(interceptionCaCertificateSha256), Collections.unmodifiableList(offered.sorted()),
                credentialExpiresAtMillis)
        } catch (_: Exception) {
            throw IllegalArgumentException("Invalid enrollment approval")
        }

        fun hash(value: ByteArray): ByteArray {
            require(value.size == 32)
            return value.copyOf()
        }

        fun requireCanonicalDeviceSpki(spki: ByteArray) {
            // Exact named-curve P-256 SPKI with one uncompressed 65-byte EC point.
            val prefix = byteArrayOf(0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(),
                0x48, 0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86.toByte(),
                0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04)
            require(spki.size == 91 && spki.copyOfRange(0, prefix.size).contentEquals(prefix))
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki)) as ECPublicKey
            require(MessageDigest.isEqual(spki, key.encoded))
            val p = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
            val b = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
            val x = key.w.affineX
            val y = key.w.affineY
            require(x.signum() >= 0 && x < p && y.signum() >= 0 && y < p)
            require(y.multiply(y).mod(p) == x.multiply(x).multiply(x).subtract(x.multiply(BigInteger.valueOf(3))).add(b).mod(p))
        }
    }
}
