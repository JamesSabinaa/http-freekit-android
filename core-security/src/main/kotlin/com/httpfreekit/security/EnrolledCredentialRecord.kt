package com.httpfreekit.security

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName

/**
 * Public material for one enrolled computer. The authority must already have been authenticated
 * for that computer; accepting a CA beside an untrusted chain does not establish that provenance.
 * No invitation, private key, route, or wire message belongs in this internal storage record.
 */
class EnrolledCredentialRecord private constructor(private val material: CredentialMaterial) {
    constructor(
        desktopId: String,
        gatewayCertificate: X509Certificate,
        gatewaySpkiSha256: String,
        logicalServerName: String,
        clientCertificateChain: List<X509Certificate>,
        authenticatedEnrollmentAuthority: X509Certificate,
    ) : this(snapshot(desktopId, gatewayCertificate, gatewaySpkiSha256, logicalServerName,
        clientCertificateChain, authenticatedEnrollmentAuthority))

    val desktopId: String get() = material.desktopId
    val gatewaySpkiSha256: String get() = material.gatewaySpkiSha256
    val logicalServerName: String get() = material.logicalServerName
    val gatewayCertificate: X509Certificate get() = decodeCertificate(material.gatewayCertificate)
    val clientCertificateChain: List<X509Certificate> get() = material.clientCertificateChain.map(::decodeCertificate)
    val authenticatedEnrollmentAuthority: X509Certificate get() = decodeCertificate(material.authenticatedEnrollmentAuthority)

    override fun toString(): String = "EnrolledCredentialRecord(publicMaterial=[REDACTED])"

    private data class CredentialMaterial(
        val desktopId: String,
        val gatewayCertificate: ByteArray,
        val gatewaySpkiSha256: String,
        val logicalServerName: String,
        val clientCertificateChain: List<ByteArray>,
        val authenticatedEnrollmentAuthority: ByteArray,
    )

    private companion object {
        fun snapshot(
            desktopId: String,
            gatewayCertificate: X509Certificate,
            gatewaySpkiSha256: String,
            logicalServerName: String,
            clientCertificateChain: List<X509Certificate>,
            authenticatedEnrollmentAuthority: X509Certificate,
        ): CredentialMaterial {
            requireDesktopId(desktopId)
            require(logicalServerName.length in 1..253 && logicalServerName.all { it.code in 33..126 }) {
                "Invalid gateway server name"
            }
            try { SNIHostName(logicalServerName) } catch (_: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid gateway server name")
            }
            require(Regex("[A-Za-z0-9_-]{43}").matches(gatewaySpkiSha256)) { "Invalid gateway pin" }
            val gateway = copyCertificate(gatewayCertificate).encoded
            val authority = copyCertificate(authenticatedEnrollmentAuthority).encoded
            var total = authority.size
            val chain = ArrayList<ByteArray>(4)
            // Bound iteration as well as reported size for caller-supplied collections.
            if (clientCertificateChain.size !in 1..4) throw CertificateException("Invalid client chain length")
            val iterator = clientCertificateChain.iterator()
            while (iterator.hasNext()) {
                if (chain.size == 4) throw CertificateException("Invalid client chain length")
                val certificate = copyCertificate(iterator.next()).encoded
                total += certificate.size
                if (total > 16 * 1024) throw CertificateException("Client certificate material is too large")
                chain += certificate
            }
            if (chain.isEmpty()) throw CertificateException("Missing client chain")
            return CredentialMaterial(desktopId, gateway, gatewaySpkiSha256, logicalServerName, chain, authority)
        }
    }
}

internal fun requireDesktopId(desktopId: String) {
    require(Regex("[A-Za-z0-9_-]{1,128}").matches(desktopId)) { "Invalid computer identity" }
}

internal fun copyCertificate(certificate: X509Certificate): X509Certificate = try {
    decodeCertificate(certificate.encoded)
} catch (_: Exception) { throw CertificateException("Invalid public certificate") }

private fun decodeCertificate(encoded: ByteArray): X509Certificate {
    if (encoded.size !in 1..4096) throw CertificateException("Invalid certificate size")
    val bytes = encoded.copyOf()
    val input = ByteArrayInputStream(bytes)
    val certificate = try {
        CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
    } catch (_: Exception) { throw CertificateException("Invalid public certificate") }
    if (input.available() != 0 || !MessageDigest.isEqual(bytes, certificate.encoded)) {
        throw CertificateException("Expected one canonical DER certificate")
    }
    return certificate
}

/** Strict, bounded application-local format. This is not companion wire or an enrollment response. */
internal object EnrolledCredentialCodec {
    const val MAX_RECORD_BYTES = 24 * 1024
    private const val MAGIC = 0x464b4352 // FKCR
    private const val VERSION = 1

    fun encode(record: EnrolledCredentialRecord): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { output ->
            output.writeInt(MAGIC)
            output.writeInt(VERSION)
            fun field(value: ByteArray) { output.writeInt(value.size); output.write(value) }
            field(record.desktopId.toByteArray(Charsets.US_ASCII))
            field(record.logicalServerName.toByteArray(Charsets.US_ASCII))
            field(record.gatewaySpkiSha256.toByteArray(Charsets.US_ASCII))
            field(record.gatewayCertificate.encoded)
            field(record.authenticatedEnrollmentAuthority.encoded)
            val chain = record.clientCertificateChain
            output.writeInt(chain.size)
            chain.forEach { field(it.encoded) }
        }
        return bytes.toByteArray().also { require(it.size <= MAX_RECORD_BYTES) { "Credential record is too large" } }
    }

    fun decode(encoded: ByteArray): EnrolledCredentialRecord {
        require(encoded.size in 1..MAX_RECORD_BYTES) { "Invalid credential record size" }
        val input = DataInputStream(ByteArrayInputStream(encoded.copyOf()))
        require(input.readInt() == MAGIC && input.readInt() == VERSION) { "Unsupported credential record format" }
        fun field(maximum: Int): ByteArray {
            val length = input.readInt()
            require(length in 1..maximum && length <= input.available()) { "Invalid credential field size" }
            return ByteArray(length).also { input.readFully(it) }
        }
        fun ascii(maximum: Int): String = field(maximum).also { value ->
            require(value.all { it.toInt() in 33..126 }) { "Invalid credential text" }
        }.toString(Charsets.US_ASCII)
        val desktopId = ascii(128)
        val name = ascii(253)
        val pin = ascii(43)
        val gateway = decodeCertificate(field(4096))
        val authority = decodeCertificate(field(4096))
        val count = input.readInt()
        require(count in 1..4) { "Invalid client chain length" }
        var total = authority.encoded.size
        val chain = ArrayList<X509Certificate>(count)
        repeat(count) {
            val certificateBytes = field(4096)
            total += certificateBytes.size
            require(total <= 16 * 1024) { "Client certificate material is too large" }
            chain += decodeCertificate(certificateBytes)
        }
        require(input.available() == 0) { "Trailing credential record data" }
        return EnrolledCredentialRecord(desktopId, gateway, pin, name, chain, authority)
    }
}
