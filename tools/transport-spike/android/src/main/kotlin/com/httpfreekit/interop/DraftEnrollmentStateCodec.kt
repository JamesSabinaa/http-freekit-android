package com.httpfreekit.interop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.time.format.ResolverStyle
import java.util.Base64
import java.util.Collections
import javax.net.ssl.SNIHostName

/** Research-local state only. Neither format is companion wire or an active-credential store. */
class DraftEnrollmentStateException : IllegalArgumentException("Invalid enrollment research state")

class DraftEnrollmentSeed internal constructor(
    val setupPort: Int, val credentialPort: Int, gatewayDer: ByteArray, pin: ByteArray,
    val logicalName: String, val desktopId: String, val invitationId: String,
    secret: ByteArray, val invitationExpiresAt: String,
) {
    private val gateway = gatewayDer.copyOf()
    private val gatewayPin = pin.copyOf()
    private val invitationSecret = secret.copyOf()
    val gatewayCertificateDer get() = gateway.copyOf()
    val gatewaySpkiSha256 get() = DraftEnrollmentStateChecks.b64(gatewayPin)
    fun secretForEnrollment(): String = DraftEnrollmentStateChecks.b64(invitationSecret)
    fun clearInvitationSecret() { invitationSecret.fill(0) }
    override fun toString() = "DraftEnrollmentSeed([REDACTED])"
}

class DraftEnrollmentRecovery(
    val setupPort: Int, val credentialPort: Int, val desktopId: String, gatewayPin: ByteArray,
    val logicalName: String, val invitationId: String, val enrollmentId: String, val deviceId: String,
    originalSpki: ByteArray, originalCertificateHashes: List<ByteArray>, clientLeafHash: ByteArray,
    authorityHash: ByteArray, interceptionCaHash: ByteArray, capabilities: List<String>,
    val reservationExpiresAt: String, val resultExpiresAt: String, val credentialExpiresAt: String,
) {
    private val pin = DraftEnrollmentStateChecks.copy(gatewayPin, 32)
    private val spki = DraftEnrollmentStateChecks.copy(originalSpki, 91)
    private val originalHashes = DraftEnrollmentStateChecks.hashes(originalCertificateHashes)
    private val leaf = DraftEnrollmentStateChecks.copy(clientLeafHash, 32)
    private val authority = DraftEnrollmentStateChecks.copy(authorityHash, 32)
    private val interception = DraftEnrollmentStateChecks.copy(interceptionCaHash, 32)
    private val offered = DraftEnrollmentStateChecks.capabilities(capabilities)
    init { DraftEnrollmentStateChecks.fixed {
        DraftEnrollmentStateChecks.ports(setupPort, credentialPort)
        DraftEnrollmentStateChecks.id(desktopId); DraftEnrollmentStateChecks.id(invitationId)
        DraftEnrollmentStateChecks.name(logicalName)
        DraftEnrollmentStateChecks.branded(enrollmentId, "enr_"); DraftEnrollmentStateChecks.branded(deviceId, "dev_")
        require(pin.size == 32 && spki.size == 91 && leaf.size == 32 && authority.size == 32 && interception.size == 32)
        require(originalCertificateHashes.size in 1..4 && originalHashes.size in 1..4 && originalHashes.all { it.size == 32 })
        require(capabilities.size in 1..16 && offered.size in 1..16 && offered.distinct().size == offered.size)
        require(offered.all { Regex("[a-z][a-z0-9-]{0,31}").matches(it) })
        listOf(reservationExpiresAt, resultExpiresAt, credentialExpiresAt).forEach(DraftEnrollmentStateChecks::date)
    } }
    val gatewaySpkiSha256 get() = DraftEnrollmentStateChecks.b64(pin)
    val originalDeviceSpki get() = spki.copyOf()
    val originalKeystoreCertificateHashes get() = Collections.unmodifiableList(originalHashes.map { it.copyOf() })
    val clientCertificateSha256 get() = leaf.copyOf()
    val authorityCertificateSha256 get() = authority.copyOf()
    val interceptionCaCertificateSha256 get() = interception.copyOf()
    val capabilities: List<String> get() = Collections.unmodifiableList(offered.sorted())
    override fun toString() = "DraftEnrollmentRecovery([PUBLIC MATERIAL REDACTED])"
}

object DraftEnrollmentStateCodec {
    const val MAX_INPUT_BYTES = 16384
    const val MAX_RECOVERY_BYTES = 8192
    private val seedMagic = "HFKENR1\u0000".toByteArray(Charsets.US_ASCII)
    private val recoveryMagic = "HFKREC1\u0000".toByteArray(Charsets.US_ASCII)

    fun decodeSeed(bytes: ByteArray): DraftEnrollmentSeed = DraftEnrollmentStateChecks.fixed {
        val reader = Reader(bytes, MAX_INPUT_BYTES, seedMagic)
        val setup = reader.port(); val credential = reader.port()
        DraftEnrollmentStateChecks.ports(setup, credential)
        val gateway = reader.field(1, 4096); val pin = reader.field(32, 32)
        val name = reader.ascii(1, 253).also(DraftEnrollmentStateChecks::name)
        val desktop = reader.ascii(1, 128).also(DraftEnrollmentStateChecks::id)
        val invitation = reader.ascii(1, 128).also(DraftEnrollmentStateChecks::id)
        val secret = reader.field(32, 32)
        val expiry = reader.ascii(20, 20).also(DraftEnrollmentStateChecks::date)
        reader.finished()
        DraftEnrollmentSeed(setup, credential, gateway, pin, name, desktop, invitation, secret, expiry)
    }

    fun encodeRecovery(value: DraftEnrollmentRecovery): ByteArray = DraftEnrollmentStateChecks.fixed {
        val bytes = ByteArrayOutputStream()
        val output = DataOutputStream(bytes)
        output.write(recoveryMagic); output.writeShort(value.setupPort); output.writeShort(value.credentialPort)
        fun field(data: ByteArray) { require(data.size <= 4096); output.writeShort(data.size); output.write(data) }
        fun ascii(text: String) { require(text.all { it.code in 0..127 }); field(text.toByteArray(Charsets.US_ASCII)) }
        ascii(value.desktopId); field(DraftEnrollmentStateChecks.unb64(value.gatewaySpkiSha256))
        ascii(value.logicalName); ascii(value.invitationId); ascii(value.enrollmentId); ascii(value.deviceId)
        field(value.originalDeviceSpki); field(value.clientCertificateSha256); field(value.authorityCertificateSha256)
        field(value.interceptionCaCertificateSha256)
        ascii(value.reservationExpiresAt); ascii(value.resultExpiresAt); ascii(value.credentialExpiresAt)
        val certificates = value.originalKeystoreCertificateHashes
        output.writeByte(certificates.size); certificates.forEach { field(it) }
        output.writeByte(value.capabilities.size); value.capabilities.forEach(::ascii)
        bytes.toByteArray().also { require(it.size <= MAX_RECOVERY_BYTES) }
    }

    fun decodeRecovery(bytes: ByteArray): DraftEnrollmentRecovery = DraftEnrollmentStateChecks.fixed {
        val reader = Reader(bytes, MAX_RECOVERY_BYTES, recoveryMagic)
        val setup = reader.port(); val credential = reader.port()
        val desktop = reader.ascii(1, 128); val pin = reader.field(32, 32); val name = reader.ascii(1, 253)
        val invitation = reader.ascii(1, 128); val enrollment = reader.ascii(47, 47); val device = reader.ascii(47, 47)
        val spki = reader.field(91, 91); val leaf = reader.field(32, 32); val authority = reader.field(32, 32)
        val interception = reader.field(32, 32)
        val reservation = reader.ascii(20, 20); val result = reader.ascii(20, 20); val expiry = reader.ascii(20, 20)
        val hashes = List(reader.count(4)) { reader.field(32, 32) }
        val capabilities = List(reader.count(16)) { reader.ascii(1, 32) }
        reader.finished()
        DraftEnrollmentRecovery(setup, credential, desktop, pin, name, invitation, enrollment, device,
            spki, hashes, leaf, authority, interception, capabilities, reservation, result, expiry)
    }

    private class Reader(bytes: ByteArray, maximum: Int, magic: ByteArray) {
        private val input: DataInputStream
        init {
            require(bytes.size in magic.size..maximum)
            input = DataInputStream(ByteArrayInputStream(bytes))
            require(ByteArray(magic.size).also(input::readFully).contentEquals(magic))
        }
        fun port(): Int = input.readUnsignedShort().also { require(it in 1..65535) }
        fun count(maximum: Int): Int = input.readUnsignedByte().also { require(it in 1..maximum) }
        fun field(minimum: Int, maximum: Int): ByteArray {
            val length = input.readUnsignedShort()
            require(length in minimum..maximum && input.available() >= length)
            return ByteArray(length).also(input::readFully)
        }
        fun ascii(minimum: Int, maximum: Int): String = field(minimum, maximum).also { require(it.all { byte -> byte.toInt() in 0..127 }) }.toString(Charsets.US_ASCII)
        fun finished() { require(input.read() == -1) }
    }
}

internal object DraftEnrollmentStateChecks {
    fun <T> fixed(action: () -> T): T = try { action() } catch (_: Exception) { throw DraftEnrollmentStateException() }
    fun copy(value: ByteArray, size: Int): ByteArray = fixed { require(value.size == size); value.copyOf() }
    fun hashes(values: List<ByteArray>): List<ByteArray> = fixed {
        require(values.size in 1..4)
        val result = ArrayList<ByteArray>()
        for (value in values) { require(result.size < 4); result.add(copy(value, 32)) }
        require(result.isNotEmpty()); result
    }
    fun capabilities(values: List<String>): List<String> = fixed {
        require(values.size in 1..16)
        val result = ArrayList<String>()
        for (value in values) { require(result.size < 16 && Regex("[a-z][a-z0-9-]{0,31}").matches(value)); result.add(value) }
        require(result.isNotEmpty() && result.distinct().size == result.size); result
    }
    fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun unb64(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
    fun id(value: String) { require(Regex("[A-Za-z0-9_-]{1,128}").matches(value)) }
    fun branded(value: String, prefix: String) {
        require(value.startsWith(prefix) && value.length == 47)
        val suffix = value.removePrefix(prefix); val bytes = unb64(suffix)
        require(bytes.size == 32 && b64(bytes) == suffix)
    }
    fun ports(setup: Int, credential: Int) { require(setup in 1..65535 && credential in 1..65535 && setup != credential) }
    fun name(value: String) {
        require(value.length in 1..253 && value.all { it.code in 33..126 } && ':' !in value &&
            !Regex("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+").matches(value))
        SNIHostName(value)
    }
    fun date(value: String) {
        require(Regex("20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z").matches(value))
        LocalDateTime.parse(value, DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss'Z'").withResolverStyle(ResolverStyle.STRICT))
    }
}
