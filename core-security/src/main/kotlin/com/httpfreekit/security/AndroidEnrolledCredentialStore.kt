package com.httpfreekit.security

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.time.Clock
import java.util.Date
import javax.net.ssl.SNIHostName
import javax.net.ssl.X509ExtendedKeyManager

enum class EnrolledCredentialError { INVALID_CREDENTIAL, STORAGE_FAILURE }

/** Safe status only: underlying certificate/provider/I/O errors can contain identifying material. */
class EnrolledCredentialUnavailableException internal constructor(val code: EnrolledCredentialError) :
    IllegalStateException("Saved credential is unavailable: $code")

/** A validated snapshot plus a fresh manager retaining the original existing signing handle. */
class LoadedEnrolledCredential internal constructor(
    val record: EnrolledCredentialRecord,
    val clientKeyManager: X509ExtendedKeyManager,
) {
    override fun toString(): String = "LoadedEnrolledCredential(material=[REDACTED])"
}

/**
 * App-private, excluded-from-backup public enrollment records. Call off the main thread.
 * The explicit enrollment authority's authenticated provenance remains the caller's responsibility.
 * Existing keys and filesystem operations are serialized within this Android process only.
 */
class AndroidEnrolledCredentialStore internal constructor(
    private val identities: ExistingCredentialIdentities,
    private val files: CredentialRecordFiles,
    private val clock: Clock = Clock.systemUTC(),
) {
    constructor(context: Context, clock: Clock = Clock.systemUTC()) : this(
        AndroidCredentialIdentities(AndroidDeviceIdentityStore()),
        AtomicCredentialRecordFiles(File(context.noBackupFilesDir, "enrolled-credentials-v1")),
        clock,
    )

    /** Validate the frozen public record and current key before publishing that exact snapshot. */
    fun save(record: EnrolledCredentialRecord): Unit = identities.transaction(record.desktopId) {
        val encoded = try {
            validate(record)
            EnrolledCredentialCodec.encode(record)
        } catch (_: Exception) { throw EnrolledCredentialUnavailableException(EnrolledCredentialError.INVALID_CREDENTIAL) }
        try { files.publish(recordName(record.desktopId), encoded) }
        catch (_: Exception) { throw EnrolledCredentialUnavailableException(EnrolledCredentialError.STORAGE_FAILURE) }
    }

    /** Null means no published metadata. All other unusable states fail closed without key creation. */
    fun load(desktopId: String): LoadedEnrolledCredential? {
        requireDesktopId(desktopId)
        return identities.transaction(desktopId) {
            try {
                val encoded = files.read(recordName(desktopId)) ?: return@transaction null
                val record = EnrolledCredentialCodec.decode(encoded)
                check(record.desktopId == desktopId) { "Saved computer identity mismatch" }
                LoadedEnrolledCredential(record, validate(record))
            } catch (_: Exception) {
                throw EnrolledCredentialUnavailableException(EnrolledCredentialError.INVALID_CREDENTIAL)
            }
        }
    }

    /** Key first: interrupted metadata cleanup can never revive a usable saved credential. */
    fun forget(desktopId: String): Unit {
        requireDesktopId(desktopId)
        identities.transaction(desktopId) {
            try {
                identities.delete(desktopId)
                files.delete(recordName(desktopId))
            } catch (_: Exception) {
                throw EnrolledCredentialUnavailableException(EnrolledCredentialError.STORAGE_FAILURE)
            }
        }
    }

    private fun validate(record: EnrolledCredentialRecord): X509ExtendedKeyManager {
        val identity = identities.load(record.desktopId) ?: error("Device identity is missing")
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

    private fun recordName(desktopId: String): String {
        requireDesktopId(desktopId)
        return MessageDigest.getInstance("SHA-256").digest(desktopId.toByteArray(Charsets.US_ASCII))
            .joinToString("") { "%02x".format(it) } + ".credential"
    }
}

internal interface ExistingCredentialIdentities {
    fun <T> transaction(desktopId: String, operation: () -> T): T
    fun load(desktopId: String): DeviceIdentity?
    fun delete(desktopId: String)
}

private class AndroidCredentialIdentities(private val store: AndroidDeviceIdentityStore) : ExistingCredentialIdentities {
    override fun <T> transaction(desktopId: String, operation: () -> T): T =
        store.withExistingIdentityTransaction(desktopId, operation)
    override fun load(desktopId: String): DeviceIdentity? = store.load(desktopId)
    override fun delete(desktopId: String) = store.delete(desktopId)
}

internal interface CredentialRecordFiles {
    fun read(name: String): ByteArray?
    fun publish(name: String, encoded: ByteArray)
    fun delete(name: String)
}

/** Same-directory sync + atomic rename. Unsupported atomic publication fails without a fallback. */
internal class AtomicCredentialRecordFiles(private val directory: File) : CredentialRecordFiles {
    override fun read(name: String): ByteArray? {
        val path = target(name).toPath()
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) return null
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw IOException("Invalid credential record file")
        return FileInputStream(path.toFile()).use { input ->
            val result = ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (true) {
                val count = input.read(buffer, 0, minOf(buffer.size, EnrolledCredentialCodec.MAX_RECORD_BYTES + 1 - result.size()))
                if (count < 0) break
                result.write(buffer, 0, count)
                if (result.size() > EnrolledCredentialCodec.MAX_RECORD_BYTES) throw IOException("Credential record is too large")
            }
            result.toByteArray()
        }
    }

    override fun publish(name: String, encoded: ByteArray) {
        require(encoded.size in 1..EnrolledCredentialCodec.MAX_RECORD_BYTES) { "Invalid credential record size" }
        val destination = target(name).toPath()
        Files.createDirectories(directory.toPath())
        val temporary = Files.createTempFile(directory.toPath(), "$name.", ".pending")
        var failure: Exception? = null
        try {
            FileOutputStream(temporary.toFile()).use { output -> output.write(encoded); output.fd.sync() }
            Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (caught: Exception) {
            failure = caught
            throw caught
        } finally {
            try { Files.deleteIfExists(temporary) } catch (cleanup: Exception) {
                if (failure == null) throw cleanup else failure.addSuppressed(cleanup)
            }
        }
    }

    override fun delete(name: String) {
        val destination = target(name).toPath()
        Files.deleteIfExists(destination)
        if (!Files.exists(directory.toPath())) return
        Files.newDirectoryStream(directory.toPath(), "$name.*.pending").use { pending ->
            pending.forEach { Files.deleteIfExists(it) }
        }
    }

    private fun target(name: String): File {
        require(Regex("[a-f0-9]{64}\\.credential").matches(name)) { "Invalid credential record name" }
        return File(directory, name)
    }
}
