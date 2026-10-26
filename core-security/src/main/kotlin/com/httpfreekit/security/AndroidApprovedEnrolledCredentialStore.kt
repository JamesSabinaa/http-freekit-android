package com.httpfreekit.security

import android.content.Context
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Clock
import javax.net.ssl.X509ExtendedKeyManager

internal interface ApprovedCredentialIdentities : ExistingCredentialIdentities {
    fun originalCertificateChain(desktopId: String): List<X509Certificate>?
}

/** A locally validated snapshot, not proof of approval provenance or current registry authorization. */
class LoadedApprovedEnrolledCredential internal constructor(
    val record: ApprovedEnrolledCredentialRecord,
    val clientKeyManager: X509ExtendedKeyManager,
) {
    override fun toString(): String = "LoadedApprovedEnrolledCredential(material=[REDACTED])"
}

/**
 * Opt-in, app-private no-backup storage of one complete approval/credential envelope.
 * Call off the main thread. Before save, the caller must have authenticated and validated the
 * approved response AND its setup/request context, including the enrollment authority and approval
 * bindings. Constructing, decoding or loading public material cannot establish that provenance.
 * No legacy record is read, migrated or used to synthesize approval. Successful load establishes
 * neither current registry authorization nor network readiness, renewal or interception-CA trust.
 * Transactions serialize with the shared device identity within this Android process only.
 */
class AndroidApprovedEnrolledCredentialStore internal constructor(
    private val identities: ApprovedCredentialIdentities,
    private val files: CredentialRecordFiles,
    private val clock: Clock = Clock.systemUTC(),
) {
    constructor(context: Context, clock: Clock = Clock.systemUTC()) : this(
        AndroidApprovedCredentialIdentities(AndroidDeviceIdentityStore()),
        AtomicCredentialRecordFiles(
            File(context.noBackupFilesDir, "approved-enrolled-credentials-v1"),
            ApprovedEnrolledCredentialCodec.MAX_RECORD_BYTES,
        ),
        clock,
    )

    /** Validate current identity and exact original evidence before publishing one atomic generation. */
    fun save(record: ApprovedEnrolledCredentialRecord) {
        try {
            val desktopId = record.credential.desktopId
            requireDesktopId(desktopId)
            identities.transaction(desktopId) {
                val encoded = try {
                    validate(record)
                    ApprovedEnrolledCredentialCodec.encode(record)
                } catch (_: Exception) {
                    throw EnrolledCredentialUnavailableException(EnrolledCredentialError.INVALID_CREDENTIAL)
                }
                try {
                    files.publish(recordName(desktopId), encoded)
                } catch (_: Exception) {
                    throw EnrolledCredentialUnavailableException(EnrolledCredentialError.STORAGE_FAILURE)
                }
            }
        } catch (failure: EnrolledCredentialUnavailableException) {
            throw EnrolledCredentialUnavailableException(failure.code)
        } catch (_: Exception) {
            throw EnrolledCredentialUnavailableException(EnrolledCredentialError.INVALID_CREDENTIAL)
        }
    }

    /** Null means only a genuinely absent new record; all other unusable states fail closed. */
    fun load(desktopId: String): LoadedApprovedEnrolledCredential? = try {
        requireDesktopId(desktopId)
        identities.transaction(desktopId) {
            val encoded = files.read(recordName(desktopId)) ?: return@transaction null
            val record = ApprovedEnrolledCredentialCodec.decode(encoded)
            check(record.credential.desktopId == desktopId)
            LoadedApprovedEnrolledCredential(record, validate(record))
        }
    } catch (_: Exception) {
        throw EnrolledCredentialUnavailableException(EnrolledCredentialError.INVALID_CREDENTIAL)
    }

    /**
     * Computer-identity Forget: delete the shared key FIRST, invalidating generic credentials too.
     * Then remove only this computer's new metadata/pending files. Cleanup can be retried with an
     * already absent key; no identity load, validation or creation is required to forget.
     */
    fun forget(desktopId: String) {
        try {
            requireDesktopId(desktopId)
            identities.transaction(desktopId) {
                identities.delete(desktopId)
                files.delete(recordName(desktopId))
            }
        } catch (_: Exception) {
            throw EnrolledCredentialUnavailableException(EnrolledCredentialError.STORAGE_FAILURE)
        }
    }

    private fun validate(record: ApprovedEnrolledCredentialRecord): X509ExtendedKeyManager {
        val credential = record.credential
        val approval = record.approval
        val identity = identities.load(credential.desktopId) ?: error("Device identity is missing")
        val manager = EnrolledCredentialValidation.validate(credential, identity, clock)
        check(MessageDigest.isEqual(identity.publicKey.encoded, approval.originalDeviceSpki))

        val originalChain = identities.originalCertificateChain(credential.desktopId)
            ?: error("Original identity evidence is missing")
        val expectedHashes = approval.originalKeystoreCertificateHashes
        val digest = MessageDigest.getInstance("SHA-256")
        val iterator = originalChain.iterator()
        var count = 0
        var totalBytes = 0
        while (iterator.hasNext()) {
            check(count < 4 && count < expectedHashes.size)
            val certificate = iterator.next()
            val encoded = certificate.encoded
            check(encoded.size in 1..4096)
            totalBytes += encoded.size
            check(totalBytes <= 16384)
            if (count == 0) {
                check(MessageDigest.isEqual(certificate.publicKey.encoded, identity.publicKey.encoded))
            }
            check(MessageDigest.isEqual(digest.digest(encoded), expectedHashes[count]))
            count++
        }
        check(count in 1..4 && count == expectedHashes.size)
        return manager
    }

    private fun recordName(desktopId: String): String {
        requireDesktopId(desktopId)
        return MessageDigest.getInstance("SHA-256").digest(desktopId.toByteArray(Charsets.US_ASCII))
            .joinToString("") { "%02x".format(it) } + ".credential"
    }
}

private class AndroidApprovedCredentialIdentities(
    private val store: AndroidDeviceIdentityStore,
) : ApprovedCredentialIdentities {
    override fun <T> transaction(desktopId: String, operation: () -> T): T =
        store.withExistingIdentityTransaction(desktopId, operation)
    override fun load(desktopId: String): DeviceIdentity? = store.load(desktopId)
    override fun delete(desktopId: String) = store.delete(desktopId)
    override fun originalCertificateChain(desktopId: String): List<X509Certificate>? =
        store.originalCertificateChain(desktopId)
}
