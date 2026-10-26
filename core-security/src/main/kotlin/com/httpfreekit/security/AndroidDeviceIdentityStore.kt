package com.httpfreekit.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.cert.X509Certificate
import java.time.Clock
import javax.net.ssl.X509ExtendedKeyManager

/** Call off the main thread. Missing entries require explicit re-pairing, never silent replacement. */
class AndroidDeviceIdentityStore {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun create(desktopId: String): DeviceIdentity = synchronized(storeLock) {
        val alias = aliasFor(desktopId)
        check(!keyStore.containsAlias(alias)) { "A device identity already exists for this computer" }
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    // TLS hashes its transcript before the Keystore's delegated EC signature.
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .build(),
            )
        }.generateKeyPair()
        checkNotNull(load(desktopId)) { "Device key creation failed" }
    }

    fun load(desktopId: String): DeviceIdentity? = synchronized(storeLock) {
        val alias = aliasFor(desktopId)
        if (!keyStore.containsAlias(alias)) return@synchronized null
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: error("Device identity is unavailable; pair again")
        check(entry.privateKey.encoded == null) { "Device identity must be nonexportable" }
        val keyInfo = try {
            KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
                .getKeySpec(entry.privateKey, KeyInfo::class.java)
        } catch (failure: Exception) {
            throw IllegalStateException("Device identity capabilities are unavailable; pair again", failure)
        }
        check(keyInfo.digests.toSet().containsAll(setOf(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256))) {
            "Device identity cannot authenticate TLS; pair again"
        }
        val publicKey = entry.certificate.publicKey
        val expectedSpki = publicKey.encoded.copyOf()
        DeviceIdentity(publicKey, entry.privateKey) {
            synchronized(storeLock) {
                val current = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                current != null && MessageDigest.isEqual(expectedSpki, current.certificate.publicKey.encoded)
            }
        }
    }

    /** Original public Keystore evidence only; never installs or substitutes an issued chain. */
    fun originalCertificateChain(desktopId: String): List<X509Certificate>? = synchronized(storeLock) {
        try {
            val alias = aliasFor(desktopId)
            if (!keyStore.containsAlias(alias)) return@synchronized null
            val identity = checkNotNull(load(desktopId))
            val original = checkNotNull(keyStore.getCertificateChain(alias))
            check(original.size in 1..4)
            val chain = ArrayList<X509Certificate>(original.size)
            var total = 0
            for (certificate in original) {
                check(chain.size < 4)
                val snapshot = copyCertificate(certificate as X509Certificate)
                total += snapshot.encoded.size
                check(total <= 16384)
                chain += snapshot
            }
            check(MessageDigest.isEqual(chain.first().publicKey.encoded, identity.publicKey.encoded))
            check(identity.keyForClientAuthentication() != null)
            java.util.Collections.unmodifiableList(chain)
        } catch (_: Exception) {
            throw IllegalStateException("Original device certificate evidence is unavailable; pair again")
        }
    }

    fun delete(desktopId: String): Unit = synchronized(storeLock) {
        keyStore.deleteEntry(aliasFor(desktopId))
    }

    /**
     * Coordinates public credential records with existing-key lookup/deletion in this process.
     * Do not eagerly load here: an unusable legacy key must still be forgettable.
     * This hook never creates an identity and is not a multi-process transaction.
     */
    internal fun <T> withExistingIdentityTransaction(desktopId: String, operation: () -> T): T = synchronized(storeLock) {
        aliasFor(desktopId)
        operation()
    }

    private fun aliasFor(desktopId: String): String {
        require(Regex("[A-Za-z0-9_-]{1,128}").matches(desktopId)) { "Invalid computer identity" }
        val digest = MessageDigest.getInstance("SHA-256").digest(desktopId.toByteArray(Charsets.UTF_8))
        return "http-freekit.device.v1." + digest.joinToString("") { "%02x".format(it) }
    }

    private companion object {
        // One Android process owns these aliases. Instance locks would permit
        // concurrent generators to replace a key between check and creation.
        val storeLock = Any()
    }
}

class DeviceIdentity internal constructor(
    val publicKey: PublicKey,
    private val key: PrivateKey,
    private val isAvailable: () -> Boolean = { true },
) {
    fun enrollmentRequest(): ByteArray = EnrollmentRequest.create(publicKey, requiredKey())

    /**
     * Binds an issued chain to this original signing handle without changing any Keystore entry.
     * The enrollment authority must already be authenticated for this computer. Call off the UI thread.
     */
    fun bindEnrolledClientCertificate(
        certificateChain: List<X509Certificate>,
        trustedEnrollmentAuthority: X509Certificate,
        clock: Clock = Clock.systemUTC(),
    ): X509ExtendedKeyManager = EnrolledClientKeyManager.bind(this, certificateChain, trustedEnrollmentAuthority, clock)

    /** Bounded key-possession challenge; signing never exposes the private key. */
    fun signChallenge(challenge: ByteArray): ByteArray {
        require(challenge.size in 1..16384) { "Invalid challenge size" }
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(requiredKey())
            update(challenge)
            sign()
        }
    }

    internal fun keyForClientAuthentication(): PrivateKey? = try {
        if (isAvailable()) key else null
    } catch (_: Exception) { null }

    private fun requiredKey(): PrivateKey = keyForClientAuthentication()
        ?: error("Device identity is unavailable; pair again")

    override fun toString(): String = "DeviceIdentity(key=[NONEXPORTABLE])"
}
