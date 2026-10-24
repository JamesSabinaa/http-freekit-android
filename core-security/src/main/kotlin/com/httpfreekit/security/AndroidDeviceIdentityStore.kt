package com.httpfreekit.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

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
                    .setDigests(KeyProperties.DIGEST_SHA256)
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
        DeviceIdentity(entry.certificate.publicKey, entry.privateKey)
    }

    fun delete(desktopId: String): Unit = synchronized(storeLock) {
        keyStore.deleteEntry(aliasFor(desktopId))
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

class DeviceIdentity internal constructor(val publicKey: PublicKey, private val key: PrivateKey) {
    fun enrollmentRequest(): ByteArray = EnrollmentRequest.create(publicKey, key)

    /** Bounded key-possession challenge; signing never exposes the private key. */
    fun signChallenge(challenge: ByteArray): ByteArray {
        require(challenge.size in 1..16384) { "Invalid challenge size" }
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(challenge)
            sign()
        }
    }

    override fun toString(): String = "DeviceIdentity(key=[NONEXPORTABLE])"
}
