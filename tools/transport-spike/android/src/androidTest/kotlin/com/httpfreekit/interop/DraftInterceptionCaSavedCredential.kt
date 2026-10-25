package com.httpfreekit.interop

import android.content.Context
import com.httpfreekit.security.AndroidDeviceIdentityStore
import com.httpfreekit.security.AndroidEnrolledCredentialStore
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.cert.X509Certificate

/** Existing-key lookup only. The original Keystore chain is never replaced by the issued chain. */
internal object DraftInterceptionCaSavedCredential {
    private const val MAX_LOOKUP_ALIASES = 64
    fun open(context: Context, recovery: DraftEnrollmentRecovery, resolvedDialAddress: InetSocketAddress): DraftInterceptionCaClient =
        DraftInterceptionCaChecks.fixed(DraftInterceptionCaFailure.BINDING) {
            val loaded = checkNotNull(AndroidEnrolledCredentialStore(context.applicationContext).load(recovery.desktopId))
            val identity = checkNotNull(AndroidDeviceIdentityStore().load(recovery.desktopId))
            val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val candidates = ArrayList<String>(2)
            val aliases = keys.aliases()
            var scanned = 0
            while (aliases.hasMoreElements()) {
                // Existing identity APIs expose no original certificate chain. A larger research
                // namespace requires repair rather than an unbounded scan or an issued-chain fallback.
                check(scanned++ < MAX_LOOKUP_ALIASES)
                val alias = aliases.nextElement()
                if (keys.getCertificate(alias)?.publicKey?.encoded?.contentEquals(identity.publicKey.encoded) == true) {
                    candidates += alias
                    check(candidates.size == 1)
                }
            }
            val entry = keys.getEntry(candidates.single(), null) as KeyStore.PrivateKeyEntry
            check(entry.privateKey.encoded == null)
            val chain = entry.certificateChain.also { check(it.size in 1..4) }.map { it as X509Certificate }
            check(chain.first().publicKey.encoded.contentEquals(identity.publicKey.encoded))
            DraftInterceptionCaClient(loaded.record, loaded.clientKeyManager, chain, recovery, resolvedDialAddress)
        }
    override fun toString() = "DraftInterceptionCaSavedCredential([REDACTED])"
}
