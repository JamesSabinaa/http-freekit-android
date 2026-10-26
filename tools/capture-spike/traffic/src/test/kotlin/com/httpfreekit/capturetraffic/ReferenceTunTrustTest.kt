package com.httpfreekit.capturetraffic

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.Socket
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import org.junit.Assert.*
import org.junit.Test

class ReferenceTunTrustTest {
    @Test fun scopedCanonicalCaDoesNotChangeDefaultContext() {
        val before = SSLContext.getDefault()
        val material = ReferenceTunTestCertificates.authority()
        val bytes = material.certificate.encoded
        val trust = ReferenceTunTrust.create(bytes)
        bytes.fill(0)
        assertNotSame(before, trust.context)
        assertSame(before, SSLContext.getDefault())
        assertNotNull(trust.context.socketFactory)
    }

    @Test fun hostileCaProfilesFailBeforeUse() {
        val invalid = listOf(
            ReferenceTunTestCertificates.authority(ca = false),
            ReferenceTunTestCertificates.authority(signingUsage = false),
            ReferenceTunTestCertificates.authority(ekuClient = true),
            ReferenceTunTestCertificates.authority(unknownCritical = true),
            ReferenceTunTestCertificates.authority(expired = true),
            ReferenceTunTestCertificates.authority(wrongSigner = true),
            ReferenceTunTestCertificates.authority(weakRsa = true),
        )
        for (material in invalid) assertThrows(Exception::class.java) { ReferenceTunTrust.create(material.certificate.encoded) }
    }

    @Test fun nonDerEmptyOversizeConcatenatedPemAndNonminimalLengthsFail() {
        val valid = ReferenceTunTestCertificates.authority().certificate.encoded
        val invalid = listOf(ByteArray(0), ByteArray(4097), "-----BEGIN CERTIFICATE-----canary".toByteArray(),
            valid + valid, valid.copyOf(valid.size - 1), byteArrayOf(0x30, 0x80.toByte(), 0, 0),
            byteArrayOf(0x30, 0x81.toByte(), 0), byteArrayOf(0x30, 3, 2, 1, 0) + byteArrayOf(0))
        for (bytes in invalid) assertThrows(Exception::class.java) { ReferenceTunTrust.create(bytes) }
        for (bytes in listOf(byteArrayOf(0x30, 4, 2, 2, 0, 1), byteArrayOf(0x30, 3, 1, 1, 1),
            byteArrayOf(0x30, 3, 3, 1, 1))) {
            assertThrows(IllegalStateException::class.java) { ReferenceTunTrust.canonicalDer(bytes) }
        }
    }

    /** Actual local JSSE chain/name checks, not Android or authenticated-close-notify evidence. */
    @Test fun realScopedTlsChecksChainAndHostname() {
        val authority = ReferenceTunTestCertificates.authority()
        val unrelated = ReferenceTunTestCertificates.authority()
        for (case in 0..2) {
            val leaf = ReferenceTunTestCertificates.leaf(authority, if (case == 2) "wrong-reference.invalid" else ReferenceTunHttpResponse.HOST)
            val serverContext = ReferenceTunTestCertificates.serverContext(leaf, authority)
            val listener = serverContext.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress())
            var serverFailed = false
            val worker = Thread {
                try {
                    (listener.accept() as SSLSocket).use { socket ->
                        socket.soTimeout = 5000
                        socket.startHandshake()
                        socket.outputStream.write(42)
                        socket.outputStream.flush()
                    }
                } catch (_: Exception) { serverFailed = true }
            }
            worker.start()
            try {
                val trusted = ReferenceTunTrust.create((if (case == 1) unrelated else authority).certificate.encoded)
                Socket(InetAddress.getLoopbackAddress(), listener.localPort).use { raw ->
                    val tls = trusted.context.socketFactory.createSocket(raw, ReferenceTunHttpResponse.HOST, listener.localPort, false) as SSLSocket
                    tls.use {
                        it.soTimeout = 5000
                        ReferenceTunTrust.prepare(it, 26)
                        assertEquals("HTTPS", it.sslParameters.endpointIdentificationAlgorithm)
                        assertEquals(ReferenceTunHttpResponse.HOST, (it.sslParameters.serverNames.single() as javax.net.ssl.SNIHostName).asciiName)
                        if (case == 0) {
                            it.startHandshake()
                            assertEquals(42, it.inputStream.read())
                        } else assertThrows(SSLException::class.java) { it.startHandshake() }
                    }
                }
            } finally {
                listener.close()
                worker.join(6000)
                assertFalse(worker.isAlive)
            }
            if (case == 0) assertFalse(serverFailed)
        }
    }
}

/** Public test material generated locally through standard JCA; never production trust/signing data. */
internal object ReferenceTunTestCertificates {
    data class Material(val certificate: X509Certificate, val keys: KeyPair)
    fun authority(ca: Boolean = true, signingUsage: Boolean = true, ekuClient: Boolean = false,
        unknownCritical: Boolean = false, expired: Boolean = false, wrongSigner: Boolean = false,
        weakRsa: Boolean = false): Material {
        val keys = keys(weakRsa)
        return certificate(keys, keys, ca, signingUsage, ekuClient, unknownCritical, expired, wrongSigner, null)
    }
    fun leaf(authority: Material, hostname: String): Material = certificate(keys(), authority.keys, false, false, false, false, false, false, hostname)
    private fun keys(rsa: Boolean = false): KeyPair = if (rsa) KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        else KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun certificate(keys: KeyPair, signer: KeyPair, ca: Boolean, signingUsage: Boolean, ekuClient: Boolean,
        unknownCritical: Boolean, expired: Boolean, wrongSigner: Boolean, hostname: String?): Material {
        val rsa = signer.public.algorithm == "RSA"
        val algorithm = if (rsa) der(0x30, oid(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 11) + der(5, byteArrayOf()))
            else der(0x30, oid(0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2))
        val name = der(0x30, der(0x31, der(0x30, oid(0x55, 4, 3) + der(12, "Reference test".toByteArray()))))
        val validity = der(0x30, der(23, "200101000000Z".toByteArray()) + der(23, (if (expired) "210101000000Z" else "490101000000Z").toByteArray()))
        fun extension(id: ByteArray, value: ByteArray, critical: Boolean = true) = der(0x30, id +
            (if (critical) der(1, byteArrayOf(0xff.toByte())) else byteArrayOf()) + der(4, value))
        var extensions = extension(oid(0x55, 0x1d, 0x13), der(0x30, if (ca) der(1, byteArrayOf(0xff.toByte())) + der(2, byteArrayOf(0)) else byteArrayOf())) +
            extension(oid(0x55, 0x1d, 0x0f), der(3, if (signingUsage) byteArrayOf(1, 6) else byteArrayOf(7, 0x80.toByte())))
        if (ekuClient || hostname != null) extensions += extension(oid(0x55, 0x1d, 0x25), der(0x30, oid(0x2b, 6, 1, 5, 5, 7, 3, if (ekuClient) 2 else 1)), false)
        if (unknownCritical) extensions += extension(oid(0x2a, 3, 4), der(5, byteArrayOf()))
        if (hostname != null) extensions += extension(oid(0x55, 0x1d, 0x11), der(0x30, der(0x82, hostname.toByteArray())), false)
        val serial = BigInteger(1, java.security.MessageDigest.getInstance("SHA-256").digest(keys.public.encoded).copyOf(12)).toByteArray()
        val tbs = der(0x30, der(0xa0, der(2, byteArrayOf(2))) + der(2, serial) + algorithm + name + validity + name + keys.public.encoded + der(0xa3, der(0x30, extensions)))
        val signature = Signature.getInstance(if (rsa) "SHA256withRSA" else "SHA256withECDSA").apply {
            initSign(if (wrongSigner) ReferenceTunTestCertificates.keys().private else signer.private)
            update(tbs)
        }.sign()
        val bytes = der(0x30, tbs + algorithm + der(3, byteArrayOf(0) + signature))
        return Material(CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate, keys)
    }
    private fun oid(vararg bytes: Int) = der(6, bytes.map(Int::toByte).toByteArray())
    private fun der(tag: Int, value: ByteArray): ByteArray {
        val length = when {
            value.size < 128 -> byteArrayOf(value.size.toByte())
            value.size < 256 -> byteArrayOf(0x81.toByte(), value.size.toByte())
            else -> byteArrayOf(0x82.toByte(), (value.size ushr 8).toByte(), value.size.toByte())
        }
        return byteArrayOf(tag.toByte()) + length + value
    }
    fun serverContext(leaf: Material, authority: Material): SSLContext {
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry("test", leaf.keys.private, CharArray(0), arrayOf(leaf.certificate, authority.certificate))
        }
        val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
        return SSLContext.getInstance("TLS").apply { init(managers.keyManagers, null, null) }
    }
}
