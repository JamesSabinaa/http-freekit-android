package com.httpfreekit.capturetraffic

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.AlgorithmParameters
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.util.Date
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

/** One private trust store, never the process default or the Android user/system store. */
internal class ReferenceTunTrust private constructor(val context: SSLContext, private val authority: X509Certificate) {
    // PKIX providers need not recheck a trust anchor's validity. Retain and check it ourselves
    // at the actual TLS admission point, not just when scoped configuration was created.
    fun requireCurrent(now: Date) { authority.checkValidity(now) }

    companion object {
        fun create(bytes: ByteArray, now: Date = Date()): ReferenceTunTrust {
            check(bytes.size in 1..4096)
            val copy = bytes.copyOf()
            canonicalDer(copy)
            val input = ByteArrayInputStream(copy)
            val ca = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
            check(input.available() == 0 && ca.encoded.contentEquals(copy))
            ca.checkValidity(now)
            check(ca.notBefore.before(ca.notAfter) && ca.basicConstraints >= 0)
            check(ca.subjectX500Principal == ca.issuerX500Principal)
            check(ca.keyUsage?.getOrElse(5) { false } != false)
            check(ca.extendedKeyUsage?.let { it == listOf("1.3.6.1.5.5.7.3.1") } != false)
            check(ca.criticalExtensionOIDs.orEmpty().all { it in setOf("2.5.29.19", "2.5.29.15", "2.5.29.37") })
            when (val key = ca.publicKey) {
                is ECPublicKey -> {
                    val expected = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                        .getParameterSpec(ECParameterSpec::class.java)
                    check(key.params.curve == expected.curve && key.params.generator == expected.generator &&
                        key.params.order == expected.order && key.params.cofactor == expected.cofactor)
                }
                is RSAPublicKey -> check(key.modulus.bitLength() in 2048..4096)
                else -> error("invalid_ca")
            }
            check(ca.sigAlgOID in setOf("1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4",
                "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13"))
            ca.verify(ca.publicKey)
            val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("reference", ca)
            }
            val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            return ReferenceTunTrust(SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }, ca)
        }

        /** Public API26 SNI and HTTPS endpoint identification; only API29+ has public ALPN. */
        fun prepare(socket: SSLSocket, sdk: Int) {
            socket.useClientMode = true
            socket.enabledProtocols = socket.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }.toTypedArray()
            check(socket.enabledProtocols.isNotEmpty())
            val parameters = socket.sslParameters
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            parameters.serverNames = listOf(SNIHostName(ReferenceTunHttpResponse.HOST))
            if (sdk >= 29) offerH1(parameters)
            socket.sslParameters = parameters
        }

        fun requireH1(socket: SSLSocket, sdk: Int) {
            // Absent ALPN is permitted by this H1-only profile, never called negotiated H1.
            if (sdk >= 29) checkH1(socket)
        }

        @android.annotation.TargetApi(29)
        private fun offerH1(parameters: javax.net.ssl.SSLParameters) { parameters.applicationProtocols = arrayOf("http/1.1") }

        @android.annotation.TargetApi(29)
        private fun checkH1(socket: SSLSocket) {
            check(socket.applicationProtocol.isNullOrEmpty() || socket.applicationProtocol == "http/1.1")
        }

        /** Bounded DER guard, before provider parsing (providers can accept BER or preserve its encoding). */
        internal fun canonicalDer(bytes: ByteArray) {
            check(bytes.size in 1..4096 && bytes[0] == 0x30.toByte())
            var nodes = 0
            fun octet(index: Int) = bytes[index].toInt() and 255
            fun compare(a: Int, ae: Int, b: Int, be: Int): Int {
                for (i in 0 until minOf(ae - a, be - b)) {
                    val delta = octet(a + i) - octet(b + i)
                    if (delta != 0) return delta
                }
                return (ae - a) - (be - b)
            }
            fun item(start: Int, limit: Int, depth: Int): Int {
                check(++nodes <= 512 && depth <= 16 && start + 2 <= limit)
                var at = start
                val tag = octet(at++)
                check(tag != 0 && tag and 31 != 31)
                var length = octet(at++)
                if (length and 128 != 0) {
                    val count = length and 127
                    check(count in 1..2 && at + count <= limit && octet(at) != 0)
                    length = 0
                    repeat(count) { length = length * 256 + octet(at++) }
                    check(length >= 128 && (count == 1 || length >= 256))
                }
                val end = at + length
                check(end <= limit)
                if (tag and 32 != 0) {
                    if (tag and 192 == 0) check(tag == 0x30 || tag == 0x31)
                    var previous = -1; var previousEnd = -1
                    while (at < end) {
                        val next = item(at, end, depth + 1)
                        if (tag == 0x31 && previous >= 0) check(compare(previous, previousEnd, at, next) <= 0)
                        previous = at; previousEnd = next; at = next
                    }
                } else {
                    check(tag != 0x10 && tag != 0x11)
                    when (tag) {
                        1 -> check(length == 1 && octet(at) in setOf(0, 255))
                        2 -> {
                            check(length > 0)
                            if (length > 1) check(!(octet(at) == 0 && octet(at + 1) and 128 == 0) &&
                                !(octet(at) == 255 && octet(at + 1) and 128 != 0))
                        }
                        3 -> {
                            check(length > 0)
                            val unused = octet(at)
                            check(unused <= 7 && (length != 1 || unused == 0) && octet(end - 1) and ((1 shl unused) - 1) == 0)
                        }
                        5 -> check(length == 0)
                        6 -> {
                            check(length > 0 && octet(end - 1) and 128 == 0)
                            for (i in at until end) check(octet(i) != 128 || i != at && octet(i - 1) and 128 != 0)
                        }
                        12 -> Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes, at, length))
                        19 -> check(Regex("[A-Za-z0-9 '()+,\\-./:=?]*").matches(String(bytes, at, length, Charsets.ISO_8859_1)))
                        22 -> check((at until end).all { octet(it) <= 127 })
                        23 -> check(Regex("[0-9]{12}Z").matches(String(bytes, at, length, Charsets.US_ASCII)))
                        24 -> check(Regex("[0-9]{14}Z").matches(String(bytes, at, length, Charsets.US_ASCII)))
                    }
                }
                return end
            }
            check(item(0, bytes.size, 0) == bytes.size)
        }
    }
}
