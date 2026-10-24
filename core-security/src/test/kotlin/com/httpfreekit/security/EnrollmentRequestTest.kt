package com.httpfreekit.security

import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.pkcs.CertificationRequest
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentRequestTest {
    private fun keyPair() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    @Test fun requestBindsThePublicKeyAndVerifiesWithoutAnInstalledProvider() {
        val key = keyPair()
        val request = CertificationRequest.getInstance(EnrollmentRequest.create(key.public, key.private))
        assertArrayEquals(key.public.encoded, request.certificationRequestInfo.subjectPublicKeyInfo.encoded)
        assertTrue(valid(request, key.public))
        val stranger = keyPair()
        assertFalse(valid(request, stranger.public))
    }

    @Test fun keyPossessionCannotBeForgedBySigningAnotherPublicKey() {
        val first = keyPair()
        val second = keyPair()
        val request = CertificationRequest.getInstance(EnrollmentRequest.create(first.public, second.private))
        assertFalse(valid(request, first.public))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsNonEcKeys() {
        val key = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        EnrollmentRequest.create(key.public, key.private)
    }

    private fun valid(request: CertificationRequest, publicKey: PublicKey): Boolean {
        assertTrue(request.signatureAlgorithm.algorithm == X9ObjectIdentifiers.ecdsa_with_SHA256)
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(request.certificationRequestInfo.getEncoded(ASN1Encoding.DER))
            verify(request.signature.octets)
        }
    }
}
