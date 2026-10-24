package com.httpfreekit.security

import java.security.AlgorithmParameters
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.pkcs.CertificationRequest
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers

/** PKCS#10 proof of key possession. Does not perform enrollment or export the private key. */
object EnrollmentRequest {
    fun create(publicKey: PublicKey, privateKey: PrivateKey): ByteArray {
        val expected = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
        require(publicKey is ECPublicKey && publicKey.params.curve == expected.curve &&
            publicKey.params.generator == expected.generator && publicKey.params.order == expected.order &&
            publicKey.params.cofactor == expected.cofactor) {
            "Enrollment requires a P-256 device key"
        }
        require(privateKey.algorithm == "EC") { "Enrollment requires an EC device key" }
        val information = CertificationRequestInfo(
            X500Name("CN=HTTP FreeKit device"),
            SubjectPublicKeyInfo.getInstance(publicKey.encoded),
            DERSet(),
        )
        val signature = Signature.getInstance("SHA256withECDSA").run {
            // JCA selects the Android Keystore provider for its nonexportable key.
            initSign(privateKey)
            update(information.getEncoded(ASN1Encoding.DER))
            sign()
        }
        return CertificationRequest(
            information,
            AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256),
            DERBitString(signature),
        ).getEncoded(ASN1Encoding.DER)
    }
}
