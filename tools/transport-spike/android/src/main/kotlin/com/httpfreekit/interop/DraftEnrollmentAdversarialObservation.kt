package com.httpfreekit.interop

import java.util.Collections

/** Positive research facts only. No identity, wire message, certificate or provider detail is accepted. */
class DraftEnrollmentAdversarialObservation(
    scenario: String, originalKeyUnchanged: Boolean, credentialSaved: Boolean,
    ownedStateAbsent: Boolean, clientResourcesClosed: Boolean, facts: Map<String, String>,
) {
    private val fields: Map<String, String> = DraftEnrollmentStateChecks.fixed {
        val expected = when (scenario) {
            "proof_misuse" -> linkedMapOf("PurposeHttp" to "403", "PurposeCode" to "authentication_failed",
                "WireContextHttp" to "403", "WireContextCode" to "authentication_failed", "SignedContextHttp" to "403",
                "SignedContextCode" to "authentication_failed", "SameChallengeHttp" to "200", "SameChallengeType" to "pair_pending",
                "ReplayHttp" to "403", "ReplayCode" to "authentication_failed", "FreshStatusHttp" to "200",
                "FreshStatusType" to "pair_pending", "BindingUnchanged" to "true")
            "wrong_tls" -> linkedMapOf("TlsFailureType" to "SSLException", "FreshStatusHttp" to "200",
                "FreshStatusType" to "pair_pending", "BindingUnchanged" to "true", "ExpectedTrustUnchanged" to "true")
            "pending_cancel" -> linkedMapOf("CancelHttp" to "200", "CancelCode" to "pairing_cancelled", "ReplayHttp" to "403",
                "ReplayCode" to "authentication_failed", "FreshStatusHttp" to "200", "FreshStatusCode" to "pairing_cancelled",
                "BindingUnchanged" to "true")
            "published_cancel" -> linkedMapOf("ApprovalHttp" to "200", "ApprovalType" to "pair_approved",
                "SavedCredentialUnchanged" to "true", "BeforeMtlsHttp" to "200", "CancelHttp" to "200", "CancelCode" to "pairing_cancelled",
                "AfterMtlsHttp" to "403", "FreshStatusHttp" to "200", "FreshStatusCode" to "pairing_cancelled",
                "CredentialExpiresUtcMillis" to "", "RefusalObservedUtcMillis" to "", "KeyManagerUsableAtRefusal" to "true", "BindingUnchanged" to "true")
            else -> throw DraftEnrollmentStateException()
        }
        require(originalKeyUnchanged && ownedStateAbsent && clientResourcesClosed && credentialSaved == (scenario == "published_cancel"))
        require(facts.size == expected.size && facts.keys == expected.keys)
        expected.forEach { (key, value) -> if (value.isNotEmpty()) require(facts[key] == value) }
        if (scenario == "published_cancel") {
            fun epoch(key: String): Long {
                val value = facts.getValue(key)
                require(Regex("[1-9][0-9]{11,12}").matches(value))
                return value.toLong().also { require(it in 946684800000L..4102444800000L) }
            }
            require(epoch("RefusalObservedUtcMillis") < epoch("CredentialExpiresUtcMillis"))
        }
        val result = linkedMapOf("Version" to "1", "Scenario" to scenario, "OriginalKeyUnchanged" to originalKeyUnchanged.toString(),
            "CredentialSaved" to credentialSaved.toString(), "OwnedStateAbsent" to ownedStateAbsent.toString(), "ClientResourcesClosed" to clientResourcesClosed.toString())
        expected.keys.forEach { result[it] = facts.getValue(it) }
        Collections.unmodifiableMap(result.mapKeys { "draftAdversarial${it.key}" })
    }
    fun values(): Map<String, String> = fields
    override fun toString() = "DraftEnrollmentAdversarialObservation([REDACTED])"

    companion object {
        fun peerPort(value: String?, setupPort: Int, credentialPort: Int): Int = DraftEnrollmentStateChecks.fixed {
            require(value != null && Regex("[1-9][0-9]{0,4}").matches(value))
            value.toInt().also { require(it in 1..65535 && it != setupPort && it != credentialPort) }
        }
    }
}
