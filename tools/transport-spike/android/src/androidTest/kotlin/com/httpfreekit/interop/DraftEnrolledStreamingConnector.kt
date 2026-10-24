package com.httpfreekit.interop

import com.httpfreekit.security.LoadedEnrolledCredential

/** The existing fresh scoped transport/upgrade with one saved exact credential and gateway. */
internal class DraftEnrolledStreamingConnector(
    loaded: LoadedEnrolledCredential, private val credential: DraftStreamingFixture.Credential, private val port: Int,
) : DraftStreamingConnector {
    private val record = loaded.record
    init {
        require(port in 1..65535 && credential.manager === loaded.clientKeyManager) { "Invalid saved streaming binding" }
    }
    override fun upgrade(credential: DraftStreamingFixture.Credential, route: String, session: String?,
        scenario: String?, rawSendBufferBytes: Int): Pair<DraftStreamingTls, Int> {
        check(credential === this.credential && route in setOf("/companion/v1/control", "/companion/v1/streams")) { "Streaming binding changed" }
        val tls = draftStreamingConnect(record.gatewayCertificate, record.gatewaySpkiSha256, record.logicalServerName,
            port, credential.manager, rawSendBufferBytes)
        return draftStreamingUpgrade(tls, "${record.logicalServerName}:$port", route, session, scenario)
    }
    override fun toString() = "DraftEnrolledStreamingConnector([REDACTED])"
}
