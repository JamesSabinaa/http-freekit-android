package com.httpfreekit.interop

import org.json.JSONObject

/** Exact bounded synthetic metadata. Never stringify a response or retain arbitrary peer text. */
internal class DraftStreamingProbe private constructor(private val data: JSONObject) {
    fun boolean(section: String, key: String) = data.getJSONObject(section).getBoolean(key)
    fun number(section: String, key: String) = data.getJSONObject(section).getLong(key)
    fun optionalNumber(section: String, key: String): Long? = data.getJSONObject(section).let {
        if (it.isNull(key)) null else it.getLong(key)
    }
    fun digest(key: String): String? = data.getJSONObject("fixture").let { if (it.isNull(key)) null else it.getString(key) }
    fun phase(section: String): String? = if (data.isNull(section)) null else data.getJSONObject(section).getString("phase")
    fun cause(section: String): String? = if (data.isNull(section)) null else data.getJSONObject(section).let {
        if (it.isNull("cause")) null else it.getString("cause")
    }
    fun ordinal() = data.getInt("streamOrdinal")
    override fun toString() = "ResearchProbe([BOUNDED SYNTHETIC COUNTERS])"

    companion object {
        fun read(fixture: DraftStreamingFixture, credential: DraftStreamingFixture.Credential, token: String): DraftStreamingProbe {
            val reply = fixture.request(credential, method = "GET", path = "/research/probe",
                headers = mapOf("X-FreeKit-Session" to token))
            check(reply.status == 200 && reply.body.size in 1..4096 && reply.headers["content-type"]?.substringBefore(';') == "application/json") {
                "Invalid synthetic probe response"
            }
            val value = JSONObject(reply.body.toString(Charsets.UTF_8))
            exact(value, "revision scenario streamOrdinal control stream pool fixture io cleanup timing")
            check(value.get("revision") == 1 && value.getString("scenario") in
                setOf("gated", "backpressure", "cancel", "expiry", "binding", "malformed", "premature"))
            integer(value, "streamOrdinal", 64)
            val control = value.getJSONObject("control")
            exact(control, "phase cause sessionLease webSocketClosed resourcesReleased historyCount streamLeases chargedBytes")
            check(control.getString("phase") in setOf("awaiting_hello", "awaiting_ready", "active", "closed", "failed"))
            cause(control)
            booleans(control, "sessionLease webSocketClosed resourcesReleased")
            integers(control, "historyCount streamLeases chargedBytes", 65536)
            if (!value.isNull("stream")) {
                val stream = value.getJSONObject("stream")
                exact(stream, "phase cause streamLease webSocketClosed resourcesReleased chargedFrames client gateway")
                check(stream.getString("phase") in setOf("awaiting_open", "awaiting_ready", "open", "half_closed", "draining", "closing", "complete", "cancelled", "failed"))
                cause(stream)
                booleans(stream, "streamLease webSocketClosed resourcesReleased")
                integer(stream, "chargedFrames", 4)
                for (direction in listOf("client", "gateway")) {
                    val queue = stream.getJSONObject(direction)
                    exact(queue, "sealed eofEmitted chargedBytes")
                    booleans(queue, "sealed eofEmitted"); integer(queue, "chargedBytes", 8192)
                }
            }
            val pool = value.getJSONObject("pool")
            exact(pool, "sessionLeases streamLeases chargedBytes")
            integer(pool, "sessionLeases", 4); integer(pool, "streamLeases", 8); integer(pool, "chargedBytes", 65536)
            val flow = value.getJSONObject("fixture")
            exact(flow, "proxyReadPaused uploadBytesRead uploadPrefixSeen uploadEof uploadVerified uploadSha256 responseBytesWritten responsePrefixWritten responseTailReleased responseEof responseSha256")
            booleans(flow, "proxyReadPaused uploadPrefixSeen uploadEof uploadVerified responsePrefixWritten responseTailReleased responseEof")
            integers(flow, "uploadBytesRead responseBytesWritten", 33570816)
            for (key in listOf("uploadSha256", "responseSha256")) {
                check(flow.isNull(key) || flow.getString(key).matches(Regex("[a-f0-9]{64}"))) { "Invalid synthetic digest" }
            }
            val io = value.getJSONObject("io")
            exact(io, "proxyWriteEntries proxyWriteCompletions proxyWritePending wsWriteEntries wsWriteCompletions wsWritePending pendingIngressBytes backpressureCount resumedPendingCount retainedBytesAtAbort retainedFramesAtAbort retainedStreamLeasesAtAbort")
            booleans(io, "proxyWritePending wsWritePending")
            integers(io, "proxyWriteEntries proxyWriteCompletions wsWriteEntries wsWriteCompletions backpressureCount resumedPendingCount", 33570816)
            integer(io, "pendingIngressBytes", 4096)
            integer(io, "retainedBytesAtAbort", 16384); integer(io, "retainedFramesAtAbort", 8)
            integer(io, "retainedStreamLeasesAtAbort", 2)
            val cleanup = value.getJSONObject("cleanup")
            exact(cleanup, "controlClosed streamClosed proxyClosed fixtureClosed workers timers pendingCallbacks complete")
            booleans(cleanup, "controlClosed streamClosed proxyClosed fixtureClosed complete")
            integers(cleanup, "workers timers pendingCallbacks", 64)
            val timing = value.getJSONObject("timing")
            exact(timing, "readyUtcMillis expiresUtcMillis terminalUtcMillis terminalElapsedMillis")
            integers(timing, "readyUtcMillis expiresUtcMillis", 9007199254740991L)
            for (key in listOf("terminalUtcMillis", "terminalElapsedMillis")) {
                if (!timing.isNull(key)) integer(timing, key, 9007199254740991L)
            }
            check(timing.isNull("terminalUtcMillis") == timing.isNull("terminalElapsedMillis")) { "Incomplete terminal timing" }
            return DraftStreamingProbe(value)
        }

        fun command(fixture: DraftStreamingFixture, credential: DraftStreamingFixture.Credential, token: String, command: String) {
            check(command in setOf("release_response_tail", "resume_proxy_read"))
            val body = "{\"command\":\"$command\"}".toByteArray(Charsets.UTF_8)
            check(body.size <= 128)
            val reply = fixture.request(credential, method = "POST", path = "/research/command", body = body,
                headers = mapOf("X-FreeKit-Session" to token, "Content-Type" to "application/json"))
            check(reply.status == 200 && reply.body.size <= 4096) { "Research gate command failed" }
        }

        private fun exact(value: JSONObject, names: String) {
            check(value.keys().asSequence().toSet() == names.split(' ').toSet()) { "Synthetic probe schema mismatch" }
        }
        private fun cause(value: JSONObject) {
            check(value.isNull("cause") || value.getString("cause") in setOf("cancelled", "unsupported_version", "unsupported_capability",
                "authentication_failed", "device_revoked", "proxy_unavailable", "session_limit", "stream_limit", "invalid_message",
                "network_unreachable", "session_expired", "desktop_stopped", "message_too_large")) { "Invalid synthetic cause" }
        }
        private fun booleans(value: JSONObject, names: String) = names.split(' ').forEach {
            check(value.get(it) is Boolean) { "Synthetic probe boolean mismatch" }
        }
        private fun integers(value: JSONObject, names: String, max: Long) = names.split(' ').forEach { integer(value, it, max) }
        private fun integer(value: JSONObject, name: String, max: Long) {
            val raw = value.get(name)
            check((raw is Int || raw is Long) && value.getLong(name) in 0..max) { "Synthetic probe integer mismatch" }
        }
    }
}
