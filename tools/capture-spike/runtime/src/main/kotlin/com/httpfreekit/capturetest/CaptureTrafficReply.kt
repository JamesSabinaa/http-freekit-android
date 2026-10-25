package com.httpfreekit.capturetest

/** Finite replies from the signature-protected synthetic traffic APK only. */
internal data class CaptureTrafficReply(val status: Int, val bytes: Int, val sha256: String?, val failureCode: String?) {
    companion object {
        val failureCodes: Set<String> = buildSet {
            for (stage in listOf("connect", "write", "shutdown", "reply", "eof", "close"))
                for (category in listOf("timeout", "io", "protocol", "other", "reset", "aborted", "closed", "bad_fd", "not_connected")) add("traffic_tcp_${stage}_$category")
            for (expected in listOf("vpn", "nonvpn")) for (present in 0..1) for (internet in 0..1) for (vpn in 0..1)
                add("traffic_route_${expected}_timeout_p${present}_i${internet}_v$vpn")
            for (category in listOf("timeout", "io", "protocol", "other")) add("traffic_datagram_$category")
            add("traffic_route_unavailable"); add("traffic_command_failed"); add("traffic_close_io")
        }

        fun decode(command: Int, status: Int, keys: Set<String>, bytes: Any?, hash: Any?, code: Any?): CaptureTrafficReply? {
            if (command !in setOf(1, 2, 10, 11, 12, 13, 14, 15, 16, 17, 18) || status !in 0..3 ||
                keys != setOf("bytes", "sha256", "failureCode") || bytes !is Int || bytes !in 0..65507 ||
                hash != null && (hash !is String || !hash.matches(Regex("[0-9a-f]{64}"))) ||
                code != null && (code !is String || code !in failureCodes) || status == 0 && code != null) return null
            if (command in 17..18) {
                val prefix = if (command == 17) "traffic_route_vpn_timeout_" else "traffic_route_nonvpn_timeout_"
                if (bytes != 0 || hash != null || when (status) {
                    2 -> code !is String || !code.startsWith(prefix)
                    3 -> code != "traffic_route_unavailable"
                    else -> code != null
                }) return null
            } else if (code is String && code.startsWith("traffic_route_") || command in 10..16 && status in 2..3 && code == null) return null
            return CaptureTrafficReply(status, bytes, hash, code)
        }
    }
}
