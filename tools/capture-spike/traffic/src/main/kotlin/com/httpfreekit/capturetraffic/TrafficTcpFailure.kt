package com.httpfreekit.capturetraffic

import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.Collections
import java.util.IdentityHashMap

/** Negative-only categories. Neither a normalized reset nor closed text recovers a specific errno. */
internal object TrafficTcpFailure {
    enum class Errno(val category: String) { RESET("reset"), ABORTED("aborted"), BAD_FD("bad_fd"), NOT_CONNECTED("not_connected") }

    fun category(failure: Exception, errno: (Throwable) -> Errno? = { null }): String {
        if (failure is SocketTimeoutException) return "timeout"
        if (failure !is IOException) return if (failure is IllegalStateException || failure is IllegalArgumentException) "protocol" else "other"
        val seen = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
        val chain = ArrayList<Throwable>(8)
        var current: Throwable? = failure
        while (current != null && chain.size < 8 && seen.add(current)) {
            chain.add(current)
            current = try { current.cause } catch (_: Exception) { null }
        }
        for (cause in chain) {
            val known = try { errno(cause) } catch (_: Exception) { null }
            if (known != null) return known.category
        }
        for (cause in chain) if (cause is SocketException) {
            val message = try { cause.message } catch (_: Exception) { null }
            when (message) {
                "Connection reset", "Connection reset by peer" -> return "reset"
                "Socket closed", "Socket is closed" -> return "closed"
                "Socket is not connected" -> return "not_connected"
            }
        }
        return "io"
    }
}
