package com.httpfreekit.capturetest

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.TextView
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Launches the actual platform consent dialog; there is no VPN app-op or root shortcut. */
class ConsentActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply { setText(R.string.research_notice) })
        val request = VpnService.prepare(this)
        if (request == null) complete(true) else startActivityForResult(request, CONSENT)
    }

    @Deprecated("Platform result callback retained for the API-26 research host")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == CONSENT) complete(resultCode == RESULT_OK && VpnService.prepare(this) == null)
    }

    private fun complete(approved: Boolean) { granted = approved; completed.countDown() }

    companion object {
        private const val CONSENT = 1
        @Volatile private var granted = false
        @Volatile private var completed = CountDownLatch(1)
        fun reset() { granted = false; completed = CountDownLatch(1) }
        fun awaitConsent(timeoutMillis: Long): Boolean = completed.await(timeoutMillis, TimeUnit.MILLISECONDS) && granted
    }
}
