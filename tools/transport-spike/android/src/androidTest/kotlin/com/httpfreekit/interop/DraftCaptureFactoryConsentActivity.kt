package com.httpfreekit.interop

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.TextView
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Actual platform preparation only: this Activity never establishes a VPN or starts capture. */
class DraftCaptureFactoryConsentActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply { text = "Controlled authenticated transport research; no packet capture." })
        val request = VpnService.prepare(this)
        requested = request != null
        if (request == null) complete(true) else startActivityForResult(request, CONSENT)
    }

    @Deprecated("Platform result callback retained for the API-26 research host")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == CONSENT) complete(resultCode == RESULT_OK && VpnService.prepare(this) == null)
    }

    override fun onDestroy() {
        try { super.onDestroy() } finally { destroyed.countDown() }
    }

    private fun complete(approved: Boolean) { granted = approved; completed.countDown() }

    companion object {
        private const val CONSENT = 1
        @Volatile private var granted = false
        @Volatile private var requested = false
        @Volatile private var completed = CountDownLatch(1)
        @Volatile private var destroyed = CountDownLatch(1)
        fun reset() { granted = false; requested = false; completed = CountDownLatch(1); destroyed = CountDownLatch(1) }
        fun consentRequested(): Boolean = requested
        fun awaitConsent(timeoutMillis: Long): Boolean = completed.await(timeoutMillis, TimeUnit.MILLISECONDS) && granted
        fun awaitDestroyed(timeoutMillis: Long): Boolean = destroyed.await(timeoutMillis, TimeUnit.MILLISECONDS)
    }
}
