package com.httpfreekit.interop

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.TextView
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Actual platform consent for the separately started selected-UID capture research service. */
class DraftEnrolledTunConsentActivity : Activity() {
    @Volatile private var resumed = false
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "Controlled selected-app capture research. Only synthetic fixture traffic is selected."
        })
        val request = VpnService.prepare(this)
        if (request == null) complete(true) else startActivityForResult(request, CONSENT)
    }

    @Deprecated("Platform result callback retained for the API-26 research host")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == CONSENT) complete(resultCode == RESULT_OK && VpnService.prepare(this) == null)
    }

    override fun onDestroy() { try { super.onDestroy() } finally { destroyed.countDown() } }
    override fun onResume() { super.onResume(); resumed = true }
    override fun onPause() { resumed = false; super.onPause() }
    fun researchResumed(): Boolean = resumed
    private fun complete(value: Boolean) { granted = value; completed.countDown() }

    companion object {
        private const val CONSENT = 1
        @Volatile private var granted = false
        @Volatile private var completed = CountDownLatch(1)
        @Volatile private var destroyed = CountDownLatch(1)
        fun reset() { granted = false; completed = CountDownLatch(1); destroyed = CountDownLatch(1) }
        fun awaitConsent(timeoutMillis: Long) = completed.await(timeoutMillis, TimeUnit.MILLISECONDS) && granted
        fun awaitDestroyed(timeoutMillis: Long) = destroyed.await(timeoutMillis, TimeUnit.MILLISECONDS)
    }
}
