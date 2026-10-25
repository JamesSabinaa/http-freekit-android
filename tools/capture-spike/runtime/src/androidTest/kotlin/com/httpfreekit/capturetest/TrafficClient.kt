package com.httpfreekit.capturetest

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

internal class TrafficClient(context: Context, directPort: Int) : AutoCloseable {
    private val app = context.applicationContext
    private val thread = HandlerThread("capture-fixture-replies").apply { start() }
    private val connected = CountDownLatch(1)
    private val remote = AtomicReference<Messenger?>()
    private var nextId = 1
    private var bound = false
    @Volatile private var waitingId = 0
    @Volatile private var waitingCommand = 0
    @Volatile private var waiting = CountDownLatch(0)
    @Volatile private var received: Result? = null
    private val replies = Messenger(Handler(thread.looper) { reply ->
        if (reply.what == 100 && reply.arg1 == waitingId) {
            val data = reply.data
            val decoded = CaptureTrafficReply.decode(waitingCommand, reply.arg2, data.keySet(), data.get("bytes"), data.get("sha256"), data.get("failureCode"))
            if (decoded != null) {
                received = Result(decoded.status, decoded.bytes, decoded.sha256, decoded.failureCode)
                waiting.countDown()
            }
        }
        true
    })
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) { remote.set(Messenger(service)); connected.countDown() }
        override fun onServiceDisconnected(name: ComponentName) { remote.set(null) }
        override fun onNullBinding(name: ComponentName) { connected.countDown() }
        override fun onBindingDied(name: ComponentName) { remote.set(null); connected.countDown() }
    }

    init {
        try {
            bound = app.bindService(Intent().setComponent(ComponentName("com.httpfreekit.capturetraffic", "com.httpfreekit.capturetraffic.TrafficService")), connection, Context.BIND_AUTO_CREATE)
            check(bound && connected.await(5000, TimeUnit.MILLISECONDS) && remote.get() != null) { "traffic_bind" }
            check(command(1, Bundle().apply { putInt("directPort", directPort) }).status == 0) { "traffic_configure" }
        } catch (failure: Exception) {
            if (bound) app.unbindService(connection)
            thread.quitSafely(); thread.join(5000)
            throw failure
        }
    }

    @Synchronized fun command(code: Int, data: Bundle = Bundle()): Result {
        check(!thread.isInterrupted && nextId <= 1_000_000) { "traffic_closed" }
        if (code in 10..18) lastData.set(CaptureTrafficOutcome(code, -1, 0))
        val request = Message.obtain(null, code, nextId++, 0)
        waitingCommand = code; waitingId = request.arg1; waiting = CountDownLatch(1); received = null
        request.data = data; request.replyTo = replies
        checkNotNull(remote.get()) { "traffic_disconnected" }.send(request)
        check(waiting.await(12000, TimeUnit.MILLISECONDS)) { "traffic_reply_timeout" }
        return checkNotNull(received) { "traffic_invalid_reply" }.also { if (code in 10..18) lastData.set(CaptureTrafficOutcome(code, it.status, it.bytes)) }
    }

    override fun close() {
        var failure: Exception? = null
        try { check(command(2).status == 0) { "traffic_worker_not_joined" } } catch (caught: Exception) { failure = caught }
        try { if (bound) { app.unbindService(connection); bound = false } } catch (caught: Exception) { failure = failure ?: caught }
        thread.quitSafely(); thread.join(5000)
        check(!thread.isAlive) { "traffic_reply_worker_not_joined" }
        if (failure != null) throw failure
    }

    data class Result(val status: Int, val bytes: Int, val sha256: String?, val failureCode: String?)
    companion object {
        private val lastData = AtomicReference(CaptureTrafficOutcome(0, -1, 0))
        fun resetObservation() { lastData.set(CaptureTrafficOutcome(0, -1, 0)) }
        fun observation(): CaptureTrafficOutcome = lastData.get()
    }
}
