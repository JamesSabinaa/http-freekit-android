package com.httpfreekit.interop

import java.io.ByteArrayInputStream
import java.io.DataInputStream

/** Research-local wrapper only. The nested invitation remains explicit, copied and clearable. */
class DraftEnrollmentStreamSeed internal constructor(val streamPort: Int, val scenario: Int, val enrollment: DraftEnrollmentSeed) {
    override fun toString() = "DraftEnrollmentStreamSeed([REDACTED])"
}

object DraftEnrollmentStreamInputCodec {
    fun decode(bytes: ByteArray): DraftEnrollmentStreamSeed = DraftEnrollmentStateChecks.fixed {
        require(bytes.size in 14..DraftEnrollmentStateCodec.MAX_INPUT_BYTES)
        val input = DataInputStream(ByteArrayInputStream(bytes))
        require(ByteArray(8).also(input::readFully).contentEquals(byteArrayOf(72, 70, 75, 83, 84, 82, 49, 0)))
        val port = input.readUnsignedShort().also { require(it in 1..65535) }
        val scenario = input.readUnsignedByte().also { require(it in 1..3) }
        val length = input.readUnsignedShort().also { require(it > 0 && it == input.available()) }
        val embedded = ByteArray(length).also(input::readFully)
        val seed = try { DraftEnrollmentStateCodec.decodeSeed(embedded) } finally { embedded.fill(0) }
        try {
            require(input.read() == -1 && port != seed.setupPort && port != seed.credentialPort)
            DraftEnrollmentStreamSeed(port, scenario, seed)
        } catch (failure: Exception) { seed.clearInvitationSecret(); throw failure }
    }
}
