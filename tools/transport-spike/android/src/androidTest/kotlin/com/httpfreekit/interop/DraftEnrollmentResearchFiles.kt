package com.httpfreekit.interop

import android.content.Context
import android.os.Process
import android.system.Os
import android.system.OsConstants
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.Instant

/** Fixed app-private research paths only; opening recovery never initializes or repairs it. */
internal class DraftEnrollmentResearchFiles(context: Context) {
    private val directory: File
    private val input: File
    private val recovery: File
    init {
        check(context.packageName == "com.httpfreekit.interop.test") { "Unexpected enrollment research package" }
        val base = context.noBackupFilesDir.canonicalFile
        directory = File(base, "draft-enrollment-research")
        check(directory.canonicalFile == directory.absoluteFile && directory.parentFile == base) { "Invalid research directory" }
        val stat = Os.lstat(directory.path)
        check(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == Process.myUid() && stat.st_mode and 63 == 0) { "Research directory is not private" }
        input = File(directory, "input-v1.bin")
        recovery = File(directory, "recovery-v1.bin")
    }

    fun consumeInput(): DraftEnrollmentSeed {
        check(!recovery.exists()) { "Unexpected prior enrollment recovery state" }
        var bytes: ByteArray? = null
        try {
            bytes = read(input, DraftEnrollmentStateCodec.MAX_INPUT_BYTES)
            val seed = DraftEnrollmentStateCodec.decodeSeed(bytes)
            try {
                val certificate = DraftEnrollmentHttpsClient.certificate(seed.gatewayCertificateDer)
                DraftEnrollmentHttpsClient.validateTrust(certificate, seed.gatewaySpkiSha256, seed.logicalName)
                check(Instant.now().isBefore(Instant.parse(seed.invitationExpiresAt))) { "Research invitation already expired" }
                return seed
            } catch (failure: Exception) { seed.clearInvitationSecret(); throw failure }
        } finally {
            bytes?.fill(0)
            // Delete only this fixed owned entry; never retain setup credentials for restart.
            check(!input.exists() || input.delete()) { "Research input was not removed" }
        }
    }

    fun saveRecovery(value: DraftEnrollmentRecovery) {
        check(!recovery.exists()) { "Recovery publication would replace existing state" }
        val bytes = DraftEnrollmentStateCodec.encodeRecovery(value)
        val temporary = Files.createTempFile(directory.toPath(), "recovery-", ".tmp").toFile()
        try {
            Os.chmod(temporary.path, 384)
            FileOutputStream(temporary).use { it.write(bytes); it.fd.sync() }
            Files.move(temporary.toPath(), recovery.toPath(), StandardCopyOption.ATOMIC_MOVE)
            syncDirectory()
            check(readRecovery().let { DraftEnrollmentStateCodec.encodeRecovery(it).contentEquals(bytes) }) { "Recovery publication mismatch" }
        } finally { if (temporary.exists()) check(temporary.delete()) { "Recovery temporary file remained" } }
    }

    fun readRecovery(): DraftEnrollmentRecovery = DraftEnrollmentStateCodec.decodeRecovery(read(recovery, DraftEnrollmentStateCodec.MAX_RECOVERY_BYTES))
    fun clearRecovery() {
        if (recovery.exists()) {
            regular(recovery, DraftEnrollmentStateCodec.MAX_RECOVERY_BYTES)
            check(recovery.delete()) { "Recovery file was not removed" }
            syncDirectory()
        }
        check(!recovery.exists() && !input.exists()) { "Enrollment research files remained" }
    }

    private fun read(file: File, maximum: Int): ByteArray {
        regular(file, maximum)
        return FileInputStream(file).use { source ->
            val output = ByteArrayOutputStream(); val chunk = ByteArray(4096)
            while (true) {
                val count = source.read(chunk)
                if (count < 0) break
                check(output.size() + count <= maximum) { "Research file exceeded bound" }
                output.write(chunk, 0, count)
            }
            output.toByteArray().also { check(it.isNotEmpty()) { "Research state is empty" } }
        }
    }
    private fun regular(file: File, maximum: Int) {
        check(file.canonicalFile == file.absoluteFile && file.parentFile == directory) { "Research state path changed" }
        val stat = Os.lstat(file.path)
        check(OsConstants.S_ISREG(stat.st_mode) && stat.st_uid == Process.myUid() && stat.st_nlink == 1L &&
            stat.st_mode and 63 == 0 && stat.st_size in 1..maximum.toLong()) { "Research state is not a bounded private file" }
    }
    private fun syncDirectory() {
        val descriptor = Os.open(directory.path, OsConstants.O_RDONLY, 0)
        try {
            check(OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode)) { "Research sync target is not a directory" }
            Os.fsync(descriptor)
        } finally { Os.close(descriptor) }
    }
    override fun toString() = "DraftEnrollmentResearchFiles([REDACTED])"
}
