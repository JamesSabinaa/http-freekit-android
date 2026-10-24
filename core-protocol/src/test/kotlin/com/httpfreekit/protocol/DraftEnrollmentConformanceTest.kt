package com.httpfreekit.protocol

import java.io.File
import java.math.BigDecimal
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.Locale
import kotlinx.serialization.json.*
import org.junit.Assert.assertTrue
import org.junit.Test

/** Independent actual execution. Expectations are read only after each actual outcome exists. */
class DraftEnrollmentConformanceTest {
    private val json = Json { isLenient = false }
    private val directory = File("protocol/fixtures/a21-draft-0.4")
    private val hex = Regex("(?:[0-9a-f]{2})*")
    private val digestPattern = Regex("[0-9a-f]{64}")
    private val rejectionCodes = setOf("invalid_message", "message_too_large", "unsupported_version")

    @Test fun executesEveryCommittedEnrollmentCaseAndWritesIndependentActualReport() {
        try { execute() }
        catch (_: Exception) { throw AssertionError("invalid_enrollment_corpus_or_adapter") }
    }

    private fun execute() {
        val digest = MessageDigest.getInstance("SHA-256")
        val files = listOf("codec.json", "comparison.json", "manifest.json", "proof.json").associateWith { name ->
            val bytes = File(directory, name).inputStream().use { it.readNBytes(2 * 1024 * 1024 + 1) }
            require(bytes.size <= 2 * 1024 * 1024) { "invalid_enrollment_corpus_size" }
            digest.update(name.toByteArray(Charsets.UTF_8)); digest.update(0.toByte()); digest.update(bytes); digest.update(0.toByte())
            corpusJson(bytes)
        }
        val manifest = files.getValue("manifest.json")
        envelope(manifest, "manifest", "codecIds", "proofIds", "comparisonIds")
        val codecIds = ids(manifest["codecIds"], 512); val proofIds = ids(manifest["proofIds"], 256)
        val comparisonIds = ids(manifest["comparisonIds"], 128)
        val allIds = codecIds + proofIds + comparisonIds
        require(allIds.distinct().size == allIds.size) { "duplicate_enrollment_corpus_id" }
        val codec = cases(files.getValue("codec.json"), "codec", codecIds)
        val proof = cases(files.getValue("proof.json"), "proof", proofIds)
        val comparison = cases(files.getValue("comparison.json"), "comparison", comparisonIds)
        validateCases(codec, proof, comparison)
        var firstMismatch: String? = null
        fun record(category: String, case: JsonObject, actual: JsonObject, expected: JsonObject): JsonObject {
            if (actual != expected && firstMismatch == null) firstMismatch = "$category/${case.string("id")}"
            return obj("id" to case.getValue("id"), "actual" to actual)
        }
        val actualCodec = codec.map { case ->
            val actual = codecActual(channel(case.string("channel")), unhex(case.string("wireHex"), 65536))
            record("codec", case, actual, case.getValue("expect").objectValue())
        }
        val actualProof = proof.map { case ->
            val actual = proofActual(case.getValue("context"), unhex(case.string("challengeWireHex"), 65536))
            val expected = case.getValue("expect").objectValue()
            // Hash independently authored expected bytes only for the comparison, never actual generation.
            val normalized = if (expected.boolean("ok")) obj("ok" to JsonPrimitive(true),
                "payloadSha256" to JsonPrimitive(sha256(unhex(expected.string("payloadHex"), 1024)))) else expected
            record("proof", case, actual, normalized)
        }
        val actualComparison = comparison.map { case ->
            val actual = comparisonActual(case.getValue("gatewayPin"), case.getValue("deviceHash"))
            record("comparison", case, actual, case.getValue("expect").objectValue())
        }
        val corpusDigest = digest.digest().hex()
        val report = obj("format" to JsonPrimitive("http-freekit-a21"), "revision" to JsonPrimitive("0.4"),
            "kind" to JsonPrimitive("results"), "implementation" to JsonPrimitive("kotlin"),
            "corpusSha256" to JsonPrimitive(corpusDigest), "codec" to JsonArray(actualCodec),
            "proof" to JsonArray(actualProof), "comparison" to JsonArray(actualComparison)).toString().toByteArray(Charsets.UTF_8)
        require(report.size <= 16 * 1024 * 1024) { "invalid_enrollment_report_size" }
        File("build/reports/draft-enrollment/kotlin-conformance.json").apply { parentFile.mkdirs(); writeBytes(report) }
        println("draft_enrollment_conformance codec=${codec.size} proof=${proof.size} comparison=${comparison.size} sha256=$corpusDigest")
        assertTrue("draft_enrollment_conformance_mismatch:${firstMismatch ?: "none"}", firstMismatch == null)
    }

    private fun codecActual(channel: DraftEnrollmentChannel, bytes: ByteArray): JsonObject =
        when (val decoded = DraftEnrollmentCodec.decode(channel, bytes)) {
            is DraftEnrollmentDecodeResult.Rejected -> rejected(decoded.code)
            is DraftEnrollmentDecodeResult.Accepted -> obj("ok" to JsonPrimitive(true), "canonicalSha256" to JsonPrimitive(sha256(DraftEnrollmentCodec.encode(decoded.message))))
        }
    private fun proofActual(context: JsonElement, bytes: ByteArray): JsonObject {
        val decoded = DraftEnrollmentCodec.decode(DraftEnrollmentChannel.CHALLENGE_RESPONSE, bytes)
        if (decoded is DraftEnrollmentDecodeResult.Rejected) return rejected(decoded.code)
        return try {
            val challenge = (decoded as DraftEnrollmentDecodeResult.Accepted).message as? DraftEnrollmentMessage.Challenge ?: error("invalid_context_bridge")
            val fields = context.objectValue()
            exact(fields, "desktopId", "gatewaySpkiSha256", "invitationId", "enrollmentId", "deviceSpkiSha256", "purpose")
            val purpose = DraftEnrollmentPurpose.entries.single { it.wire == fields.string("purpose") }
            val typed = DraftEnrollmentProofContext(fields.string("desktopId"), fields.string("gatewaySpkiSha256"),
                fields.string("invitationId"), fields.string("enrollmentId"), fields.string("deviceSpkiSha256"), purpose)
            obj("ok" to JsonPrimitive(true), "payloadSha256" to JsonPrimitive(sha256(DraftEnrollmentProof.payload(typed, challenge))))
        } catch (_: Exception) { rejected("invalid_message") }
    }
    private fun comparisonActual(pin: JsonElement, device: JsonElement): JsonObject = try {
        obj("ok" to JsonPrimitive(true), "value" to JsonPrimitive(DraftEnrollmentProof.comparisonCode(pin.stringValue(), device.stringValue())))
    } catch (_: Exception) { rejected("invalid_message") }

    private fun validateCases(codec: List<JsonObject>, proof: List<JsonObject>, comparison: List<JsonObject>) {
        codec.forEach {
            exact(it, "id", "channel", "wireHex", "expect"); channel(it.string("channel")); unhex(it.string("wireHex"), 65536)
            outcome(it.getValue("expect"), "canonicalSha256")
        }
        proof.forEach {
            exact(it, "id", "context", "challengeWireHex", "expect"); unhex(it.string("challengeWireHex"), 65536)
            argument(it.getValue("context")); outcome(it.getValue("expect"), "payloadHex")
        }
        comparison.forEach {
            exact(it, "id", "gatewayPin", "deviceHash", "expect")
            argument(it.getValue("gatewayPin")); argument(it.getValue("deviceHash")); outcome(it.getValue("expect"), "value")
        }
        for (channel in DraftEnrollmentChannel.entries) for (accepted in listOf(true, false)) require(codec.any {
            channel(it.string("channel")) == channel && it.getValue("expect").objectValue().boolean("ok") == accepted
        }) { "missing_enrollment_codec_coverage" }
        for (code in rejectionCodes) require(codec.any { it.getValue("expect").objectValue()["code"] == JsonPrimitive(code) }) { "missing_enrollment_rejection_coverage" }
        for (purpose in listOf("status", "cancel")) require(proof.any {
            it.getValue("expect").objectValue().boolean("ok") && (it["context"] as? JsonObject)?.get("purpose") == JsonPrimitive(purpose)
        }) { "missing_enrollment_proof_coverage" }
        require(proof.any { !it.getValue("expect").objectValue().boolean("ok") }) { "missing_enrollment_proof_coverage" }
        for (accepted in listOf(true, false)) require(comparison.any { it.getValue("expect").objectValue().boolean("ok") == accepted }) { "missing_enrollment_comparison_coverage" }
    }
    private fun outcome(value: JsonElement, acceptedField: String) {
        val root = value.objectValue()
        if (!root.boolean("ok")) {
            exact(root, "ok", "code"); require(root.string("code") in if (acceptedField == "value") setOf("invalid_message") else rejectionCodes) { "invalid_enrollment_expected_code" }
        } else {
            exact(root, "ok", acceptedField)
            val text = root.string(acceptedField)
            require(when (acceptedField) {
                "canonicalSha256" -> digestPattern.matches(text)
                "payloadHex" -> unhex(text, 1024).isNotEmpty()
                else -> Regex("[0-9a-f]{8}(-[0-9a-f]{8}){7}").matches(text)
            }) { "invalid_enrollment_expected_value" }
        }
    }
    private fun argument(value: JsonElement) {
        require(value.toString().toByteArray(Charsets.UTF_8).size <= 4096) { "invalid_enrollment_argument_size" }
        fun check(element: JsonElement, depth: Int) {
            when (element) {
                is JsonObject -> { require(depth <= 4 && element.size <= 32) { "invalid_enrollment_argument_shape" }; element.values.forEach { check(it, depth + 1) } }
                is JsonArray -> { require(depth <= 4 && element.size <= 32) { "invalid_enrollment_argument_shape" }; element.forEach { check(it, depth + 1) } }
                else -> Unit
            }
        }
        check(value, 1)
    }
    private fun envelope(root: JsonObject, kind: String, vararg fields: String) {
        exact(root, "format", "revision", "kind", *fields)
        require(root.string("format") == "http-freekit-a21" && root.string("revision") == "0.4" && root.string("kind") == kind) { "invalid_enrollment_envelope" }
    }
    private fun ids(value: JsonElement?, max: Int): List<String> {
        val array = value as? JsonArray ?: error("invalid_enrollment_ids")
        require(array.size in 1..max) { "invalid_enrollment_ids" }
        return array.map { it.stringValue().also { id -> require(Regex("[a-z][a-z0-9-]{0,79}").matches(id)) { "invalid_enrollment_id" } } }
    }
    private fun cases(root: JsonObject, kind: String, ids: List<String>): List<JsonObject> {
        envelope(root, kind, "cases")
        val array = root["cases"] as? JsonArray ?: error("invalid_enrollment_cases")
        require(array.size == ids.size) { "invalid_enrollment_case_count" }
        return array.map { it.objectValue() }.also { require(it.map { item -> item.string("id") } == ids) { "invalid_enrollment_case_order" } }
    }
    private fun channel(value: String): DraftEnrollmentChannel = try {
        require(value == value.lowercase(Locale.ROOT))
        DraftEnrollmentChannel.valueOf(value.uppercase(Locale.ROOT)) }
        catch (_: Exception) { error("invalid_enrollment_channel") }
    private fun unhex(value: String, max: Int): ByteArray {
        require(value.length <= max * 2 && hex.matches(value)) { "invalid_enrollment_hex" }
        return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    private fun ByteArray.hex() = joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value).hex()
    private fun rejected(code: String) = obj("ok" to JsonPrimitive(false), "code" to JsonPrimitive(code))
    private fun obj(vararg fields: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*fields))
    private fun exact(value: JsonObject, vararg fields: String) { require(value.keys == fields.toSet()) { "invalid_enrollment_fields" } }
    private fun JsonElement.objectValue() = this as? JsonObject ?: error("invalid_enrollment_object")
    private fun JsonElement.stringValue() = (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("invalid_enrollment_string")
    private fun JsonObject.string(key: String) = getValue(key).stringValue()
    private fun JsonObject.boolean(key: String) = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull ?: error("invalid_enrollment_boolean")

    /** Fixture-only structural guard. Protocol bytes always pass through the public implementation. */
    private fun corpusJson(bytes: ByteArray): JsonObject {
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        require(!text.startsWith('\uFEFF')) { "invalid_enrollment_corpus_json" }
        val stack = ArrayList<MutableSet<String>>()
        var at = 0
        while (at < text.length) {
            when (text[at]) {
                '{', '[' -> { require(stack.size < 8) { "invalid_enrollment_corpus_depth" }; stack.add(HashSet()); at++ }
                '}', ']' -> { require(stack.isNotEmpty()) { "invalid_enrollment_corpus_json" }; stack.removeAt(stack.lastIndex); at++ }
                '"' -> {
                    val start = at++; var closed = false
                    while (at < text.length) {
                        val char = text[at++]
                        if (char == '\\') { require(at < text.length) { "invalid_enrollment_corpus_json" }; at++ }
                        else if (char == '"') { closed = true; break }
                    }
                    require(closed) { "invalid_enrollment_corpus_json" }
                    val value = json.parseToJsonElement(text.substring(start, at)).stringValue()
                    var index = 0
                    while (index < value.length) {
                        val char = value[index++]
                        if (char.isHighSurrogate()) require(index < value.length && value[index++].isLowSurrogate()) { "invalid_enrollment_corpus_unicode" }
                        else require(!char.isLowSurrogate()) { "invalid_enrollment_corpus_unicode" }
                    }
                    var next = at
                    while (next < text.length && text[next] in " \t\r\n") next++
                    if (next < text.length && text[next] == ':') require(stack.isNotEmpty() && stack.last().add(value)) { "duplicate_enrollment_corpus_member" }
                }
                else -> at++
            }
        }
        require(stack.isEmpty()) { "invalid_enrollment_corpus_json" }
        val root = json.parseToJsonElement(text).objectValue()
        fun numbers(value: JsonElement) {
            when (value) {
                is JsonObject -> value.values.forEach(::numbers)
                is JsonArray -> value.forEach(::numbers)
                is JsonPrimitive -> if (!value.isString && value != JsonNull && value.booleanOrNull == null) {
                    val number = try { BigDecimal(value.content).longValueExact() } catch (_: Exception) { error("invalid_enrollment_corpus_number") }
                    require(number in -9007199254740991L..9007199254740991L) { "invalid_enrollment_corpus_number" }
                }
            }
        }
        numbers(root)
        return root
    }
}
