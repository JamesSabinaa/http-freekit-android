package com.httpfreekit.protocol

import java.io.File
import java.security.MessageDigest
import java.util.Locale
import kotlinx.serialization.json.*
import org.junit.Assert.assertTrue
import org.junit.Test

/** Executes committed synthetic cases; expected outcomes never create model state or actual output. */
class DraftConformanceTest {
    private val json = Json { isLenient = false }
    private val directory = File("protocol/fixtures/a19-draft-0.3")
    private val idPattern = Regex("[a-z][a-z0-9-]{0,79}")
    private val refPattern = Regex("[a-z][a-z0-9-]{0,39}")
    private val hexPattern = Regex("(?:[0-9a-f]{2})*")

    @Test fun executesEveryCommittedCaseAndWritesIndependentActualReport() {
        val digest = MessageDigest.getInstance("SHA-256")
        val files = listOf("codec.json", "lifecycle.json", "manifest.json").associateWith { name ->
            val bytes = File(directory, name).inputStream().use { it.readNBytes(2 * 1024 * 1024 + 1) }
            require(bytes.size <= 2 * 1024 * 1024) { "invalid_corpus_size" }
            digest.update(name.toByteArray()); digest.update(0.toByte()); digest.update(bytes); digest.update(0.toByte())
            corpusJson(bytes)
        }
        val manifest = files.getValue("manifest.json")
        envelope(manifest, "manifest", "codecIds", "lifecycleIds")
        val codecIds = ids(manifest.getValue("codecIds")); val lifecycleIds = ids(manifest.getValue("lifecycleIds"))
        require((codecIds + lifecycleIds).distinct().size == codecIds.size + lifecycleIds.size) { "duplicate_corpus_id" }
        val codec = files.getValue("codec.json"); envelope(codec, "codec", "cases")
        val lifecycle = files.getValue("lifecycle.json"); envelope(lifecycle, "lifecycle", "cases")
        val codecCases = cases(codec, codecIds); val lifecycleCases = cases(lifecycle, lifecycleIds)
        var matches = true
        val codecActual = codecCases.map { case ->
            exact(case, "id", "channel", "input", "expect")
            val channel = when (case.string("channel")) { "control" -> DraftChannel.CONTROL; "stream" -> DraftChannel.STREAM; else -> error("invalid_corpus_channel") }
            val actual = when (val result = DraftWireCodec.decode(channel, bytes(case.getValue("input")))) {
                is DraftDecodeResult.Rejected -> obj("code" to str(result.code))
                is DraftDecodeResult.Accepted -> obj("code" to str("ok"), "message" to json.parseToJsonElement(String(DraftWireCodec.encode(result.message))))
            }
            matches = matches && actual == case["expect"]
            obj("id" to case.getValue("id"), "actual" to actual)
        }
        val lifecycleActual = lifecycleCases.map { case ->
            exact(case, "id", "pool", "initialClock", "controls", "steps")
            val poolValue = case.getValue("pool").objectValue()
            exact(poolValue, "maxSessions", "maxStreams", "maxBytes")
            val pool = DraftBudgetPool(poolValue.number("maxSessions", 1, 16).toInt(), poolValue.number("maxStreams", 1, 256).toInt(), poolValue.number("maxBytes", 1, 16777216))
            val initialClock = clock(case.getValue("initialClock"))
            val definitions = case.getValue("controls").objectValue()
            definitions.forEach { (ref, value) ->
                require(refPattern.matches(ref)) { "invalid_corpus_reference" }
                exact(value.objectValue(), "deviceId", "desktopId", "supportedCapabilities")
            }
            val controls = linkedMapOf<String, DraftSession>()
            val streams = linkedMapOf<String, Pair<String, DraftStream>>()
            val operations = case.getValue("steps") as? JsonArray ?: error("invalid_corpus_steps")
            require(operations.size in 1..2048) { "invalid_corpus_steps" }
            val actualSteps = operations.map { element ->
                val step = element.objectValue()
                val op = step.string("op")
                val now = step["clock"]?.let(::clock) ?: initialClock
                fun control(): DraftSession = controls[step.string("control")] ?: error("absent_corpus_reference")
                fun stream(): DraftStream = streams[step.string("stream")]?.second ?: error("absent_corpus_reference")
                fun direction(): DraftDirection? {
                    val value = step.string("direction")
                    require(value.length <= 128 && value.all { it.code in 0..127 }) { "invalid_corpus_direction" }
                    return when (value) { "client" -> DraftDirection.CLIENT; "gateway" -> DraftDirection.GATEWAY; else -> null }
                }
                fun fields(vararg fields: String) = exact(step, "op", "expect", *fields, *if ("clock" in step) arrayOf("clock") else emptyArray())
                fun targetFields(vararg other: String) {
                    require(("control" in step) != ("stream" in step)) { "invalid_corpus_target" }
                    fields(if ("control" in step) "control" else "stream", *other)
                }
                var result = DraftResult()
                var peek: ByteArray? = null
                when (op) {
                    "create_control" -> {
                        fields("control")
                        val ref = step.string("control")
                        require(ref !in controls) { "reused_corpus_reference" }
                        val definition = definitions[ref]?.objectValue() ?: error("absent_corpus_definition")
                        val supported = definition.getValue("supportedCapabilities") as? JsonArray ?: error("invalid_corpus_capabilities")
                        controls[ref] = DraftSession(definition.string("deviceId"), definition.string("desktopId"), supported.map { it.stringValue() }, pool, now)
                    }
                    "control_text" -> { fields("control", "direction", "input"); result = control().text(direction(), bytes(step.getValue("input")), now) }
                    "control_activity" -> { fields("control", "direction"); result = control().pingPong(direction(), now) }
                    "allocate_stream" -> {
                        fields("control", "stream", "deviceId", "sessionHeader")
                        val ref = step.string("stream")
                        require(refPattern.matches(ref) && ref !in streams) { "invalid_corpus_reference" }
                        val allocated = control().allocateStream(step.string("deviceId"), step.string("sessionHeader"), now)
                        result = allocated.result
                        allocated.stream?.let { streams[ref] = step.string("control") to it }
                    }
                    "stream_text" -> { fields("stream", "direction", "input"); result = stream().text(direction(), bytes(step.getValue("input")), now) }
                    "binary" -> { fields("stream", "direction", "input"); result = stream().binary(direction(), bytes(step.getValue("input")), now) }
                    "peek" -> {
                        fields("stream", "direction", "count")
                        val value = stream().peek(direction(), step.number("count", -1, 16777217).toInt(), now)
                        result = value.result
                        if (result.code == "ok") peek = value.bytes()
                    }
                    "drain" -> { fields("stream", "direction", "count"); result = stream().drain(direction(), step.number("count", -1, 16777217), now) }
                    "local_cancel" -> { targetFields(); result = if ("control" in step) control().cancelLocally(now) else stream().cancelLocally(now) }
                    "tick" -> { targetFields(); if ("control" in step) control().tick(now) else stream().tick(now) }
                    "ws_closed" -> {
                        targetFields("closeCode")
                        val code = step.number("closeCode", 0, 65535).toInt()
                        if ("control" in step) control().webSocketClosed(code, now) else stream().webSocketClosed(code, now)
                    }
                    "resources_closed" -> { targetFields(); if ("control" in step) control().confirmClosed(now) else stream().confirmClosed(now) }
                    "snapshot" -> { exact(step, "op", "expect") }
                    else -> error("invalid_corpus_operation")
                }
                val effects = result.eofDirections.sortedBy { it.name }.map { direction ->
                    obj("type" to str("write_eof"), "stream" to step.getValue("stream"), "direction" to str(direction.name.lowercase(Locale.ROOT)))
                }
                val fields = sortedMapOf<String, JsonElement>("code" to str(result.code), "effects" to JsonArray(effects), "snapshot" to snapshot(pool, controls, streams))
                if (peek != null) fields["peekHex"] = str(hex(peek))
                val actual = JsonObject(fields)
                matches = matches && actual == step["expect"]
                actual
            }
            obj("id" to case.getValue("id"), "steps" to JsonArray(actualSteps))
        }
        val hash = hex(digest.digest())
        val report = obj("format" to str("http-freekit-a19"), "revision" to str("0.3"), "kind" to str("results"),
            "implementation" to str("kotlin"), "corpusSha256" to str(hash), "codec" to JsonArray(codecActual), "lifecycle" to JsonArray(lifecycleActual))
        val reportBytes = report.toString().toByteArray()
        require(reportBytes.size <= 16 * 1024 * 1024) { "invalid_actual_report_size" }
        File("build/reports/draft-protocol/kotlin-conformance.json").also { it.parentFile.mkdirs(); it.writeBytes(reportBytes) }
        println("A19 kotlin corpusSha256=$hash codecIds=${codecIds.joinToString(",")} lifecycleIds=${lifecycleIds.joinToString(",")} codecCount=${codecIds.size} lifecycleCount=${lifecycleIds.size}")
        assertTrue("a19_conformance_mismatch", matches)
    }

    private fun snapshot(pool: DraftBudgetPool, controls: Map<String, DraftSession>, streams: Map<String, Pair<String, DraftStream>>): JsonObject {
        val budget = pool.snapshot()
        return obj("pool" to obj("sessionLeases" to num(budget.sessionLeases), "streamLeases" to num(budget.streamLeases), "chargedBytes" to num(budget.chargedBytes)),
            "controls" to JsonObject(controls.toSortedMap().mapValues { (_, control) ->
                val s = control.snapshot()
                obj("phase" to str(s.phase.name.lowercase(Locale.ROOT)), "cause" to nullable(s.cause), "sessionLease" to bool(s.sessionLease),
                    "webSocketClosed" to bool(s.webSocketClosed), "resourcesReleased" to bool(s.controlClosureConfirmed), "historyCount" to num(s.openedIds),
                    "streamLeases" to num(s.streamLeases), "chargedBytes" to num(s.chargedBytes))
            }), "streams" to JsonObject(streams.toSortedMap().mapValues { (_, pair) ->
                val s = pair.second.snapshot()
                obj("control" to str(pair.first), "phase" to str(s.phase.name.lowercase(Locale.ROOT)), "cause" to nullable(s.cause),
                    "streamLease" to bool(s.streamLease), "webSocketClosed" to bool(s.webSocketClosed), "resourcesReleased" to bool(s.resourceClosureConfirmed),
                    "chargedFrames" to num(s.chargedFrames),
                    "client" to obj("sealed" to bool(s.clientSealed), "eofEmitted" to bool(s.clientEof), "chargedBytes" to num(s.clientBytes)),
                    "gateway" to obj("sealed" to bool(s.gatewaySealed), "eofEmitted" to bool(s.gatewayEof), "chargedBytes" to num(s.gatewayBytes)))
            }))
    }
    private fun envelope(value: JsonObject, kind: String, vararg extra: String) {
        exact(value, "format", "revision", "kind", *extra)
        require(value.string("format") == "http-freekit-a19" && value.string("revision") == "0.3" && value.string("kind") == kind) { "invalid_corpus_envelope" }
    }
    private fun ids(value: JsonElement): List<String> {
        val ids = (value as? JsonArray ?: error("invalid_corpus_ids")).map { it.stringValue() }
        require(ids.size in 1..256 && ids.all(idPattern::matches) && ids.distinct().size == ids.size && ids.sorted() == ids) { "invalid_corpus_ids" }
        return ids
    }
    private fun cases(envelope: JsonObject, expected: List<String>): List<JsonObject> {
        val cases = (envelope["cases"] as? JsonArray ?: error("invalid_corpus_cases")).map { it.objectValue() }
        require(cases.map { it.string("id") } == expected) { "incomplete_corpus_ids" }
        return cases
    }
    private fun clock(value: JsonElement): DraftClock {
        val root = value.objectValue(); exact(root, "utcMillis", "monotonicMillis")
        return DraftClock(root.number("utcMillis", 0, 9007199254740991), root.number("monotonicMillis", 0, 9007199254740991))
    }
    private fun bytes(value: JsonElement): ByteArray {
        val root = value.objectValue()
        if ("wireHex" in root) { exact(root, "wireHex"); return unhex(root.string("wireHex")) }
        exact(root, "prefixHex", "repeatHex", "repeatCount", "suffixHex")
        val prefix = root.string("prefixHex"); val repeat = root.string("repeatHex"); val suffix = root.string("suffixHex")
        val count = root.number("repeatCount", 0, 65537).toInt()
        require(hexPattern.matches(prefix) && hexPattern.matches(suffix) && Regex("[0-9a-f]{2}").matches(repeat) && prefix.length.toLong() / 2 + count + suffix.length / 2 <= 65537) { "invalid_corpus_bytes" }
        return unhex(prefix) + ByteArray(count) { repeat.toInt(16).toByte() } + unhex(suffix)
    }
    private fun unhex(value: String): ByteArray {
        require(value.length <= 131074 && hexPattern.matches(value)) { "invalid_corpus_bytes" }
        return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    private fun hex(value: ByteArray) = value.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun exact(value: JsonObject, vararg fields: String) { require(value.keys == fields.toSet()) { "invalid_corpus_fields" } }
    private fun JsonElement.objectValue() = this as? JsonObject ?: error("invalid_corpus_object")
    private fun JsonElement.stringValue() = (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("invalid_corpus_string")
    private fun JsonObject.string(key: String) = getValue(key).stringValue()
    private fun JsonObject.number(key: String, min: Long, max: Long): Long {
        val token = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content ?: error("invalid_corpus_integer")
        require(Regex("0|-?[1-9][0-9]*").matches(token)) { "invalid_corpus_integer" }
        return (token.toLongOrNull() ?: error("invalid_corpus_integer")).also { require(it in min..max) { "invalid_corpus_integer" } }
    }
    private fun obj(vararg values: Pair<String, JsonElement>) = JsonObject(sortedMapOf(*values))
    private fun str(value: String) = JsonPrimitive(value)
    private fun nullable(value: String?) = value?.let(::str) ?: JsonNull
    private fun num(value: Number) = JsonPrimitive(value)
    private fun bool(value: Boolean) = JsonPrimitive(value)

    /** Corpus-specific bounded duplicate guard; wire input uses the independent production codec. */
    private fun corpusJson(bytes: ByteArray): JsonObject {
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        require(!text.startsWith('\uFEFF')) { "invalid_corpus_json" }
        val keys = ArrayList<MutableSet<String>>()
        var index = 0
        while (index < text.length) {
            when (text[index]) {
                '{', '[' -> { require(keys.size < 64) { "invalid_corpus_depth" }; keys.add(HashSet()); index++ }
                '}', ']' -> { require(keys.isNotEmpty()) { "invalid_corpus_json" }; keys.removeAt(keys.lastIndex); index++ }
                '"' -> {
                    val start = index++
                    var ended = false
                    while (index < text.length) {
                        when (text[index++]) { '\\' -> { require(index < text.length) { "invalid_corpus_json" }; index++ }; '"' -> { ended = true; break } }
                    }
                    require(ended) { "invalid_corpus_json" }
                    var next = index
                    while (next < text.length && text[next] in " \r\n\t") next++
                    if (next < text.length && text[next] == ':') {
                        require(keys.isNotEmpty() && keys.last().add(json.parseToJsonElement(text.substring(start, index)).stringValue())) { "duplicate_corpus_member" }
                    }
                }
                else -> index++
            }
        }
        require(keys.isEmpty()) { "invalid_corpus_json" }
        return json.parseToJsonElement(text).objectValue()
    }
}
