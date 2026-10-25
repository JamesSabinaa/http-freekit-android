plugins { alias(libs.plugins.android.library) }

android {
    namespace = "com.httpfreekit.interop"
    compileSdk { version = release(37) }
    buildToolsVersion = "36.0.0"
    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        listOf("gatewayDer", "gatewayPin", "enrollmentPort", "webSocketPort").forEach { name ->
            providers.gradleProperty("interop.$name").orNull?.let { testInstrumentationRunnerArguments[name] = it }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint { warningsAsErrors = true }
    packaging.resources.merges += setOf("META-INF/LICENSE.md", "META-INF/NOTICE.md")
}
kotlin { jvmToolchain(17) }
val interceptionCaPeerInputs = rootProject.fileTree("tools/transport-spike") {
    include(
        "companion-interception-ca-peer.mjs",
        "companion-enrollment-authority.mjs",
        "companion-enrollment-codec.mjs",
        "companion-enrollment-crypto-fixtures.mjs",
        "companion-enrollment-crypto.mjs",
        "companion-enrollment-https-assets.mjs",
        "companion-enrollment-https.mjs",
        "companion-enrollment-issuer.mjs",
        "companion-enrollment-store.mjs",
        "companion-enrollment-stream-client.mjs",
        "companion-protocol-codec.mjs",
        "companion-stream-peer-client.mjs",
        "companion-stream-peer-io.mjs",
        "companion-stream-peer-schema.mjs",
        "android-peer.mjs",
        "draft-stream-command.mjs",
        "research-websocket.mjs",
        "package.json",
        "package-lock.json",
    )
}
val interceptionCaProofCommit = providers.exec {
    workingDir(rootProject.projectDir)
    commandLine("git", "rev-parse", "HEAD")
}.standardOutput.asText.map { it.trim() }
androidComponents.onVariants { variant ->
    variant.hostTests.values.forEach { test ->
        checkNotNull(test.sources.kotlin).addStaticSourceDirectory("../ca-client/src/main/kotlin")
        test.configureTestTask { task ->
            task.workingDir = rootProject.projectDir
            task.inputs.files(interceptionCaPeerInputs)
            task.inputs.property("interceptionCaProofCommit", interceptionCaProofCommit)
            task.outputs.file(rootProject.layout.projectDirectory.file("build/reports/interception-ca/jvm-tls.json"))
        }
    }
    variant.deviceTests.values.forEach { test ->
        checkNotNull(test.sources.kotlin).apply {
            addStaticSourceDirectory("../ca-client/src/main/kotlin")
            addStaticSourceDirectory("../../capture-spike/shared-traffic/src/main/kotlin")
            addStaticSourceDirectory("../../capture-spike/shared-traffic/src/androidTest/kotlin")
        }
    }
}
dependencies {
    testImplementation(libs.junit)
    testImplementation(project(":core-security"))
    testImplementation(project(":core-protocol"))
    testImplementation(libs.serialization.json)
    testImplementation(libs.okhttp.tls)
    androidTestImplementation(project(":core-security"))
    androidTestImplementation(project(":core-protocol"))
    androidTestImplementation(project(":transport-framing"))
    androidTestImplementation(project(":core-capture"))
    androidTestImplementation(project(":capture-transport-research"))
    androidTestImplementation(libs.android.test.runner)
    androidTestImplementation(libs.android.test.junit)
}
