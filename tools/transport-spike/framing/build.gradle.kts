plugins { alias(libs.plugins.kotlin.jvm) }
kotlin { jvmToolchain(17) }
dependencies { testImplementation(libs.junit) }
tasks.test {
    workingDir = rootProject.projectDir
    inputs.files(rootProject.file("tools/transport-spike/research-websocket.mjs"),
        rootProject.file("tools/transport-spike/research-websocket-peer.mjs"))
    useJUnit()
    testLogging { events("passed", "skipped", "failed") }
}
