plugins { alias(libs.plugins.kotlin.jvm) }
kotlin { jvmToolchain(17) }
dependencies {
    implementation(libs.serialization.json)
    testImplementation(libs.junit)
    testImplementation(libs.okhttp)
    testImplementation(libs.okhttp.tls)
}
tasks.test {
    inputs.dir(rootProject.layout.projectDirectory.dir("protocol/fixtures"))
    outputs.file(rootProject.layout.projectDirectory.file("build/reports/draft-protocol/kotlin-conformance.json"))
    outputs.file(rootProject.layout.projectDirectory.file("build/reports/draft-enrollment/kotlin-conformance.json"))
    useJUnit()
    workingDir = rootProject.projectDir
    testLogging { events("passed", "skipped", "failed") }
}
