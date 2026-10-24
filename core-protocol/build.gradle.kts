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
    useJUnit()
    workingDir = rootProject.projectDir
    testLogging { events("passed", "skipped", "failed") }
}
