import java.security.MessageDigest

plugins { alias(libs.plugins.kotlin.jvm) }
kotlin { jvmToolchain(17) }
dependencies {
    implementation(libs.java.websocket)
    implementation(libs.slf4j.api)
    implementation(libs.slf4j.nop)
    testImplementation(libs.junit)
    testImplementation(libs.okhttp.tls)
}

val verifyEngineArtifact = tasks.register("verifyEngineArtifact") {
    inputs.files(configurations.runtimeClasspath)
    doLast {
        val artifact = configurations.runtimeClasspath.get().files.single { it.name == "Java-WebSocket-1.6.0.jar" }
        val digest = MessageDigest.getInstance("SHA-256").digest(artifact.readBytes())
            .joinToString("") { "%02x".format(it) }
        check(digest == "eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f") {
            "Maintained WebSocket artifact verification failed"
        }
    }
}
tasks.named("compileKotlin") { dependsOn(verifyEngineArtifact) }
tasks.test {
    dependsOn(verifyEngineArtifact)
    workingDir = rootProject.projectDir
    useJUnit()
    testLogging { events("passed", "skipped", "failed") }
}
