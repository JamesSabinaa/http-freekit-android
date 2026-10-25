import java.io.File

plugins { alias(libs.plugins.android.library) }
android {
    namespace = "com.httpfreekit.capture.transport"
    compileSdk { version = release(37) }
    buildToolsVersion = "36.0.0"
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint { warningsAsErrors = true }
    packaging.resources.merges += setOf("META-INF/LICENSE", "META-INF/LICENSE.txt", "META-INF/NOTICE", "META-INF/NOTICE.txt")
}
kotlin { jvmToolchain(17) }
dependencies {
    implementation(project(":core-protocol"))
    implementation(project(":core-security"))
    implementation(project(":core-capture"))
    implementation(project(":gateway-websocket"))
    testImplementation(libs.junit)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.serialization.json)
}

val verifyDesktopIntegrationInput = tasks.register("verifyDesktopIntegrationInput") {
    doLast {
        val source = System.getenv("FREEKIT_DESKTOP_ROOT")
        check(source != null && File(source).isAbsolute && File(source).isDirectory &&
            System.getenv("FREEKIT_DESKTOP_COMMIT") == "fd63f6940226c8e3401a165082dfa9325abaca69") {
            "Explicit pinned desktop source required"
        }
    }
}

tasks.withType<Test>().configureEach {
    if (name != "testDesktopIntegration") exclude("**/EnrolledCaptureDesktopTest*.class")
}

tasks.register<Test>("testDesktopIntegration") {
    val unit = tasks.named<Test>("testDebugUnitTest").get()
    dependsOn(verifyDesktopIntegrationInput, unit.testClassesDirs, unit.classpath)
    testClassesDirs = unit.testClassesDirs
    classpath = unit.classpath
    javaLauncher.set(unit.javaLauncher)
    workingDir = rootProject.projectDir
    useJUnit()
    filter { includeTestsMatching("com.httpfreekit.capture.transport.EnrolledCaptureDesktopTest") }
}
