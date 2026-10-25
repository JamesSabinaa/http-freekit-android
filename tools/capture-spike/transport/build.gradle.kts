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
    testImplementation(libs.java.websocket)
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
    if (name != "testDesktopHttpsIntegration") exclude("**/EnrolledCaptureHttpsDesktopTest*.class")
    if (name != "testDesktopPolicyIntegration") exclude("**/EnrolledCapturePolicyDesktopTest*.class")
}

val verifyDesktopHttpsIntegrationInput = tasks.register("verifyDesktopHttpsIntegrationInput") {
    doLast {
        val source = System.getenv("FREEKIT_DESKTOP_ROOT")
        check(source != null && File(source).isAbsolute && File(source).isDirectory &&
            System.getenv("FREEKIT_DESKTOP_COMMIT") == "2ee70e86b17e2feb2fd2bf4842a85c66671eb4c6") {
            "Explicit pinned HTTPS desktop source required"
        }
    }
}

tasks.register<Test>("testDesktopHttpsIntegration") {
    val unit = tasks.named<Test>("testDebugUnitTest").get()
    dependsOn(verifyDesktopHttpsIntegrationInput, unit.testClassesDirs, unit.classpath)
    testClassesDirs = unit.testClassesDirs
    classpath = unit.classpath
    javaLauncher.set(unit.javaLauncher)
    workingDir = rootProject.projectDir
    useJUnit()
    // The owned external desktop/Node fixture must execute for every requested proof.
    outputs.upToDateWhen { false }
    outputs.doNotCacheIf("Requires fresh external desktop execution") { true }
    systemProperty("com.sun.net.ssl.requireCloseNotify", "true")
    filter { includeTestsMatching("com.httpfreekit.capture.transport.EnrolledCaptureHttpsDesktopTest") }
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

tasks.register<Test>("testDesktopPolicyIntegration") {
    val unit = tasks.named<Test>("testDebugUnitTest").get()
    dependsOn(verifyDesktopHttpsIntegrationInput, unit.testClassesDirs, unit.classpath)
    testClassesDirs = unit.testClassesDirs
    classpath = unit.classpath
    javaLauncher.set(unit.javaLauncher)
    workingDir = rootProject.projectDir
    useJUnit()
    outputs.upToDateWhen { false }
    outputs.doNotCacheIf("Requires fresh policy and external desktop execution") { true }
    systemProperty("com.sun.net.ssl.requireCloseNotify", "true")
    filter { includeTestsMatching("com.httpfreekit.capture.transport.EnrolledCapturePolicyDesktopTest") }
}
