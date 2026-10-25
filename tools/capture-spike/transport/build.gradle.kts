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
}
