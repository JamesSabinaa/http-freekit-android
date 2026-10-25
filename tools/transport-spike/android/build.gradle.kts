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
dependencies {
    testImplementation(libs.junit)
    androidTestImplementation(project(":core-security"))
    androidTestImplementation(project(":core-protocol"))
    androidTestImplementation(project(":transport-framing"))
    androidTestImplementation(project(":core-capture"))
    androidTestImplementation(project(":capture-transport-research"))
    androidTestImplementation(libs.android.test.runner)
    androidTestImplementation(libs.android.test.junit)
}
