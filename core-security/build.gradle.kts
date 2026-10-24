plugins { alias(libs.plugins.android.library) }

android {
    namespace = "com.httpfreekit.security"
    compileSdk { version = release(37) }
    buildToolsVersion = "36.0.0"
    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint { warningsAsErrors = true }
    packaging {
        resources.merges += "META-INF/LICENSE.md"
        resources.merges += "META-INF/NOTICE.md"
    }
}

androidComponents.onVariants { variant ->
    variant.hostTests.values.forEach { checkNotNull(it.sources.kotlin).addStaticSourceDirectory("src/sharedTest/kotlin") }
    variant.deviceTests.values.forEach { checkNotNull(it.sources.kotlin).addStaticSourceDirectory("src/sharedTest/kotlin") }
}

tasks.withType<Test>().configureEach {
    workingDir = rootProject.projectDir
    inputs.files(rootProject.files(
        "tools/transport-spike/server.mjs", "tools/transport-spike/package.json", "tools/transport-spike/package-lock.json",
    ))
}
kotlin { jvmToolchain(17) }

dependencies {
    implementation(libs.bouncycastle.provider)
    testImplementation(libs.junit)
    testImplementation(libs.okhttp)
    testImplementation(libs.okhttp.tls)
    androidTestImplementation(libs.android.test.runner)
    androidTestImplementation(libs.android.test.junit)
}
