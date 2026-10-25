plugins { alias(libs.plugins.android.application) }

android {
    namespace = "com.httpfreekit.capturetest"
    compileSdk { version = release(37) }
    buildToolsVersion = "36.0.0"
    defaultConfig {
        applicationId = "com.httpfreekit.capturetest"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "1.0-research"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint { warningsAsErrors = true }
}
kotlin { jvmToolchain(17) }
androidComponents.onVariants { variant ->
    checkNotNull(variant.sources.kotlin).addStaticSourceDirectory("../shared-traffic/src/main/kotlin")
    variant.deviceTests.values.forEach { test ->
        checkNotNull(test.sources.kotlin).addStaticSourceDirectory("../shared-traffic/src/androidTest/kotlin")
    }
}
dependencies {
    implementation(project(":core-capture"))
    testImplementation(libs.junit)
    androidTestImplementation(libs.android.test.runner)
    androidTestImplementation(libs.android.test.junit)
}
