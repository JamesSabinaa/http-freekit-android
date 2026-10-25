plugins { alias(libs.plugins.android.application) }

android {
    namespace = "com.httpfreekit.capturetraffic"
    compileSdk { version = release(37) }
    buildToolsVersion = "36.0.0"
    defaultConfig {
        applicationId = "com.httpfreekit.capturetraffic"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "1.0-research"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint { warningsAsErrors = true }
}
kotlin { jvmToolchain(17) }
