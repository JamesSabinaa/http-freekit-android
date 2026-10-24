plugins { alias(libs.plugins.android.library) }

abstract class NativeProbeBuild : Exec() {
    @get:OutputDirectory abstract val libraries: DirectoryProperty
    @get:OutputDirectory abstract val notices: DirectoryProperty
}

val repositoryRoot = rootDir.resolve("../../..").canonicalFile
val sdkRoot = providers.environmentVariable("ANDROID_HOME")
val python = providers.gradleProperty("pythonExecutable").orElse(
    if (System.getProperty("os.name").startsWith("Windows")) "python" else "python3"
)
val buildNative = tasks.register<NativeProbeBuild>("buildNative") {
    workingDir(repositoryRoot)
    libraries.set(layout.buildDirectory.dir("native/libs"))
    notices.set(layout.buildDirectory.dir("native/assets"))
    // Always verify the cache, including on an otherwise up-to-date build.
    outputs.upToDateWhen { false }
    commandLine(
        python.get(), "tools/engine-spike/build_android_probe.py",
        "--engine-root", repositoryRoot.resolve(".gradle/engine-spike/hev-socks5-tunnel"),
        "--ndk-root", file(sdkRoot.get()).resolve("ndk/28.2.13676358"),
        "--output-root", layout.buildDirectory.dir("native").get().asFile,
        "--application-mk", rootDir.resolve("Application.mk"), "--fetch"
    )
}

android {
    namespace = "com.httpfreekit.engineprobe"
    testNamespace = "com.httpfreekit.engineprobe.test"
    compileSdk { version = release(37) }
    buildToolsVersion = "36.0.0"
    ndkVersion = "28.2.13676358"
    defaultConfig {
        minSdk = 26
        testApplicationId = "com.httpfreekit.engineprobe.test"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint { warningsAsErrors = true }
}
androidComponents.onVariants { variant ->
    variant.sources.jniLibs?.addGeneratedSourceDirectory(buildNative, NativeProbeBuild::libraries)
    variant.sources.assets?.addGeneratedSourceDirectory(buildNative, NativeProbeBuild::notices)
}
tasks.named("preBuild") { dependsOn(buildNative) }

dependencies {
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.android.test.runner)
    androidTestImplementation(libs.android.test.junit)
}
