plugins { alias(libs.plugins.android.library) }

abstract class CaptureNativeBuild : Exec() {
    @get:OutputDirectory abstract val libraries: DirectoryProperty
    @get:OutputDirectory abstract val notices: DirectoryProperty
}

val python = providers.gradleProperty("pythonExecutable").orElse(
    if (System.getProperty("os.name").startsWith("Windows")) "python" else "python3"
)
val engineRoot = providers.gradleProperty("captureEngineRoot").orElse(
    rootProject.layout.projectDirectory.dir(".gradle/engine-spike/hev-socks5-tunnel").asFile.absolutePath
)
val buildNative = tasks.register<CaptureNativeBuild>("buildNative") {
    workingDir(rootProject.projectDir)
    libraries.set(layout.buildDirectory.dir("native/libs"))
    notices.set(layout.buildDirectory.dir("native/assets"))
    outputs.upToDateWhen { false }
    commandLine(
        python.get(), "tools/engine-spike/build_android_probe.py",
        "--engine-root", engineRoot.get(),
        "--ndk-root", file(providers.environmentVariable("ANDROID_HOME").get()).resolve("ndk/28.2.13676358"),
        "--output-root", layout.buildDirectory.dir("native").get().asFile,
        "--application-mk", projectDir.resolve("Application.mk"),
        "--jni-package", "com/httpfreekit/capture", "--jni-class", "NativeEngine", "--purpose", "capture", "--fetch"
    )
}

android {
    namespace = "com.httpfreekit.capture"
    compileSdk { version = release(37) }
    buildToolsVersion = "36.0.0"
    ndkVersion = "28.2.13676358"
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint { warningsAsErrors = true }
}
androidComponents.onVariants { variant ->
    variant.sources.jniLibs?.addGeneratedSourceDirectory(buildNative, CaptureNativeBuild::libraries)
    variant.sources.assets?.addGeneratedSourceDirectory(buildNative, CaptureNativeBuild::notices)
}
kotlin { jvmToolchain(17) }
dependencies { testImplementation(libs.junit) }
