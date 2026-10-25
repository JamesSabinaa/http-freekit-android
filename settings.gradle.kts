pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "HTTPFreeKitAndroid"
include(":app", ":core-protocol", ":core-security")
include(":transport-interop")
project(":transport-interop").projectDir = file("tools/transport-spike/android")
include(":transport-framing")
project(":transport-framing").projectDir = file("tools/transport-spike/framing")
include(":installed-app-fixture")
project(":installed-app-fixture").projectDir = file("tools/installed-app-fixture")
include(":core-capture")
include(":capture-runtime", ":capture-traffic")
project(":capture-runtime").projectDir = file("tools/capture-spike/runtime")
project(":capture-traffic").projectDir = file("tools/capture-spike/traffic")
