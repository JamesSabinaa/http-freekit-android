# Dependency notices

This independent implementation does not incorporate HTTP Toolkit Android source or native forwarding-engine source. The root MIT licence covers project-authored code; it does not replace third-party licences.

| Dependency family | Use | Upstream licence/source |
| --- | --- | --- |
| Kotlin standard library, kotlinx.serialization | Runtime and draft parser | [Apache-2.0](https://github.com/JetBrains/kotlin/blob/master/license/LICENSE.txt) |
| AndroidX Activity, Compose and their AndroidX dependencies | Android UI runtime | [Apache-2.0](https://android.googlesource.com/platform/frameworks/support/+/androidx-main/LICENSE.txt) |
| Gradle wrapper | Build bootstrap only | [Apache-2.0](third-party/gradle-LICENSE.txt); generated wrapper scripts retain upstream headers |
| Android Gradle Plugin | Build tooling only | [Apache-2.0](https://android.googlesource.com/platform/tools/base/+/mirror-goog-studio-main/LICENSE) |
| OkHttp, Okio, okhttp-tls | JVM test transport only | [Apache-2.0](https://github.com/square/okhttp/blob/parent-5.5.1/LICENSE.txt) |
| JUnit 4, Hamcrest | Tests only | [EPL-1.0](https://github.com/junit-team/junit4/blob/main/LICENSE-junit.txt), [BSD-3-Clause](https://github.com/hamcrest/JavaHamcrest/blob/master/LICENSE.txt) |
| ws | Node test peer only | [MIT](https://github.com/websockets/ws/blob/master/LICENSE) |

The Gradle distribution includes additional third-party licences. Native engine candidate licence findings are recorded in the [foundation decision](docs/decisions/0001-foundation.md); they are not shipped dependencies. A complete resolved runtime dependency inventory, bundled notices, and licence check remain release gates before distributing a production app.
