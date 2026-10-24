# Android interface preview

Package B provides a local Compose preview of the companion flow and an installed-app selector. The connection flow uses the [draft protocol parser](protocol.md), without enrollment, network access, a VPN service, a CA installer, or traffic capture. The persistent banner and connection controls identify it as a preview. Real package selection does not change routing, HTTPS trust, or capture status.

## Explore the interface

1. On Home, choose **Try a sample computer**. This creates a public sample identity in memory, with simulated device credentials, and explicitly selects the sample app catalogue.
2. In Apps, select example apps under **Sample apps**, or explicitly choose **Installed apps** to load enabled applications in this profile. The lists keep separate selections; no routing is changed.
3. Choose **Preview connection**. Notification permission and VPN consent are separate simulated choices. The VPN dialog explains the one-active-VPN constraint. No Android permission dialog or real VPN starts.
4. Allow the preview to reach its ready state. Setup checks continue to show HTTPS trust and capture as unverified. **Stop preview** invalidates pending connection completions immediately.
5. In Diagnostics, toggle gateway availability or simulate network changes, missing keys, revoked credentials, unavailable camera, and preference restoration. Reconnect has a bounded three-attempt budget and a visible terminal failure state.

To explore an invitation, choose **Add computer** and paste a fresh payload matching the draft. Native text-field paste is available; QR scanning is not implemented. The field obscures the credential. Review the computer name, logical TLS name, public SPKI fingerprint, route hint, and expiry before choosing **Use in preview**. Expiration is checked again when the review is confirmed. The desktop approval step remains separate; its approve/reject controls explicitly simulate the outcome and send no request.

Only public invitation metadata enters the preview coordinator. The invitation ID and invitation secret are not retained in that model or its diagnostics. The raw input is not put in saved instance state. Diagnostics hold at most 20 enum event codes, with no payload, URL, certificate, header, or exception detail.

The state holder uses an activity-scoped [ViewModel](https://developer.android.com/topic/libraries/architecture/viewmodel) to retain the preview across configuration changes. A new process starts empty, with no saved computer or key. The **Restore without saved credentials** scenario exercises the future preferences-restoration boundary: public computers and app choices survive in that scenario, credentials and permission state do not, and pairing is required again. This does not implement durable preference or credential storage.

Setup help distinguishes desktop identity, VPN consent, user CA installation, debug-app trust, certificate pinning, DNS behavior, Stop, Forget, and desktop revocation. Forgetting a preview computer does not claim to remove a user-installed Android CA.

## Installed-app selection

**Installed apps** queries the platform's current-profile installed applications on a background worker. It includes enabled system and development packages without launcher activities, excludes this companion package, removes duplicate package entries, and sorts by application label then package name. **All apps** shows that full enabled catalogue; **Development** filters it to the platform's debuggable flag. This flag does not establish HTTPS trust or interception support. Search matches labels and package names without changing hidden selections.

Loading is explicit: starting the app or using the sample flow does not request installed-app inventory. **Refresh apps** loads a new snapshot. A successful inactive refresh removes selections for vanished or disabled packages; a failed refresh keeps the last successful list and choices, with a fixed error message. Request identifiers reject stale background results after catalogue changes. Source, selection, and refresh controls lock during an active connection simulation. A scan already in flight may finish, but cannot change that active selection; Stop reconciles it with the last successful snapshot.

The activity ViewModel retains both catalogues' choices through rotation, not process death. Labels, package names, search text and choices remain in memory. They are not logged, transmitted or persisted. The provider retains only application context. Clearing the ViewModel cancels queued work and callbacks, requests interruption of the active scan, and rejects late completions; a synchronous platform query may finish before stopping. There is no app launch action or installation request.

Full discovery on Android 11+ uses the coordinator-owned `QUERY_ALL_PACKAGES` manifest declaration, with the explicitly approved permission-scoped lint exception recorded in [the discovery decision](decisions/0010-installed-app-discovery.md). No broader lint rule is disabled. See [Android package visibility](https://developer.android.com/training/package-visibility) and the [PackageManager API](https://developer.android.com/reference/android/content/pm/PackageManager). The provider uses the typed API 33 overload and the integer overload on API 26–32.

## Validation and limits

Host validation uses:

```powershell
./gradlew.bat :app:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug
```

The pure coordinator tests cover invitation rejection/expiry, explicit review and approval, cancelled/rejected enrollment, missing prerequisites, notification denial, cancelled VPN consent, existing-VPN warning state, Stop races, app-selection stability during an active preview, revocation, network-change attempt replacement, bounded reconnect, restored preferences without credentials, Forget, unavailable camera, and diagnostic bounds. Fourteen additional pure app-selection cases cover explicit loading, sorting/deduplication, defensive snapshots, filters/search, unknown IDs, separate catalogues, successful pruning, failed refresh retention, stale requests, active selection locks, deferred pruning, empty lists and redacted default diagnostics. See [developer setup](development.md) for toolchain configuration.

Original shell host evidence on 2026-10-24: the command above with `--rerun-tasks` passed all 19 lifecycle tests, assembled the debug APK, and completed Android lint with `No issues found.` The other-VPN regression also verifies that a competing VPN invalidates an existing preview grant and requires fresh consent. Resource XML parsing, 22 local Markdown links, and `git diff --check` passed. No checks or lint rules were disabled at that checkpoint.

B3 host validation passes all 33 app JVM cases (19 coordinator and 14 selection), builds the debug app and existing sample instrumentation APK, and passes strict lint with `No issues found.` The first incremental lint report retained caller warnings after the permission manifest update; a fresh `--no-build-cache :app:lintDebug --rerun-tasks` run regenerated the analysis and report successfully. No caller-site suppression or additional lint exception was added. This is local compilation/model evidence, not execution of installed discovery on Android.

The original sample-only Compose runtime results are recorded in [preview runtime evidence](android-preview-runtime.md). They do not establish real installed-app discovery. F owns separate API 26/37 tests using an unrelated, headless synthetic debug package; those checks must prove actual discovery, filtering/search, selection/rotation, disabled-package refresh and source isolation before device acceptance. No installed-list screenshot is part of the sample screenshot flow. System VPN consent, notification Stop, OS VPN revocation, physical-device behavior and capture remain separate gates. Package B remains open until its device and production integration criteria in [the work board](../tasks/README.md) are proved.
