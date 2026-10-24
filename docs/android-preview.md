# Android interface preview

Package B now provides a local Compose preview of the companion flow. It is built against the [draft protocol parser](protocol.md), without enrollment, network access, a VPN service, a CA installer, or traffic capture. The persistent banner and connection controls identify it as a preview. A simulated connection never marks HTTPS trust or successful capture as verified.

## Explore the interface

1. On Home, choose **Try a sample computer**. This creates a public sample identity in memory, with simulated device credentials.
2. In Apps, select one or more example apps. These are fixture entries, not a list of installed applications; no routing is changed.
3. Choose **Preview connection**. Notification permission and VPN consent are separate simulated choices. The VPN dialog explains the one-active-VPN constraint. No Android permission dialog or real VPN starts.
4. Allow the preview to reach its ready state. Setup checks continue to show HTTPS trust and capture as unverified. **Stop preview** invalidates pending connection completions immediately.
5. In Diagnostics, toggle gateway availability or simulate network changes, missing keys, revoked credentials, unavailable camera, and preference restoration. Reconnect has a bounded three-attempt budget and a visible terminal failure state.

To explore an invitation, choose **Add computer** and paste a fresh payload matching the draft. Native text-field paste is available; QR scanning is not implemented. The field obscures the credential. Review the computer name, logical TLS name, public SPKI fingerprint, route hint, and expiry before choosing **Use in preview**. Expiration is checked again when the review is confirmed. The desktop approval step remains separate; its approve/reject controls explicitly simulate the outcome and send no request.

Only public invitation metadata enters the preview coordinator. The invitation ID and invitation secret are not retained in that model or its diagnostics. The raw input is not put in saved instance state. Diagnostics hold at most 20 enum event codes, with no payload, URL, certificate, header, or exception detail.

The state holder uses an activity-scoped [ViewModel](https://developer.android.com/topic/libraries/architecture/viewmodel) to retain the preview across configuration changes. A new process starts empty, with no saved computer or key. The **Restore without saved credentials** scenario exercises the future preferences-restoration boundary: public computers and app choices survive in that scenario, credentials and permission state do not, and pairing is required again. This does not implement durable preference or credential storage.

Setup help distinguishes desktop identity, VPN consent, user CA installation, debug-app trust, certificate pinning, DNS behavior, Stop, Forget, and desktop revocation. Forgetting a preview computer does not claim to remove a user-installed Android CA.

## Validation and limits

Host validation uses:

```powershell
./gradlew.bat :app:testDebugUnitTest :app:assembleDebug :app:lintDebug
```

The pure coordinator tests cover invitation rejection/expiry, explicit review and approval, cancelled/rejected enrollment, missing prerequisites, notification denial, cancelled VPN consent, existing-VPN warning state, Stop races, app-selection stability during an active preview, revocation, network-change attempt replacement, bounded reconnect, restored preferences without credentials, Forget, unavailable camera, and diagnostic bounds. See [developer setup](development.md) for toolchain configuration.

Host evidence on 2026-10-24: the command above with `--rerun-tasks` passed all 19 lifecycle tests, assembled the debug APK, and completed Android lint with `No issues found.` The other-VPN regression also verifies that a competing VPN invalidates an existing preview grant and requires fresh consent. Resource XML parsing, 22 local Markdown links, and `git diff --check` passed. No checks or lint rules were disabled.

Emulator and physical-device launch, Compose rendering/accessibility, keyboard behavior, rotation, system VPN consent, notification Stop, OS VPN revocation, real installed-app discovery, credential persistence, and network transitions remain unrun or unimplemented. No service lifecycle or capture gate is satisfied by these host tests. Package B remains open until its device and production integration criteria in [the work board](../tasks/README.md) are proved.
