# Round 6 Deep Scan — System Apps + Additional Services Audit

**Date:** 2026-04-29
**Scope:** Batch 1 (Location, Audio, Power, Shortcut, CompanionDevice) + Batch 2 (LauncherApps, CrossProfileApps, MediaSession, Display, TextServices, NotificationListener) + Batch 3 (Settings, SystemUI, Launcher3, Dialer/Contacts, Gallery, DocumentsUI)
**Method:** Source code review of AOSP `main` branch
**Target:** Pixel 10 (frankel), Android 16, CP1A.260405.005, patch 2026-04-05

---

## Executive Summary

| Batch | Components | Findings | Top Severity |
|-------|-----------|----------|-------------|
| Batch 1: Framework Services | 5 services | 20 | HIGH (CDM-1) |
| Batch 2: Framework Services | 6 services | 19 | HIGH (DMS-1) |
| Batch 3: System Apps | 6 apps | 15 | HIGH (SET-1) |
| **TOTAL** | **17** | **54** | **HIGH** |

### Top Priority Findings

| ID | Severity | Component | Issue | Est. Bounty |
|----|----------|-----------|-------|-------------|
| V-176 (CDM-1) | HIGH | CompanionDeviceManager | enableSystemDataSync/disableSystemDataSync zero permission | $5k-$15k |
| V-167 (DMS-1) | HIGH | DisplayManagerService | overrideHdrTypes() zero permission check | $5k-$15k |
| V-171 (SET-1) | HIGH | Settings/SubSettings | isValidFragment() returns true for ALL — universal fragment injection | $5k-$15k |
| V-173 (SET-2) | MED-HIGH | Settings/Trampoline | Deep link URI parsing allows internal component launch | $3k-$7.5k |
| V-172 (GAL-1) | MED-HIGH | Gallery2 | FLAG_DISMISS_KEYGUARD via intent extra — lock screen bypass | $3k-$7.5k |
| V-169 (MSS-2) | MED-HIGH | MediaSessionService | dispatchMediaKeyEventToSessionAsSystemService missing perm | $3k-$7.5k |
| V-178 (LOC-1) | MED-HIGH | LocationManager | LOCATION_BYPASS over-grants FINE access | $3k-$7.5k |
| V-168 (CPA-1) | MED | CrossProfileApps | checkCallingOrSelfPermission return value discarded | $3k-$7.5k |
| V-177 (AUD-2/3) | MED | AudioService | Call volume/mic mute with normal-level permission | $2k-$5k |
| V-179 (CDM-3/4) | MED | CompanionDeviceManager | disassociate() no visible permission enforcement | $2k-$5k |

---

## Batch 1: Location, Audio, Power, Shortcut, CompanionDevice

### CompanionDeviceManagerService

#### CDM-1 [HIGH] — enableSystemDataSync/disableSystemDataSync Zero Permission (V-176)
- **File:** `frameworks/base/services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java`, lines 601-608
- **Methods:** `enableSystemDataSync(associationId, flags)`, `disableSystemDataSync(associationId, flags)`
- **Issue:** NO permission check at all. Compare: `enablePermissionsSync`/`disablePermissionsSync` check `getCallingUid() != SYSTEM_UID`. Association IDs are sequential integers, easily guessable.
- **Impact:** Any app can enable/disable system data transfer (contacts, call logs etc.) to/from companion devices for any association.
- **Attack:** Enumerate IDs (1,2,3...) → `enableSystemDataSync(id, ALL_FLAGS)` → data syncs to companion device.

#### CDM-2 [MED] — isCompanionApplicationBound() Info Leak
- **File:** Same, line 651
- **Issue:** Returns companion binding state for any package+user without permission check.

#### CDM-3 [MED] — legacyDisassociate() No Visible Permission Enforcement (V-179)
- **File:** Same, line 407
- **Issue:** Delegates directly to processor without visible permission check in stub.

#### CDM-4 [MED] — disassociate(int) No Visible Permission Enforcement (V-179)
- **File:** Same, line 415
- **Issue:** Same as CDM-3 but with integer-based IDs — even easier to enumerate.

### LocationManagerService

#### LOC-1 [MED-HIGH] — LOCATION_BYPASS Over-Grants FINE Permission (V-178)
- **File:** `frameworks/base/services/core/java/com/android/server/location/LocationManagerService.java`
- **Methods:** `getCurrentLocation()`, `registerLocationListener()`, `registerLocationPendingIntent()`, `getLastLocation()`
- **Issue:** When `Flags.enableLocationBypass()` is true, `LOCATION_BYPASS` (signature|privileged) grants PERMISSION_FINE level instead of COARSE. Pattern repeats in 4 methods.
- **Impact:** Emergency-purpose app with LOCATION_BYPASS gets full GPS coordinates.

#### LOC-2 [MED] — Test Provider Methods Use Unsafe CallerIdentity
- **File:** Same
- **Issue:** `addTestProvider()` etc. use `CallerIdentity.fromBinderUnsafe(packageName)`. TOCTOU between identity creation and AppOps validation.

#### LOC-3 [LOW-MED] — Allowlist Package Name Leak
- **File:** Same
- **Methods:** `getBackgroundThrottlingWhitelist()`, `getIgnoreSettingsAllowlist()`, `getAdasAllowlist()`
- **Issue:** Return security-relevant allowlists without any permission check.

### AudioService

#### AUD-2 [MED] — Voice Call Volume Adjustable with Normal Permission (V-177)
- **File:** `frameworks/base/services/core/java/com/android/server/audio/AudioService.java`, line 3834
- **Method:** `adjustStreamVolume()`
- **Issue:** `MODIFY_PHONE_STATE` check only applies to mute (isMuteAdjust). Non-mute volume adjust on `STREAM_VOICE_CALL` only needs `MODIFY_AUDIO_SETTINGS` (normal level, auto-granted).
- **Impact:** Any app can max/min call volume during active call — acoustic harm or call disruption.

#### AUD-3 [MED] — setMicrophoneMute with Normal Permission (V-177)
- **File:** Same, line 5899
- **Issue:** Only requires `MODIFY_AUDIO_SETTINGS` (normal level). Any app can silently mute device microphone during calls/recordings.

#### AUD-1 [MED] — forceVolumeControlStream Silent Failure
- **File:** Same, line 5224
- **Issue:** Silently returns on permission denial instead of throwing SecurityException.

#### AUD-5 [LOW] — Surround Format Capabilities Leak
- **Issue:** `getSurroundFormats()` returns hardware capabilities without permission — device fingerprinting.

### PowerManagerService

#### PWR-1 [MED-HIGH] — onShellCommand No Explicit Permission Check
- **File:** `frameworks/base/services/core/java/com/android/server/power/PowerManagerService.java`, line 5760
- **Issue:** Unlike AudioService which checks MANAGE_AUDIO_POLICY, PowerManager's onShellCommand has no explicit check. Relies on Binder framework implicit shell check.

#### PWR-2 [MED] — Wakelock UID Attribution Manipulation
- **File:** Same, line 5767
- **Issue:** `acquireWakeLockWithUid()` with arbitrary UID attribution. Protected by UPDATE_DEVICE_STATS but allows battery stats manipulation.

### ShortcutService

#### SC-1 [MED-HIGH] — Shell Commands Run as SYSTEM_UID
- **File:** `frameworks/base/services/core/java/com/android/server/pm/ShortcutService.java`, line 4952
- **Issue:** `onShellCommand()` calls `clearCallingIdentity()` after `enforceShell()`. Shell commands execute as system_server identity, bypassing all `isCallerSystem()` checks.
- **Impact:** `cmd shortcut` can manipulate shortcuts for any package/user as system.

#### SC-2 [LOW-MED] — verifyCaller System UID Bypass
- **File:** Same, line 1727
- **Issue:** Returns immediately if `isCallerSystem()`, bypassing package+user validation.

---

## Batch 2: Framework Services

### DisplayManagerService

#### DMS-1 [HIGH] — overrideHdrTypes() Zero Permission Check (V-167)
- **File:** `frameworks/base/services/core/java/com/android/server/display/DisplayManagerService.java`, ~line 4703
- **Method:** `BinderService.overrideHdrTypes(int displayId, int[] modes)`
- **Issue:** No permission check at all. Compare: `setUserDisabledHdrTypes` and `setAreUserDisabledHdrTypesAllowed` both require `WRITE_SECURE_SETTINGS`.
- **Impact:** Any app can modify SurfaceFlinger display HDR configuration. Can disable HDR or set bogus types.
- **Attack:** `DisplayManager.overrideHdrTypes(0, new int[]{})` — disables all HDR.

#### DMS-2 [MED] — disconnectWifiDisplay() No Permission Check (V-170)
- **File:** Same, ~line 4604
- **Issue:** Connecting requires `CONFIGURE_WIFI_DISPLAY`, but disconnecting requires nothing. Code comment acknowledges this.
- **Impact:** Any app can disrupt WFD (Miracast) sessions.

#### DMS-3 [LOW-MED] — isUidPresentOnDisplay() Cross-UID Leak
- **File:** Same, ~line 4501
- **Issue:** Accepts arbitrary `uid` parameter, no caller check. Can enumerate active UIDs across displays.

### CrossProfileAppsServiceImpl

#### CPA-1 [MED] — checkCallingOrSelfPermission Return Value Discarded (V-168)
- **File:** `frameworks/base/services/core/java/com/android/server/pm/CrossProfileAppsServiceImpl.java`, ~line 604
- **Methods:** `canConfigureInteractAcrossProfiles()`, `canUserAttemptToConfigureInteractAcrossProfiles()`
- **Issue:** Calls `checkCallingOrSelfPermission(INTERACT_ACROSS_USERS)` but **discards the return value**. Should use `enforceCallingOrSelfPermission()`.
- **Impact:** Any app can query cross-user profile configurations without INTERACT_ACROSS_USERS.

#### CPA-3 [LOW-MED] — startActivityAsUserByIntent Extras Not Stripped
- **File:** Same, ~line 199
- **Issue:** Doesn't strip extras/data URI from cross-profile intent.

### MediaSessionService

#### MSS-2 [MED-HIGH] — dispatchMediaKeyEventToSessionAsSystemService Missing Permission (V-169)
- **File:** `frameworks/base/services/core/java/com/android/server/media/MediaSessionService.java`, ~line 1848
- **Issue:** Dispatches key events with `asSystemService=true` without verifying caller is system. Any app with valid session token can inject system-level events.

#### MSS-1 [MED] — dispatchMediaKeyEvent packageName Not Validated
- **File:** Same, ~line 1774
- **Issue:** `packageName` parameter accepted without validating against calling UID. Caller impersonation.

#### MSS-3 [LOW-MED] — addSession2TokensListener Skips Media Permission
- **File:** Same, ~line 1702
- **Issue:** `addSessionsListener()` calls `verifySessionsRequest()` but `addSession2TokensListener()` does not.

### LauncherAppsService

#### LA-1 [MED-HIGH] — Hidden Profile Feature Flag Gate Bypass
- **File:** `LauncherAppsService.java`, ~line 600
- **Issue:** Hidden profile protection gated behind 5 feature flags. If ANY ONE is disabled (staged rollout, config), `canAccessHiddenProfile()` returns true unconditionally.
- **Impact:** Third-party launchers can enumerate hidden/private profile data.

#### LA-3 [MED] — getActivityOverrides Skips canAccessProfile
- **File:** Same, ~line 1447
- **Issue:** Checks shortcut permission but never calls `canAccessProfile()` for managed profile.

#### LA-4 [LOW-MED] — onPackageRemoved Skips Package Visibility Check
- **File:** Same, ~line 2454
- **Issue:** Package removal callbacks don't call `isPackageVisibleToListener()` unlike add/modify.

### TextServicesManagerService

#### TSM-2 [LOW-MED] — No Rate Limiting on Session Creation
- **Issue:** `getSpellCheckerService()` creates sessions without per-UID rate limiting.

### NotificationManagerService (Listener)

#### NLS-3 [LOW-MED] — snoozeNotification Accepts Infinite Duration
- **File:** `NotificationManagerService.java`, ~line 5512
- **Issue:** No upper bound on snooze duration. Notification listener can permanently suppress notifications with `Long.MAX_VALUE`.

---

## Batch 3: System Apps

### Settings App

#### SET-1 [HIGH] — SubSettings Universal Fragment Injection (V-171)
- **File:** `packages/apps/Settings/src/com/android/settings/SubSettings.java`
- **Method:** `isValidFragment()` — returns `true` for ALL classes
- **Issue:** Root cause of V-49/V-50 pattern. SettingsActivity validates fragments against allowlist, but SubSettings bypasses completely. SearchResultTrampoline routes to SubSettings.
- **Impact:** Load arbitrary fragments with attacker arguments: `ChooseLockPasswordFragment`, `MainClearConfirm`, etc.
- **Attack:** Intent → SearchResultTrampoline → SubSettings → any fragment class

#### SET-2 [MED-HIGH] — Deep Link Intent URI Injection (V-173)
- **File:** `packages/apps/Settings/src/com/android/settings/search/SearchResultTrampoline.java`, lines 80-92
- **Issue:** Parses `EXTRA_SETTINGS_EMBEDDED_DEEP_LINK_INTENT_URI` via `Intent.parseUri()` without validation equivalent to `SettingsHomepageActivity.launchDeepLinkIntentToRight()`.
- **Impact:** Launch non-exported Settings internal components.

#### SET-3 [LOW-MED] — Cross-Package Resource Loading via Title Extra
- **File:** `SettingsActivity.java`, lines 548-562
- **Issue:** `EXTRA_SHOW_FRAGMENT_TITLE_RES_PACKAGE_NAME` creates arbitrary package contexts.

### SystemUI

#### SUI-1 [MED] — SystemUIService Exported Without Permission (V-175)
- **File:** `packages/SystemUI/AndroidManifest.xml`, line 421-423
- **Issue:** `exported="true"`, no `android:permission`. Source has TODO comment. Repeated startService causes re-init.

#### SUI-2 [MED] — WalletContextualLocationsService Exported
- **Issue:** Exported without permission. Payment context data.

#### SUI-3 [MED] — MediaProjectionPermissionActivity Exported
- **Issue:** Exported, `showForAllUsers="true"`. Any app triggers screen recording dialog.

### Launcher3

#### LAUNCH-1 [MED] — GridCustomizationsProvider No Permission (V-174)
- **File:** `packages/apps/Launcher3/AndroidManifest-common.xml`
- **Issue:** `exported="true"`, no read/write permission. Manifest TODO: "Add proper permissions." `query()` and `update()` unprotected. Any app can change home screen grid layout.

### Gallery2

#### GAL-1 [MED-HIGH] — FLAG_DISMISS_KEYGUARD Via Intent Extra (V-172)
- **File:** `packages/apps/Gallery2/src/com/android/gallery3d/app/GalleryActivity.java`, lines 52, 65
- **Issue:** Reads `KEY_DISMISS_KEYGUARD` boolean from intent, sets `FLAG_DISMISS_KEYGUARD` on window. Exported `ACTION_VIEW` activity.
- **Impact:** Lock screen dismissal from any app. Deprecated API 26 but targets SDK 28. May not be on Pixel 10.

#### GAL-2 [MED] — CropActivity FLAG_SHOW_WHEN_LOCKED
- **File:** `CropActivity.java`, line 100
- **Issue:** Intent extra controls `FLAG_SHOW_WHEN_LOCKED`. Activity renders over lock screen.

### DocumentsUI

#### DOC-1 [LOW-MED] — ArchivesProvider Weak Document ID Validation
- **Issue:** Archive URI embedded in documentId could reference cross-user providers.

### Contacts

#### CONT-1 [LOW-MED] — ImportVCardActivity No Size Limits
- **Issue:** Processes external vCard URIs without size limits. Storage/memory exhaustion.

---

## Cumulative Coverage (Rounds 1-6)

### Framework Services Audited: 34+
ActivityManagerService, ActivityTaskManagerService, PackageManagerService, PackageInstallerService, NotificationManagerService, AppOpsService, AccessibilityManagerService, SettingsProvider, BluetoothPbapService, BluetoothMapService, SmsProvider, MmsProvider, TelephonyProvider, MediaProvider, DevicePolicyManagerService, InputMethodManagerService, DreamManagerService, ClipboardService, WallpaperManagerService, MediaProjectionManagerService, AccountManagerService, JobSchedulerService, AlarmManagerService, ContentService, UsageStatsService, DeviceIdleController, InputManagerService, WindowManagerService, UriGrantsManagerService, StorageManagerService, TelecomServiceImpl, ConnectivityService, UserManagerService, BackupManagerService, PrintManagerService, NetworkPolicyManagerService, LauncherAppsService, CrossProfileAppsServiceImpl, MediaSessionService, DisplayManagerService, TextServicesManagerService

### System Apps Audited: 7
Settings, SystemUI, Launcher3, Gallery2, DocumentsUI, Contacts, Dialer (partial)

### Remaining Unaudited
1. SensorService (native)
2. CameraService (native)
3. RoleManagerService (full — Permission mainline module)
4. CrossProfileIntentFilterManager
5. HealthConnectService
6. NearbyManager
7. VirtualDeviceManager
8. GameManagerService
9. UwbServiceImpl
10. WifiServiceImpl (deeper audit)
