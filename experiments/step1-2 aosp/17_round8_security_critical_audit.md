# Round 8 Deep Audit — Security-Critical Components + Newer APIs

**Date:** 2026-04-29
**Scope:** Batch 1 (LockSettings, DPMS, PermissionManager, KeyStore, PMS Install) + Batch 2 (CredentialManager, GrammaticalInflection, OnDevicePersonalization, BackgroundInstallControl, ScreenRecording, SafetyCenter)
**Method:** Line-by-line source review with cross-reference verification
**Target:** Pixel 10 (frankel), Android 16, CP1A.260405.005, patch 2026-04-05

---

## Executive Summary

| Batch | Components | Findings | Top Severity |
|-------|-----------|----------|-------------|
| Batch 1: Security-critical | 5 | 7 | HIGH (PERMS-1) |
| Batch 2: Newer APIs | 6 | 11 | HIGH (CRED-1, BIC-1) |
| **TOTAL** | **11** | **18** | **HIGH** |

### Top 5 Findings This Round

| ID | Severity | Service | Issue |
|----|----------|---------|-------|
| V-190 (PERMS-1) | HIGH | PermissionManager | **INVERTED ternary** — non-system can modify SYSTEM_FIXED flags |
| V-184 (CRED-1) | HIGH | CredentialManager | getCandidateCredentials missing origin/allowedProviders perm |
| V-185 (BIC-1) | HIGH | BackgroundInstallControl | registerCallback zero perm — monitors ALL installs |
| V-186 (GI-1) | MED | GrammaticalInflection | Modify any app's config without ownership check |
| V-189 (CRED-3) | MED | CredentialManager | Cross-user provider enumeration |

---

## Batch 1: Security-Critical Components

### PermissionManagerServiceImpl

#### PERMS-1 [HIGH] — Inverted SYSTEM_FIXED Flag Protection (V-190)
- **File:** `PermissionManagerServiceImpl.java`, lines 902-906
- **Method:** `updatePermissionFlagsForAllApps()`
- **Bug:** Ternary condition inverted. Comment says "Only the system can change system fixed flags" but code:
  - `callingUid != SYSTEM_UID` → keeps FLAG_PERMISSION_SYSTEM_FIXED (allows non-system!)
  - `callingUid == SYSTEM_UID` → strips FLAG_PERMISSION_SYSTEM_FIXED (blocks system!)
- **Compare:** Correct implementation at lines 807-809 in `updatePermissionFlagsInternal()` strips for non-system
- **Impact:** Privileged app with GRANT_RUNTIME_PERMISSIONS can modify SYSTEM_FIXED flags for ALL packages
- **Note:** Clear code bug, not design choice. Requires signature-level permission.

### LockSettingsService

#### KG-1 [MED] — Shell require-strong-auth Without Credential
- **File:** `LockSettingsShellCommand.java`, lines 100-103, 283-299
- **Issue:** Shell command triggers USER_ALL lockdown without credential verification. clearCallingIdentity runs as system_server.
- **Impact:** ADB shell forces all users into lockdown (requires PIN re-entry, disables biometric)

#### KG-2 [LOW-MED → NEEDS_REVIEW] — Remote Lockscreen Validation No Permission (V-191)
- **File:** `LockSettingsService.java`, lines 2857-2869
- **Issue:** startRemoteLockscreenValidation/validateRemoteLockscreen delegate to RecoverableKeyStoreManager without permission check. AIDL has no @EnforcePermission.
- **Note:** Security may reside in RecoverableKeyStoreManager (RECOVER_KEYSTORE). Needs deeper verification.

### DevicePolicyManagerService

#### DPMS-D-1 [LOW] — wipeDataWithReason Silent Failure
- **Issue:** Silently returns when feature missing and no MASTER_CLEAR. Not exploitable but confusing.

### PackageManagerService (Install/Verify)

#### PMS-I-1 [LOW-MED] — Negative Verification ID Permission Skip (V-192)
- **File:** `PackageManagerService.java`, lines 6499-6529
- **Issue:** PACKAGE_VERIFICATION_AGENT permission skipped for negative verificationId. UID check still applies.

### AndroidKeyStore

#### KC-1 [INFORMATIONAL] — Cross-App Isolation in Native Daemon
- **Issue:** Key isolation enforced by native keystore2 daemon, not Java layer. Correct architectural approach.

---

## Batch 2: Newer APIs (Android 14-16)

### CredentialManager (New in Android 14)

#### CRED-1 [HIGH] — getCandidateCredentials Missing Permission Checks (V-184)
- **File:** `CredentialManagerService.java`, lines 486-540
- **Issue:** Missing BOTH origin and allowedProviders permission checks that parallel methods enforce:
  - `executeGetCredential` → validates origin (CREDENTIAL_MANAGER_SET_ORIGIN) + providers
  - `executePrepareGetCredential` → explicitly enforces both permissions
  - `getCandidateCredentials` → **NEITHER check performed**
- **Verified:** No deeper check in GetCandidateRequestSession/ProviderGetSession
- **Impact:** Spoof origin (e.g., `https://bank.com`) to enumerate credential types

#### CRED-2 [MED] — CallingAppInfo Null SigningInfo on NameNotFoundException
- **Issue:** Race condition: package uninstalled between enforceCallingPackage and getPackageInfoAsUser → null signingInfo passed to providers

#### CRED-3 [MED] — Cross-User Provider Enumeration (V-189)
- **Issue:** getCredentialProviderServices lacks handleIncomingUser, unlike setEnabledProviders

### BackgroundInstallControlService (Newer)

#### BIC-1 [HIGH] — registerBackgroundInstallCallback Zero Permission (V-185)
- **File:** `BackgroundInstallControlService.java`, lines 196-198
- **Issue:** Zero permission on register/unregister. Compare: getBackgroundInstalledPackages requires GET_BACKGROUND_INSTALLED_PACKAGES.
- **Impact:** Real-time monitoring of ALL installs/uninstalls across all users

#### BIC-2 [MED] — Feature Flag Gates Permission Check
- **Issue:** getBackgroundInstalledPackages permission check behind Flags.bicClient()

### GrammaticalInflectionService (Android 14)

#### GI-1 [MED] — Cross-App Config Modification (V-186)
- **File:** `GrammaticalInflectionService.java`, lines 239-263
- **Issue:** No package ownership verification. Any app modifies any app's grammatical gender config, triggering activity restart.

### OnDevicePersonalizationManager

#### ODP-1 [MED] — logApiCallStats No Auth (V-187)
- **Issue:** No kill switch, no device check, no package verification, no enrollment check, no rate limit.

### SafetyCenterManager

#### SAFE-2 [MED] — Test Methods in Production (V-188)
- **Issue:** clearAllSafetySourceDataForTests/setSafetyCenterConfigForTests available in production with MANAGE_SAFETY_CENTER.

#### SAFE-1 [MED] — setSafetySourceData Silent Failure
- **Issue:** enforcePackage returns false for invalid packages instead of throwing.

### ScreenRecordingCallbackController

#### SC-1 [MED] — No Permission on Recording Detection Registration
- **Issue:** Any app can register IScreenRecordingCallback. Properly scoped to own UID but enables screen recording evasion.

---

## Cumulative Audit Statistics (All Rounds)

### Total Status Files
```
67 total
├── 16 HIGH
├── 15 MEDIUM-HIGH
├── 27 MEDIUM
├──  4 LOW
├──  2 NEEDS_DEEPER_REVIEW
├──  1 FALSE_POSITIVE
└──  2 LOW-MEDIUM
```

### Confirmed HIGH Findings (Cross-Verified)
1. **V-167** — DisplayManagerService overrideHdrTypes() zero permission [CONFIRMED]
2. **V-154** — AppOps Proxy Attribution forgery [CONFIRMED on device]
3. **V-06** — SafeActivityOptions FREEFORM CVE-2025-48546 incomplete fix [CONFIRMED on device]

### HIGH Findings Pending Verification
4. **V-190** — PermissionManager INVERTED SYSTEM_FIXED ternary
5. **V-184** — CredentialManager getCandidateCredentials missing permission
6. **V-185** — BackgroundInstallControl registerCallback zero permission

### Services/Components Audited (Rounds 1-8): 57+
Framework services (45+): AMS, ATMS, PMS, NMS, AppOps, A11y, SettingsProvider, Bluetooth(3), SMS/MMS/Telephony, MediaProvider, DPMS, IME, Dream, Clipboard, Wallpaper, MediaProjection, AccountManager, JobScheduler, AlarmManager, ContentService, UsageStats, DeviceIdle, InputManager, WMS, UriGrants, StorageManager, Telecom, Connectivity, UserManager, Backup, Print, NetworkPolicy, LauncherApps, CrossProfileApps, MediaSession, DisplayManager, TextServices, NMS(Listener), LocationManager, AudioService, PowerManager, ShortcutService, CompanionDeviceManager, VirtualDeviceManager, HealthConnect, CredentialManager, GrammaticalInflection, ODP, BackgroundInstallControl, ScreenRecording, SafetyCenter, PermissionManager, LockSettings, KeyStore, WiFi

System Apps (7): Settings, SystemUI, Launcher3, Gallery2, DocumentsUI, Contacts, Dialer
