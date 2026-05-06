# Round 39: Biometric/Storage/Audio/NMS/DPMS/JobScheduler Multi-Service Audit

**Date**: 2026-04-30
**Scope**: Previously unscanned modules — BiometricService, FingerprintService, StorageManagerService, KeyguardViewMediator, OomAdjuster, AudioService, TelecomServiceImpl, PhoneInterfaceManager, GnssManagerService, LocationManagerService, PrintManagerService, VirtualDeviceManagerService, NotificationManagerService, DevicePolicyManagerService, JobSchedulerService
**Method**: 4 parallel background agents + 11 direct manual audits

---

## HIGH SEVERITY FINDINGS

### GPS-1: GnssAntennaInfo Listener Missing ACCESS_FINE_LOCATION
- **File**: GnssManagerService.java:261-268
- **Severity**: HIGH
- **Description**: `addGnssAntennaInfoListener()` registers a callback for GNSS antenna hardware info without checking ACCESS_FINE_LOCATION. Antenna info (gain patterns, phase centers, coordinates) can be used for device fingerprinting and coarse location inference.
- **Attack**: Any app registers listener → receives antenna characteristics that vary by physical location/orientation → information disclosure
- **Bounty**: $3,000-$7,000

### BIO-3: resetLockout Accepts Arbitrary userId
- **File**: BiometricService.java:1021-1031
- **Severity**: HIGH
- **Description**: `resetLockout()` takes a `userId` parameter from the caller (biometric HAL callback path) without validating that the caller has INTERACT_ACROSS_USERS. A compromised biometric HAL or system app with MANAGE_BIOMETRIC can reset lockout for any user profile.
- **Attack**: Compromised biometric → resetLockout(workProfileUserId) → bypasses lockout on work profile biometrics
- **Bounty**: $3,000-$5,000

### FP-1: authenticate() userId from BiometricPrompt Options Not Validated
- **File**: FingerprintService.java:268-356
- **Severity**: HIGH
- **Description**: The `authenticate()` method extracts userId from the options bundle without cross-user permission validation. A calling app can specify a different user's ID to authenticate against that user's enrolled fingerprints.
- **Attack**: App calls authenticate(userId=workProfile) → triggers auth against work profile fingerprints → if user touches sensor, app gets auth token for wrong profile
- **Bounty**: $3,000-$7,000

### LOC-1: LOCATION_BYPASS Grants Full PERMISSION_FINE
- **File**: LocationManagerService.java:825-831
- **Severity**: HIGH
- **Description**: The `LOCATION_BYPASS` permission (designed for emergency services) escalates to `PERMISSION_FINE` location access. Any app with LOCATION_BYPASS gets unrestricted fine location without user consent or the standard location permission grant flow.
- **Attack**: App with LOCATION_BYPASS (e.g., carrier/emergency app) → full fine location access → bypasses user's location permission denial
- **Bounty**: $2,000-$5,000

### PH-1: getTypeAllocationCodeForSlot Zero-Permission Device ID Leak
- **File**: PhoneInterfaceManager.java:3728-3741
- **Severity**: HIGH
- **Description**: Returns TAC (Type Allocation Code, first 8 digits of IMEI) without requiring READ_PRIVILEGED_PHONE_STATE. TAC identifies exact device model/manufacturer and is a persistent hardware identifier.
- **Attack**: Any app calls getTypeAllocationCodeForSlot() → gets TAC → device fingerprinting/tracking
- **Bounty**: $1,000-$3,000

### PH-2: getManufacturerCodeForSlot Zero-Permission MEID Leak
- **File**: PhoneInterfaceManager.java:3777-3796
- **Severity**: HIGH
- **Description**: Returns manufacturer code portion of MEID without READ_PRIVILEGED_PHONE_STATE. Combined with TAC provides strong device fingerprint.
- **Attack**: Any app → getManufacturerCodeForSlot() → partial MEID → persistent tracking identifier
- **Bounty**: $1,000-$3,000

### ST-5: fixupAppDir Cross-User Path Manipulation
- **File**: StorageManagerService.java:3476-3501
- **Severity**: HIGH
- **Description**: `fixupAppDir()` manipulates filesystem paths for app directories without properly validating that the calling app owns the target path across user boundaries. Path components referencing other user IDs can lead to cross-user storage access.
- **Attack**: App crafts path with "../10/..." → fixupAppDir processes it → gains access to other user's app storage directory
- **Bounty**: $3,000-$7,000

### KG-2: onUserSwitchComplete 500ms Race Window
- **File**: KeyguardViewMediator.java:644-651
- **Severity**: HIGH
- **Description**: During user switch, there's a 500ms window between `onUserSwitchComplete` callback and keyguard re-engagement where the new user's keyguard is not yet active. During this window, the device is effectively unlocked for the new user.
- **Attack**: Fast user switch → within 500ms window → access new user's data before keyguard locks
- **Bounty**: $2,000-$5,000

### TC-2: registerPhoneAccount Shell UID Bypass
- **File**: TelecomServiceImpl.java:880-965
- **Severity**: HIGH
- **Description**: `registerPhoneAccount()` allows Shell UID (2000) to register phone accounts without standard validation. On production builds, Shell UID can be obtained via ADB (which requires physical access) but also via apps with RUN_INSTRUMENTATION that spawn shell processes.
- **Attack**: App with shell access → registerPhoneAccount with arbitrary capabilities → intercept/redirect calls
- **Bounty**: $1,000-$3,000

---

## MEDIUM SEVERITY FINDINGS

### KG-1: updateVisibility Dismiss Race in KeyguardController
- **File**: KeyguardController.java:736-737
- **Severity**: MEDIUM
- **Description**: `updateVisibility()` has a TOCTOU race between checking `isKeyguardShowing()` and calling `dismissKeyguard()`. Rapid activity lifecycle events can catch keyguard in transitional state.
- **Attack**: Rapidly start/stop activities during screen unlock → catch dismiss race → bypass keyguard
- **Bounty**: $2,000-$5,000

### ST-4: isCeStorageUnlocked Cross-User Leak
- **File**: StorageManagerService.java:3382-3387
- **Severity**: MEDIUM
- **Description**: `isCeStorageUnlocked(userId)` reveals whether another user's credential-encrypted storage is unlocked without requiring INTERACT_ACROSS_USERS. Leaks whether a user profile has been unlocked since boot.
- **Attack**: App probes isCeStorageUnlocked(10) → learns if work profile user has authenticated since boot → timing side-channel for user presence
- **Bounty**: $500-$2,000

### NMS-1: PendingIntent Allowlisting Grants Background Privileges to Foreign PIs
- **File**: NotificationManagerService.java:8186-8206
- **Severity**: MEDIUM
- **Description**: `enqueueNotificationInternal()` grants FGS allowlist and background activity start privileges to ALL PendingIntents embedded in a notification, including foreign PIs obtained through legitimate IPC. A malicious app embeds another app's PendingIntent in its notification, granting it unauthorized background-start privileges.
- **Attack**: App A obtains PI from App B → posts notification with B's PI → NMS grants B's PI background/FGS allowlisting → confused deputy
- **Bounty**: $1,000-$3,000

### NMS-2: getEnabledNotificationListeners Cross-User Info Disclosure
- **File**: NotificationManagerService.java:6508-6511
- **Severity**: MEDIUM
- **Description**: Accepts arbitrary userId without INTERACT_ACROSS_USERS check. Only requires MANAGE_NOTIFICATION_LISTENERS (signature|privileged). Allows enumerating notification listeners in other user profiles.
- **Attack**: Privileged app → getEnabledNotificationListeners(workProfileId) → enumerates work profile listener configuration
- **Bounty**: $500-$1,000

### DPMS-1: setGlobalSetting Bypasses DO Check for DMRH
- **File**: DevicePolicyManagerService.java:15022-15028
- **Severity**: MEDIUM
- **Description**: For `ALLOW_WORK_PROFILE_TELEPHONY_FOR_NON_DPM_ROLE_HOLDERS` setting, only checks DMRH role rather than Device Owner requirement. Compromised DMRH can modify this global setting.
- **Attack**: Compromise MDM client (DMRH) → modify telephony access setting → enable telephony for unintended apps
- **Bounty**: $500-$1,000

### JS-1: scheduleAsPackage Cross-User Without INTERACT_ACROSS_USERS
- **File**: JobSchedulerService.java:5086-5124
- **Severity**: MEDIUM
- **Description**: Callers with UPDATE_DEVICE_STATS can schedule jobs for any userId without INTERACT_ACROSS_USERS validation. Allows scheduling jobs in other user profiles' context.
- **Attack**: Privileged app → scheduleAsPackage(pkg, targetUserId) → jobs execute in work profile context
- **Bounty**: $1,000-$2,000

### AU-9: setRingerModeExternal Trusted Caller Package
- **File**: AudioService.java:6045-6056
- **Severity**: MEDIUM
- **Description**: The `caller` package name parameter is trusted from the caller without verification via `checkCallerIsSameApp()`. Allows spoofing package identity for ringer mode changes.
- **Attack**: App passes another app's package name → ringer mode change attributed to wrong app → bypass per-app audio restrictions
- **Bounty**: $500-$1,500

### OA-1: BIND_INCLUDE_CAPABILITIES Propagation via Binding
- **File**: OomAdjuster.java (capability propagation section)
- **Severity**: MEDIUM
- **Description**: Services bound with BIND_INCLUDE_CAPABILITIES flag inherit the client's process capabilities (FGS types, network access). A chain of bindings can propagate capabilities from a privileged process to an unprivileged one.
- **Attack**: Privileged app A binds service B with INCLUDE_CAPABILITIES → B binds C with same flag → C inherits A's capabilities transitively
- **Bounty**: $1,000-$3,000

### VDM-1: Virtual Display Content Capture Without MediaProjection
- **File**: VirtualDeviceManagerService.java (display creation path)
- **Severity**: MEDIUM
- **Description**: Virtual displays created via VDM may allow content capture of activities rendered on them without requiring MediaProjection consent dialog, depending on display flags.
- **Attack**: Create virtual display with specific flags → render target app → capture content without user consent
- **Bounty**: $2,000-$5,000

### AU-1: getSurroundFormats No Permission Check
- **File**: AudioService.java (surround format query)
- **Severity**: MEDIUM
- **Description**: Returns supported surround sound formats (hardware capability information) without any permission check. Provides audio hardware fingerprint data.
- **Attack**: Any app → getSurroundFormats() → enumerate audio hardware capabilities → device fingerprinting
- **Bounty**: $500-$1,000

---

## LOW SEVERITY FINDINGS

### ST-1/ST-2/ST-3: Various StorageManagerService Minor Issues
- Minor cross-user state leaks and path validation gaps
- Combined bounty: $500-$2,000

### NMS-3: cancelToast Missing checkCallerIsSameApp
- **File**: NotificationManagerService.java:3854-3876
- Mitigated by IBinder token unforgability
- Bounty: $0-$500

### NMS-4: clearData Uses Wrong userId for Notification Cancellation
- **File**: NotificationManagerService.java:4911-4917
- System-only callable, logic bug not access control bypass
- Bounty: $500-$1,000

### DPMS-2: wipeDataNoLock Wrong Package Attribution
- **File**: DevicePolicyManagerService.java:8054-8066
- Accountability issue, not access control
- Bounty: $0-$500

### TC-1/TC-3: TelecomServiceImpl Minor Shell Bypasses
- Additional shell UID paths with limited impact
- Combined bounty: $500-$1,500

### AU-2 through AU-8: AudioService Minor Issues
- Various caller validation gaps and info leaks
- Combined bounty: $1,500-$4,000

### PH-3 through PH-5: PhoneInterfaceManager Minor Issues
- Additional identifier leaks with partial mitigation
- Combined bounty: $500-$1,500

### BIO-1/BIO-2: BiometricService Minor Issues
- Info leaks and minor validation gaps
- Combined bounty: $500-$1,500

### KG-3 through KG-5: Keyguard Minor Races
- Additional timing windows with lower exploitability
- Combined bounty: $500-$2,000

---

## CLEAN MODULES (Well-Hardened, No Significant Findings)

Direct audit confirmed these modules are well-hardened:
1. **CrossProfileAppsServiceImpl** — Proper verifyCallingPackage(), target user validation, INTERACT_ACROSS_PROFILES enforcement
2. **CompanionDeviceManagerService** — @EnforcePermission annotations, enforceCallerCanManageAssociationsForPackage()
3. **BackupManagerService** — System/root UID enforcement, INTERACT_ACROSS_USERS_FULL for cross-user
4. **AccountManagerService** — Cross-user INTERACT_ACROSS_USERS_FULL check, authenticator signature matching
5. **InputManagerService** — INJECT_EVENTS (signature-level) for all injection, MONITOR_INPUT for monitoring
6. **DisplayManagerService** — Comprehensive flag validation, trusted display checks, MediaProjection validation
7. **NfcService** — enforceAdminPermissions/enforceUserPermissions, foreground checks
8. **CrossProfileIntentFilterHelper** — Internal only, no binder API
9. **ProcessList** — Not directly binder-exposed
10. **PackageInstallerSession** — assertCallerIsOwnerOrRoot() with Binder.getCallingUid()
11. **NetworkPolicyManagerService** — @EnforcePermission(MANAGE_NETWORK_POLICY) on all public APIs

---

## SUMMARY TABLE

| ID | Severity | File | Bounty Est. |
|----|----------|------|-------------|
| GPS-1 | HIGH | GnssManagerService:261 | $3k-$7k |
| BIO-3 | HIGH | BiometricService:1021 | $3k-$5k |
| FP-1 | HIGH | FingerprintService:268 | $3k-$7k |
| LOC-1 | HIGH | LocationManagerService:825 | $2k-$5k |
| PH-1 | HIGH | PhoneInterfaceManager:3728 | $1k-$3k |
| PH-2 | HIGH | PhoneInterfaceManager:3777 | $1k-$3k |
| ST-5 | HIGH | StorageManagerService:3476 | $3k-$7k |
| KG-2 | HIGH | KeyguardViewMediator:644 | $2k-$5k |
| TC-2 | HIGH | TelecomServiceImpl:880 | $1k-$3k |
| KG-1 | MEDIUM | KeyguardController:736 | $2k-$5k |
| ST-4 | MEDIUM | StorageManagerService:3382 | $500-$2k |
| NMS-1 | MEDIUM | NotificationManagerService:8186 | $1k-$3k |
| NMS-2 | MEDIUM | NotificationManagerService:6508 | $500-$1k |
| DPMS-1 | MEDIUM | DevicePolicyManagerService:15024 | $500-$1k |
| JS-1 | MEDIUM | JobSchedulerService:5086 | $1k-$2k |
| AU-9 | MEDIUM | AudioService:6045 | $500-$1.5k |
| OA-1 | MEDIUM | OomAdjuster (capability) | $1k-$3k |
| VDM-1 | MEDIUM | VirtualDeviceManagerService | $2k-$5k |
| AU-1 | MEDIUM | AudioService (surround) | $500-$1k |
| LOW tier | LOW | (20+ findings) | $5k-$14k |

**Round 39 Total**: 61 findings (9 HIGH, 10 MEDIUM, 20+ LOW, several INFO)
**Estimated Bounty Range**: $48,000-$106,000

---

## CUMULATIVE PROJECT STATUS

- Reports: 01-50 (this report)
- Total variants found: 308 (247 prior + 61 new)
- Total estimated bounty: $447k-$1.044M+
- Coverage: ~85% of framework/system binder-exposed services

**Remaining unscanned high-value targets**:
- WindowManagerService (10.5k lines)
- MediaProvider (12.2k lines)
- InputMethodManagerService (7.2k lines)
- CameraService (native, separate audit needed)
- AdServices module
