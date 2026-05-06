# Report 38: Round 27 — EoP: Accessibility Service Bypass, DeviceIdle Allowlist, LauncherApps

**Date**: 2026-04-30  
**Scope**: AccessibilityManagerService, DeviceIdleController, LauncherAppsService, JobSchedulerService  
**Method**: Deep background agents + manual source verification  
**Previous**: Reports 01-37, ~376 variants

---

## Part A: AccessibilityManagerService (4 findings)

### V-376: Backup/Restore Silently Enables Accessibility Services Without Warning Dialog [HIGH/EoP]

**File**: `services/accessibility/java/com/android/server/accessibility/AccessibilityManagerService.java` (lines 2230-2244)

**Issue**: When `ACTION_SETTING_RESTORED` is processed for `ENABLED_ACCESSIBILITY_SERVICES`, the restore handler directly merges old and new component names and enables them via `onUserStateChangedLocked()` — completely bypassing the mandatory 2-step Settings confirmation dialog:

```java
void restoreEnabledAccessibilityServicesLocked(String oldSetting, String newSetting, ...) {
    readComponentNamesFromStringLocked(oldSetting, mTempComponentNameSet, false);
    readComponentNamesFromStringLocked(newSetting, mTempComponentNameSet, true);
    userState.mEnabledServices.clear();
    userState.mEnabledServices.addAll(mTempComponentNameSet);
    persistComponentNamesToSettingLocked(...);
    onUserStateChangedLocked(userState);  // Directly enables & binds the service!
}
```

While `updateServicesLocked` does check `isAccessibilityTargetAllowed` (Enhanced Confirmation Mode), this only blocks sideloaded apps. Play Store-installed apps pass ECM and are silently enabled.

**Attack**:
1. Attacker publishes malicious accessibility service on Play Store (passes review as legitimate tool)
2. Crafts backup data including the service in `ENABLED_ACCESSIBILITY_SERVICES`
3. User restores from backup (new device setup, cloud backup restore)
4. Accessibility service is enabled without the confirmation dialog
5. Service can now inject input, read all screen content, perform gestures

**Permission**: ZERO (requires user to restore from backup containing the malicious entry)  
**Impact**: Full accessibility service privileges without user consent dialog — input injection, screen reading, gesture injection  
**Bounty**: $5,000-$15,000

---

### V-377: Accessibility Shortcut Restore + Volume Key = Service Enable Without Warning [HIGH/EoP]

**File**: `AccessibilityManagerService.java` (lines 2256-2302, 4308-4361)

**Issue**: A two-part bypass chain:

**Part 1** — `restoreShortcutTargets` (line 2256-2302) merges restored shortcut targets without checking `isAccessibilityServiceWarningRequired` or `isAccessibilityTargetAllowed`:
```java
readColonDelimitedStringToSet(newValue, str -> str, mergedTargets, true);
userState.updateShortcutTargetsLocked(mergedTargets, shortcutType);
persistColonDelimitedSetToSettingLocked(...);
```

**Part 2** — `performAccessibilityShortcutTargetService` (line 4308-4361) enables services via the HARDWARE shortcut without a warning dialog check:
```java
if ((targetSdk <= Build.VERSION_CODES.Q && shortcutType == HARDWARE) || ...) {
    enableAccessibilityServiceLocked(assignedTarget, mCurrentUserId);
    // NO warning dialog! NO isAccessibilityServiceWarningRequired check!
}
```

**Part 3** — Circular trust: `isAccessibilityServiceWarningRequired` (line 5191-5196) returns `false` if the service is already assigned to a shortcut.

**Attack chain**:
1. Backup restore puts attacker's service into shortcut target list (no validation)
2. User accidentally presses volume shortcut (hardware accessibility shortcut)
3. `isAccessibilityServiceWarningRequired` returns false (service is in shortcut list)
4. Service is directly enabled via `enableAccessibilityServiceLocked` — no dialog
5. Full accessibility privileges granted

**Permission**: ZERO (requires backup restore + user accidentally pressing volume shortcut)  
**Impact**: Full accessibility service privileges via backup+volume key chain  
**Bounty**: $5,000-$10,000

---

### V-378: performGlobalAction(TAKE_SCREENSHOT) Bypasses CAPABILITY_CAN_TAKE_SCREENSHOT Check [MEDIUM/EoP]

**File**: `services/accessibility/java/com/android/server/accessibility/AbstractAccessibilityServiceConnection.java` (lines 1110-1128)

**Issue**: `performGlobalAction(GLOBAL_ACTION_TAKE_SCREENSHOT)` has NO capability check — any bound accessibility service can call it regardless of declared capabilities:

```java
public boolean performGlobalAction(int action) {
    // Only checks hasRightsToCurrentUserLocked() - no capability check!
    return mSystemActionPerformer.performSystemAction(action);
}
```

In contrast, the dedicated `takeScreenshot()` API properly requires `CAPABILITY_CAN_TAKE_SCREENSHOT`:
```java
public void takeScreenshot(int displayId, RemoteCallback callback) {
    if (!mSecurityPolicy.canTakeScreenshotLocked(this)) { // Checks capability!
        throw new SecurityException(...);
    }
}
```

**Attack**: A minimal accessibility service declared with ZERO capabilities can take screenshots via `performGlobalAction(9)`, bypassing the capability restriction that should require explicit user approval for screenshot capability.

Additionally available without capability: `GLOBAL_ACTION_LOCK_SCREEN`, `GLOBAL_ACTION_POWER_DIALOG`, `GLOBAL_ACTION_DISMISS_NOTIFICATION_SHADE`.

**Permission**: Must be an enabled accessibility service (any capabilities)  
**Impact**: Screenshot capture without CAPABILITY_CAN_TAKE_SCREENSHOT  
**Bounty**: $2,000-$5,000

---

### V-379: Dynamic FLAG_RETRIEVE_INTERACTIVE_WINDOWS Escalation via setServiceInfo [MEDIUM/EoP]

**File**: `AbstractAccessibilityServiceConnection.java` (lines 467-468, 522-554)

**Issue**: `setServiceInfo()` allows a bound accessibility service to dynamically add `FLAG_RETRIEVE_INTERACTIVE_WINDOWS` after being enabled. While `capabilities` are immutable (set from XML manifest), `flags` are fully mutable:

```java
// In updateDynamicallyConfigurableProperties:
flags = other.flags;  // Includes FLAG_RETRIEVE_INTERACTIVE_WINDOWS!
mMotionEventSources = other.mMotionEventSources;
```

```java
// After setServiceInfo:
mRetrieveInteractiveWindows = (info.flags
    & AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS) != 0;
```

**Attack**: Service is approved by user without interactive window access declared in manifest. After binding, calls `setServiceInfo` to add `FLAG_RETRIEVE_INTERACTIVE_WINDOWS`. Now can enumerate ALL windows on screen including behind-lockscreen content.

**Permission**: Must be an enabled accessibility service with CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT  
**Impact**: Full window enumeration including lockscreen content, escalated beyond declared scope  
**Bounty**: $1,000-$3,000

---

## Part B: DeviceIdleController (2 findings)

### V-380: Cross-Profile Temp Allowlist Propagation by AppId — Work Profile Doze Bypass Leaks to Personal [MEDIUM/EoP]

**File**: `services/core/java/com/android/server/DeviceIdleController.java` (line 3276)

**Issue**: The temp power save allowlist is indexed by **appId** (not full UID):

```java
int appId = UserHandle.getAppId(uid);
mTempWhitelistAppIdEndTimes.put(appId, entry);
```

When a package is temp-allowlisted for a specific user profile (e.g., work profile via push notification), the Doze exemption applies to that **appId across ALL user profiles**. The FGS start allowlist (AMS `mFgsStartTempAllowList`) correctly uses full UIDs, but the Doze network/wakelock bypass leaks across profiles.

**Attack**:
1. App has instances in both personal and work profiles
2. Work profile instance receives a push notification → gets temp-allowlisted
3. Personal profile instance gains Doze bypass (network access, wakelocks) without any legitimate trigger
4. Personal instance uses this to perform background network operations during Doze

**Permission**: Must have app installed in multiple profiles  
**Impact**: Doze bypass leaks across profile boundaries  
**Bounty**: $1,000-$3,000

---

### V-381: Zero-Permission Temp/Permanent Allowlist Enumeration [LOW-MEDIUM/Info Disclosure → EoP enabler]

**File**: `DeviceIdleController.java` (lines 2229-2242)

**Issue**: Four Binder methods return allowlist appId arrays with **ZERO permission checks**:
- `getAppIdWhitelistExceptIdle()` 
- `getAppIdWhitelist()`
- `getAppIdUserWhitelist()`
- `getAppIdTempWhitelist()`

Any app can enumerate which appIds have Doze exemptions, revealing:
- Which system apps are allowlisted (MDM, VPN, security tools)
- Which apps are currently temp-allowlisted (indicating recent notification/activity)
- Device configuration fingerprinting

**Permission**: ZERO  
**Impact**: Information disclosure enabling targeted attacks against privileged apps  
**Bounty**: $500-$1,000

---

## Part C: LauncherAppsService (2 findings)

### V-382: ROLE_HOME + ACCESS_HIDDEN_PROFILES Accesses Private Space via LauncherApps APIs [MEDIUM/EoP]

**File**: `services/core/java/com/android/server/pm/LauncherAppsService.java`

**Issue**: A malicious launcher holding ROLE_HOME + `ACCESS_HIDDEN_PROFILES` can access Private Space profiles via LauncherApps APIs. The `canAccessHiddenProfile()` check allows this:

```java
if (!mRoleManager.getRoleHoldersAsUser(RoleManager.ROLE_HOME, ...)
        .contains(callingPackage.getPackageName())) {
    return false;
}
return mContext.checkPermission(ACCESS_HIDDEN_PROFILES, ...) == PERMISSION_GRANTED;
```

The DeviceConfig flag `allow_3p_launchers_access_via_launcher_apps_apis` defaults to `true`, meaning third-party launchers with the appropriate permission can enumerate and interact with Private Space apps.

**Attack**:
1. Attacker publishes launcher app on Play Store with ROLE_HOME capability
2. User sets it as default launcher and grants `ACCESS_HIDDEN_PROFILES`
3. Launcher can enumerate Private Space app list, launch Private Space apps, read shortcut data
4. Combined with V-344/V-345, provides complete Private Space surveillance

**Permission**: ROLE_HOME + ACCESS_HIDDEN_PROFILES  
**Impact**: Full Private Space app enumeration and launch capability  
**Bounty**: $2,000-$5,000

---

### V-383: LauncherApps getActivityLaunchIntent Creates PendingIntent as Target App Identity [MEDIUM/EoP]

**File**: `LauncherAppsService.java`

**Issue**: `getActivityLaunchIntent` creates a `PendingIntent` with `FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT` using the **target app's package name and UID** (not the caller's):

```java
return injectCreatePendingIntent(0, intents,
    FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT, opts, packageName,
    mPackageManagerInternal.getPackageUid(packageName, ..., user.getIdentifier()));
```

This means a default launcher can obtain PendingIntents that execute as any installed app across accessible profiles. While `FLAG_IMMUTABLE` prevents intent modification, the PendingIntent itself executes with the target app's identity.

**Attack**:
1. Malicious default launcher calls `getActivityLaunchIntent` for system apps in work profile
2. Obtains PendingIntents that execute as those apps
3. Sends the PendingIntents (unchanged due to FLAG_IMMUTABLE) to trigger the app's launch activities
4. Combined with BAL allowlisting from notifications (V-338), these PIs execute from background

**Permission**: Default launcher role (ROLE_HOME) + `START_TASKS_FROM_RECENTS`  
**Impact**: Cross-user activity launch with target app identity via PendingIntent  
**Bounty**: $1,000-$3,000

---

## Part D: JobSchedulerService (1 finding)

### V-384: User-Initiated Job Data Saver Bypass with Normal Permission Only [LOW-MEDIUM/EoP]

**File**: `apex/jobscheduler/service/java/com/android/server/job/JobServiceContext.java` (lines 426-436)

**Issue**: User-initiated jobs (UIJs) receive `BIND_BYPASS_USER_NETWORK_RESTRICTIONS` and `BIND_BYPASS_POWER_NETWORK_RESTRICTIONS` when bound. Scheduling a UIJ requires only `RUN_USER_INITIATED_JOBS` which is a **normal** (auto-granted) permission. The only requirement is being in foreground at schedule time.

```java
// JobServiceContext.executeRunnableJob():
if (job.shouldTreatAsUserInitiatedJob()) {
    bindFlags |= Context.BIND_BYPASS_USER_NETWORK_RESTRICTIONS;  // Data Saver bypass!
    bindFlags |= Context.BIND_BYPASS_POWER_NETWORK_RESTRICTIONS;
    bindFlags |= Context.BIND_ALMOST_PERCEPTIBLE;
}
```

The job runs for up to 12 hours per execution, 24 hours cumulative. No re-check of foreground state at execution time.

**Attack**:
1. Malicious app briefly appears in foreground (transparent Activity)
2. Schedules UIJ with network constraint (mandatory for UIJs)
3. App goes to background
4. UIJ runs with Data Saver bypass for up to 12 hours
5. App performs background network operations despite Data Saver being active

**Permission**: ZERO beyond auto-granted `RUN_USER_INITIATED_JOBS`  
**Impact**: Data Saver bypass without explicit user consent for the specific bypass  
**Bounty**: $500-$1,500 (likely by-design, but permissive access model)

---

## Part E: Confirmed Secure (Audit Negative Results)

| Service | Result |
|---------|--------|
| JobSchedulerService cross-user | Properly scoped by UID; cancel/getPending use Binder.getCallingUid() |
| JobScheduler service binding | enforceValidJobRequest ensures target belongs to scheduling UID |
| DeviceIdleController exitIdle | Properly gated by DEVICE_POWER (signature) |
| DeviceIdleController permanent allowlist | addPowerSaveWhitelistApp requires DEVICE_POWER |
| AlarmManager temp allowlist | Proper rate limiting + BAL disabled for alarm path |
| Accessibility cross-user events | resolvedUserId == mCurrentUserId check prevents cross-user dispatch |
| VPN consent bypass | prepare() and establish() synchronized; no race condition |
| ClipboardService cross-user | Properly gated by ALLOW_FULL_ONLY |

---

## Round 27 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 2 | A11y backup enable (V-376), A11y shortcut chain (V-377) |
| MEDIUM | 4 | Screenshot bypass (V-378), A11y flag escalation (V-379), Private Space via launcher (V-382), LauncherApps PI identity (V-383) |
| MEDIUM | 1 | Cross-profile Doze bypass (V-380) |
| LOW-MEDIUM | 2 | Allowlist enumeration (V-381), UIJ Data Saver (V-384) |
| **Total** | **9** | |

**Estimated bounty this round**: $18,000 - $48,500

**Highest value findings**: V-376 and V-377 — the accessibility service enable-without-dialog via backup/restore chain. This defeats Android's most critical accessibility gate (the 2-step confirmation dialog) through a combination of backup restore + shortcut configuration + volume key trigger.

---

## Cumulative Project Statistics (Reports 01-38)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~376 | +9 | **~385** |
| HIGH/CRITICAL | ~53 | +2 | **~55** |
| Bounty estimate (low) | $726.9k | +$18k | **$744.9k** |
| Bounty estimate (high) | $1.794M | +$48.5k | **$1.842M** |

---

## V-376/V-377 Composite VRP Report Draft

### Title: Accessibility Service Enable Without User Warning Dialog via Backup Restore + Shortcut Volume Key Chain

### Summary
Android's backup/restore mechanism for accessibility settings bypasses the mandatory 2-step confirmation dialog. When `ENABLED_ACCESSIBILITY_SERVICES` or accessibility shortcut targets are restored from backup, services are directly enabled (V-376) or placed into shortcut lists (V-377). Once in a shortcut list, `isAccessibilityServiceWarningRequired` returns `false` (circular trust), allowing the hardware volume shortcut to enable the service without any warning dialog.

### Root Cause
Three independent issues combine:
1. `restoreEnabledAccessibilityServicesLocked` enables services without `isAccessibilityServiceWarningRequired` check
2. `restoreShortcutTargets` adds services to shortcut lists without `isAccessibilityTargetAllowed` check
3. `performAccessibilityShortcutTargetService` enables shortcut targets without warning because they're "already in a shortcut" (circular trust at line 5191-5196)

### Steps to Reproduce
```bash
# 1. Create a backup with malicious a11y service in shortcut targets
adb backup -f backup.ab -noapk com.android.providers.settings
# Edit backup to add "com.attacker/.EvilService" to:
#   Settings.Secure.ACCESSIBILITY_SHORTCUT_TARGET_SERVICE
# Restore on new device:
adb restore backup.ab

# 2. On the target device, hold both volume keys for 3 seconds
# → Accessibility shortcut triggers
# → EvilService is enabled WITHOUT the 2-step warning dialog
# → Service can now inject input, read screen content, etc.
```

### Impact
- CRITICAL escalation: Any accessibility capability (input injection, screen reading, gesture execution) without user consent through the standard dialog
- Requires: backup restore containing attacker's service + user accidentally/intentionally pressing volume shortcut
- The accessibility service warning dialog is Android's primary defense against malicious accessibility services

### Fix Recommendation
1. `restoreEnabledAccessibilityServicesLocked` should check `isAccessibilityServiceWarningRequired` before enabling
2. `restoreShortcutTargets` should check `isAccessibilityTargetAllowed` before adding to shortcut lists
3. `isAccessibilityServiceWarningRequired` should NOT return false merely because a service is in a shortcut list — the shortcut list itself may have been populated without user consent

### Severity
HIGH (Bypass of critical security dialog; enables input injection/screen reading without explicit user approval)

---

*Generated by FuzzMind/CoreBreaker Round 27 — 2026-04-30*
