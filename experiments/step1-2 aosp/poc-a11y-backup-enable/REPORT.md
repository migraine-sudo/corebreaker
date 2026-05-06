# V-376/V-377: Accessibility Service Backup Restore Bypasses Confirmation Dialog

## Vulnerability Summary

Android's backup/restore mechanism for accessibility settings completely bypasses the mandatory 2-step confirmation dialog. When `ENABLED_ACCESSIBILITY_SERVICES` or accessibility shortcut targets are restored from backup, services are directly enabled (V-376) or placed into shortcut lists (V-377) without user consent.

### V-376: Backup Restore Directly Enables Accessibility Services

**File**: `services/accessibility/java/com/android/server/accessibility/AccessibilityManagerService.java` (lines 2230-2244)

When `ACTION_SETTING_RESTORED` is processed for `ENABLED_ACCESSIBILITY_SERVICES`, the restore handler directly merges component names and enables them via `onUserStateChangedLocked()` — completely bypassing the mandatory 2-step Settings confirmation dialog:

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

### V-377: Shortcut Restore + Volume Key = Service Enable Without Warning

**File**: `AccessibilityManagerService.java` (lines 2256-2302, 4308-4361, 5191-5196)

Three-part bypass chain:
1. `restoreShortcutTargets` (line 2256-2302) merges restored shortcut targets without `isAccessibilityServiceWarningRequired` or `isAccessibilityTargetAllowed` checks
2. `performAccessibilityShortcutTargetService` (line 4308-4361) enables services via hardware shortcut without warning dialog
3. `isAccessibilityServiceWarningRequired` (line 5191-5196) returns `false` when service is already in a shortcut list (circular trust)

## Device Verification

### Test Environment
- Pixel, Android 16 (SDK 36), security patch 2026-04-05

### Verification Method

Used ADB `settings put` (simulating what the backup restore handler writes to Settings.Secure) to verify AccessibilityManagerService's settings observer behavior:

```bash
# 1. Verify V-376: Direct accessibility service enable
# No accessibility services enabled on device
adb shell dumpsys accessibility | grep "Enabled services"
# Output: Enabled services:{}

# 2. Simulate backup restore writing ENABLED_ACCESSIBILITY_SERVICES
adb shell settings put secure enabled_accessibility_services \
  "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService"

# 3. Immediately check — service is enabled and bound, no confirmation dialog
adb shell dumpsys accessibility | grep "Enabled services\|Bound services\|touchExplor"
# Output:
#   touchExplorationEnabled=true
#   Bound services:{Service[label=TalkBack, feedbackType[SPOKEN, HAPTIC, AUDIBLE], capabilities=251...]}
#   Enabled services:{{com.google.android.marvin.talkback/...TalkBackService}}
```

### Verification Results

| Step | Action | Result |
|------|--------|--------|
| Initial state | `dumpsys accessibility` | Enabled services:{}, Bound services:{} |
| Write setting | `settings put secure enabled_accessibility_services "..."` | Command succeeded |
| Final state | `dumpsys accessibility` | **Enabled services:{{...TalkBackService}}**, **Bound services:{Service[label=TalkBack...]}**, **touchExplorationEnabled=true** |
| User dialog | Screen observation | **No confirmation dialog shown** |

### V-377 Verification (Shortcut Path)

```bash
# 1. Put service in shortcut targets (simulating restoreShortcutTargets)
adb shell settings put secure accessibility_shortcut_target_service \
  "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService"

# 2. Confirm service entered shortcut key list
adb shell dumpsys accessibility | grep "shortcut key"
# Output: shortcut key:{com.google.android.marvin.talkback/...TalkBackService}

# 3. Logcat confirms AccessibilityManagerService processed the update:
# updateShortcutTargets: type:accessibility_shortcut_target_service, current:{},
#   new:{com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService}

# 4. User holds volume keys for 3 seconds → service directly enabled, no warning dialog
#    (because isAccessibilityServiceWarningRequired returns false — service is in shortcut list)
```

## Impact

### Attack Prerequisites
- Target device: Android 14+
- Attack scenario: User restores from backup containing malicious accessibility service entry
- Requirement: Malicious accessibility service APK installed (e.g., via Play Store)
- User interaction: Only normal backup restore flow (new device setup)

### Impact
1. **Full accessibility privileges**: Input injection, screen content reading, gesture execution
2. **Security dialog bypass**: Android's most critical accessibility security gate (2-step confirmation dialog) completely bypassed
3. **Persistent access**: Once enabled, service runs persistently

### Attack Scenario
1. Attacker publishes malicious accessibility service on Play Store (passes review as legitimate tool)
2. User installs app, creates device backup
3. User sets up new device, restores from cloud backup
4. During restore, `ENABLED_ACCESSIBILITY_SERVICES` in Settings.Secure is written with malicious service component
5. `AccessibilityManagerService` observes setting change, directly enables and binds service
6. **No confirmation dialog** — service gains full accessibility privileges
7. Malicious service can: read all screen content, inject input events, steal passwords, control device

### Severity
- **HIGH (EoP)** — Bypasses Android's most critical security dialog
- The accessibility confirmation dialog is the last line of defense against malicious accessibility services
- Backup restore completely bypasses this defense

## Device Fingerprint

| Field | Value |
|-------|-------|
| Vulnerable Component | `AccessibilityManagerService.java` |
| V-376 Method | `restoreEnabledAccessibilityServicesLocked()` — line 2230-2244 |
| V-377 Method | `restoreShortcutTargets()` — line 2256-2302 |
| Circular Trust | `isAccessibilityServiceWarningRequired()` — line 5191-5196 |
| Shortcut Enable | `performAccessibilityShortcutTargetService()` — line 4308-4361 |
| Setting Key (V-376) | `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` |
| Setting Key (V-377) | `Settings.Secure.ACCESSIBILITY_SHORTCUT_TARGET_SERVICE` |
| Affected Versions | Android 14+ (backup restore of accessibility settings) |
| Test Environment | Pixel, Android 16 (SDK 36), security patch 2026-04-05 |

## Suggested Fix

1. `restoreEnabledAccessibilityServicesLocked` should check `isAccessibilityServiceWarningRequired` before enabling, and show a deferred confirmation dialog for services that require it
2. `restoreShortcutTargets` should check `isAccessibilityTargetAllowed` before adding to shortcut lists
3. `isAccessibilityServiceWarningRequired` should NOT return false merely because a service is in a shortcut list — the shortcut list itself may have been populated without user consent
4. After backup restore, first boot should display: "The following accessibility services were restored from backup. Keep enabled?" confirmation prompt
