# Report 36: Round 25 — EoP: ActivityStarter Task Manipulation, BAL Bypass, NFC Tag Dispatch

**Date**: 2026-04-30  
**Scope**: ActivityStarter, BackgroundActivityStartController, Task, NfcDispatcher, BluetoothPeripheralHandover  
**Method**: Deep background agents + source verification  
**Previous**: Reports 01-35, ~361 variants

---

## Part A: ActivityStarter / BAL (4 findings)

### V-361: PendingIntent mCallingUid Used for Task UID Presence Check — BAL Bypass via Stored Creator Identity [HIGH/EoP]

**File**: `services/core/java/com/android/server/wm/ActivityStarter.java` (lines 2220-2221, 1464-1465)

**Issue**: When a PendingIntent triggers an activity start, `mCallingUid` represents the PendingIntent **creator** while `mRealCallingUid` represents the **sender**. The BAL task insertion check uses only `mCallingUid`:

```java
// Line 2220-2221:
boolean blockBalInTask = (newTask
    || !targetTask.isUidPresent(mCallingUid)  // Uses PI CREATOR uid!
    || (LAUNCH_SINGLE_INSTANCE == mLaunchMode && targetTask.inPinnedWindowingMode()));
if (mBalCode == BAL_BLOCK && blockBalInTask && handleBackgroundActivityAbort(r)) {
    return START_ABORTED;
}
```

```java
// Line 1464-1465 — Activity is recorded as launched from PI creator:
r.setLaunchedFromUid(callingUid);  // PI creator UID
```

**Attack**:
1. System component creates a PendingIntent (mCallingUid = SYSTEM_UID or privileged UID)
2. This PI is exposed to apps (via notification, broadcast, etc.)
3. Attacker app (background, BAL_BLOCK) sends the PendingIntent with fill-in targeting a task that has system activities
4. BAL check: `targetTask.isUidPresent(mCallingUid)` → system UID IS present in its own task → `blockBalInTask = false`
5. BAL check is BYPASSED — attacker's activity is inserted into system's task from background
6. The ASM check at line 2286 does use BOTH uids but only if the target activity opts into ASM (which is `@Disabled` by default)

**Permission**: Must obtain reference to a PendingIntent created by system/privileged app  
**Impact**: Background activity launch + task injection into privileged task stacks. Combined with task affinity hijacking, enables full UI overlay attacks.  
**Bounty**: $5,000-$15,000

---

### V-362: SYSTEM_ALERT_WINDOW as Universal BAL + ASM Bypass [MEDIUM-HIGH/EoP]

**File**: `BackgroundActivityStartController.java` (lines 1091-1101, 1278)

**Issue**: Apps with `SYSTEM_ALERT_WINDOW` (SAW) permission receive `BAL_ALLOW_SAW_PERMISSION` which:
1. Allows background activity starts unconditionally
2. At `checkActivityAllowedToStart` line 1278: bypasses ALL ASM cross-UID activity switch protections

SAW is grantable by users through Settings (not signature-only), and once granted:
- App can start activities from background at any time
- App can create new tasks and bring tasks to front
- App bypasses ASM cross-UID protections (meant to prevent StrandHogg)

Combined with task affinity hijacking (Finding V-363), SAW effectively enables full StrandHogg-style attacks on Android 15/16.

**Permission**: SYSTEM_ALERT_WINDOW (user-grantable)  
**Impact**: Complete BAL + ASM bypass — background activity launch, task manipulation, UI overlay attacks  
**Bounty**: $3,000-$7,000 (SAW is a known powerful permission, but combination with ASM bypass is novel)

---

### V-363: Task Affinity Hijacking — ASM_RESTRICTIONS Disabled by Default [MEDIUM/EoP]

**File**: `ActivityStarter.java` (line 195-196, 2964), `BackgroundActivityStartController.java` (line 1704)

**Issue**: The Activity Security Model (ASM) that prevents cross-UID activity insertion into tasks is gated by `ASM_RESTRICTIONS` (change ID 230590090) which is annotated `@Disabled`. Enforcement only applies when `CompatChanges.isChangeEnabled(ASM_RESTRICTIONS, ar.getUid())` — which returns false for all apps that haven't explicitly opted in.

This means classic StrandHogg-style task affinity hijacking remains effective on Android 15/16 for apps with BAL privileges (SAW, visible window, etc.):
1. Attacker sets `taskAffinity` matching victim's package name
2. Attacker starts activity with `FLAG_ACTIVITY_NEW_TASK` — gets placed in victim's existing task
3. User returns to victim's task and sees attacker's UI

**Permission**: Requires BAL privilege (SAW, visible window, or PendingIntent)  
**Impact**: UI overlay/phishing via task hijacking — StrandHogg still alive  
**Bounty**: $2,000-$5,000

---

### V-364: BAL Grace Period 3-Second Bypass Window After Activity Finish [MEDIUM/EoP]

**File**: `BackgroundActivityStartController.java` (lines 1262-1264, 1834-1870, 2025-2066)

**Issue**: After a visible activity finishes, there's a 3-second grace period (`ASM_GRACEPERIOD_TIMEOUT_MS = 3000`) during which background activity starts are allowed. This completely bypasses ALL ASM checks:

```java
if (balCode == BAL_ALLOW_ALLOWLISTED_UID
    || (android.security.Flags.asmReintroduceGracePeriod()
        && balCode == BAL_ALLOW_GRACE_PERIOD)) {
    return true;  // Bypasses ALL ASM checks!
}
```

**Attack**:
1. Attacker causes a visible activity to finish (via broadcast, timeout, or programmatic finish)
2. Within 3 seconds, attacker starts activities from background
3. Up to 5 chained launches allowed (`ASM_GRACEPERIOD_MAX_REPEATS = 5`)
4. Activities bypass ASM cross-UID checks

**Permission**: Must be able to trigger activity finish (multiple methods available)  
**Impact**: Temporary BAL + ASM bypass window after any activity finish  
**Bounty**: $1,000-$3,000

---

## Part B: NFC Tag Dispatch (3 findings)

### V-365: Bluetooth OOB Pairing from NFC Tag — HID Injection via Bypassed Pairing Security [MEDIUM-HIGH/EoP]

**File**: `packages/apps/Nfc/src/com/android/nfc/NfcDispatcher.java` (lines 969-1037)  
**File**: `packages/apps/Nfc/src/com/android/nfc/handover/BluetoothPeripheralHandover.java` (lines 451-465)

**Issue**: When an NFC tag contains Bluetooth OOB (Out-of-Band) pairing data, the system:
1. Parses BT MAC address, device name, and OOB cryptographic material from the tag
2. Shows a confirmation dialog with the **attacker-controlled** device name
3. If user confirms, calls `mDevice.createBondOutOfBand(mTransport, null, mOobData)` which **bypasses standard BT pairing security** (no numeric comparison, no passkey entry)

```java
// BluetoothPeripheralHandover.java line 456-458:
if (mOobData != null) {
    if (!mDevice.createBondOutOfBand(mTransport, null, mOobData)) {
        // ...
    }
}
```

The OOB data provides pre-shared cryptographic secrets for pairing, meaning the attacker controls BOTH ends of the pairing process. A successful pairing to a HID (Human Interface Device) profile enables keystroke/mouse injection.

**Attack**:
1. Attacker creates BT device configured as HID keyboard
2. Attacker programs NFC tag with BT OOB record containing device MAC + OOB pairing keys + friendly device name ("Wireless Headphones")
3. Victim taps tag → dialog shows "Connect to Wireless Headphones?"
4. Victim confirms → device bonds using OOB (no standard pairing verification)
5. Attacker's HID device can now inject keystrokes/mouse events

**Permission**: Physical proximity (NFC tap) + user interaction (confirm dialog)  
**Impact**: Keystroke injection via HID profile after OOB-bypassed BT pairing  
**Bounty**: $3,000-$7,000

---

### V-366: NFC Enables Bluetooth Without User Consent Before Pairing Dialog [MEDIUM/EoP]

**File**: `packages/apps/Nfc/src/com/android/nfc/handover/PeripheralHandoverService.java` (lines 193-199, 249-255)

**Issue**: When a BT handover NFC tag is tapped and Bluetooth is currently disabled, the NFC service silently enables Bluetooth BEFORE showing the pairing confirmation dialog:

```java
// PeripheralHandoverService.java:
if (!mBluetoothAdapter.isEnabled()) {
    mBluetoothEnabledByNfc = true;
    return mBluetoothAdapter.enableNoAutoConnect();  // BT enabled silently!
}
// Then shows ConfirmConnectActivity dialog
```

The NFC app holds `BLUETOOTH_PRIVILEGED` allowing it to toggle BT state. Even if the user denies the subsequent pairing dialog, Bluetooth was already enabled (expanding the device's wireless attack surface). While `disableBluetoothIfNeeded()` should re-disable it on failure, there's a window where BT is active without consent.

**Permission**: Physical proximity (NFC tap)  
**Impact**: Bluetooth radio enabled without user consent — expands wireless attack surface  
**Bounty**: $1,000-$2,000

---

### V-367: Cross-User NFC Tag Dispatch to Non-Foreground Profiles [LOW-MEDIUM/EoP]

**File**: `packages/apps/Nfc/src/com/android/nfc/NfcDispatcher.java` (lines 396-423, 449-479)

**Issue**: When no activity in the current foreground user handles a tag dispatch, NfcDispatcher iterates ALL enabled profiles and dispatches to them:

```java
List<UserHandle> userHandles = getCurrentActiveUserHandles();
userHandles.remove(UserHandle.of(ActivityManager.getCurrentUser()));
for (UserHandle uh : userHandles) {
    activities = queryNfcIntentActivitiesAsUser(packageManager, intentToStart, uh);
    // ...
    context.startActivityAsUser(rootIntent, uh);  // Launches in non-foreground profile!
}
```

A crafted NFC tag with a MIME type only handled by a work profile app can trigger activity launches in the work profile without the user being aware they're crossing the profile boundary.

**Permission**: Physical proximity (NFC tap)  
**Impact**: Profile boundary bypass — activities launched in work/managed profile from physical NFC tag  
**Bounty**: $500-$1,500

---

## Part C: NfcRootActivity Latent Risk (Informational)

### V-368: NfcRootActivity Intent Relay — LaunchAnywhere Pattern (Currently Mitigated) [LATENT CRITICAL]

**File**: `packages/apps/Nfc/src/com/android/nfc/NfcRootActivity.java` (lines 30-48)

**Issue**: `NfcRootActivity` extracts an Intent from its extras and launches it with `startActivityAsUser()` specifying an attacker-controlled UserHandle:

```java
final Intent launchIntent = intent.getParcelableExtra(EXTRA_LAUNCH_INTENT);
UserHandle user = intent.hasExtra(EXTRA_LAUNCH_INTENT_USER_HANDLE)
    ? intent.getParcelableExtra(EXTRA_LAUNCH_INTENT_USER_HANDLE)
    : UserHandle.CURRENT;
startActivityAsUser(launchIntent, user);
```

This is a textbook LaunchAnywhere pattern. Currently mitigated because `NfcRootActivity` is NOT exported (no intent-filter, defaults to `exported=false` on Android 12+). However, if any future code change exports this activity, it becomes an instant CRITICAL — any app could launch any activity as any user.

**Current exploitability**: NOT exploitable (activity not exported)  
**Impact**: If exported in future = CRITICAL (launch any activity as any user under NFC UID)  
**Bounty**: $500-$1,000 (latent/hardening)

---

## Round 25 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 1 | PendingIntent mCallingUid BAL bypass (V-361) |
| MEDIUM-HIGH | 2 | SAW universal bypass (V-362), BT OOB pairing (V-365) |
| MEDIUM | 2 | Task affinity hijacking (V-363), BAL grace period (V-364) |
| MEDIUM | 1 | BT enable without consent (V-366) |
| LOW-MEDIUM | 1 | Cross-user NFC dispatch (V-367) |
| LATENT | 1 | NfcRootActivity LaunchAnywhere (V-368) |
| **Total** | **8** | |

**Estimated bounty this round**: $16,000 - $42,500

---

## Cumulative Project Statistics (Reports 01-36)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~361 | +8 | **~369** |
| HIGH/CRITICAL | ~52 | +1 | **~53** |
| Bounty estimate (low) | $700.4k | +$16k | **$716.4k** |
| Bounty estimate (high) | $1.722M | +$42.5k | **$1.764M** |

---

## V-361 VRP Report Draft

### Title: PendingIntent Creator UID Used for BAL Task Insertion Check — Background Activity Injection into Privileged Tasks

### Summary
When a PendingIntent triggers an activity start, `ActivityStarter` uses `mCallingUid` (the PI creator's UID) for the BAL task insertion check at line 2220: `!targetTask.isUidPresent(mCallingUid)`. If the PI was created by a system component whose UID is already present in the target task, a background attacker sending this PI bypasses the `blockBalInTask` check entirely. The subsequent ASM check (which does use both creator and sender UIDs) is gated by `ASM_RESTRICTIONS` which is `@Disabled` by default, providing no protection for most apps.

### Root Cause
The BAL enforcement uses the wrong UID for determining task insertion authorization. It should check whether the SENDER (`mRealCallingUid`) has a presence in the target task, not the creator.

### Steps to Reproduce
1. Obtain a PendingIntent created by a system component (e.g., from a notification action, alarm callback, or system broadcast)
2. From a background app (no visible window, no SAW), call `pendingIntent.send()` with a fill-in intent targeting an activity with taskAffinity matching a system task
3. Observe that the activity is launched and placed in the system's task, despite the sender being in background with BAL_BLOCK

### Impact
- Background activity injection into system/privileged task stacks
- UI overlay for credential phishing via task hijacking
- Bypasses BAL restrictions meant to prevent background popup attacks
- Combines with V-363 (task affinity hijacking still possible due to disabled ASM) for full attack chain

### Severity
HIGH (Background Activity Launch bypass + Task injection from unprivileged sender)

---

*Generated by FuzzMind/CoreBreaker Round 25 — 2026-04-30*
