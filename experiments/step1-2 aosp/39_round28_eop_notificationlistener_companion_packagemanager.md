# Report 39: Round 28 — EoP: NotificationListener PendingIntent Extraction, CompanionDeviceManager, PackageManager

**Date**: 2026-04-30  
**Scope**: NotificationManagerService (listener paths), CompanionDeviceManagerService, PackageInstallerService, ManagedServices  
**Method**: Deep background agents + manual source verification  
**Previous**: Reports 01-38, ~385 variants

---

## Part A: NotificationListenerService (3 findings)

### V-385: PendingIntents Preserved in Redacted Notifications — BAL Pivot via NLS [HIGH/EoP]

**File**: `services/core/java/com/android/server/notification/NotificationManagerService.java` (lines 13214-13273)

**Issue**: The sensitive-content redaction feature (`redactSensitiveNotificationsFromUntrustedListeners`) was designed to protect untrusted NLS apps from reading notification text. However, `redactStatusBarNotification()` preserves ALL PendingIntents:

```java
// redactStatusBarNotification():
// Uses oldNotif.cloneInto(oldClone, false) which copies PendingIntents
// Then wraps in Builder - preserving contentIntent, deleteIntent, fullScreenIntent
// Actions are preserved: new Notification.Action.Builder(oldNotif.actions[i]).build()
// PendingIntents in actions are NOT stripped!
```

Combined with V-338 (notification PendingIntents automatically get BAL privilege at enqueue time), an NLS app can:
1. Read "redacted" notifications from high-privilege apps (Settings, SystemUI, Dialer)
2. Extract PendingIntents that execute with those apps' identities
3. Send the PendingIntents to trigger activities/services with the victim app's privileges
4. The PendingIntents already have BAL allowlisting from NMS

**Attack**:
1. Malicious app gains NLS access (via Settings toggle, companion device, or installer grant)
2. Intercepts notifications from system apps (always present: Settings, SystemUI notifications)
3. Extracts PendingIntents that launch with system app identity
4. Calls `pendingIntent.send()` to trigger BAL-privileged activity launches as system apps
5. Combined with task affinity hijacking (V-363), achieves UI overlay in system task

**Permission**: NotificationListenerService access (user-granted or via companion device)  
**Impact**: Background activity launch with system app identity; potential task injection  
**Bounty**: $5,000-$15,000

---

### V-386: Cross-User Notification Access Exposes Work Profile / Private Space to Personal App [MEDIUM/EoP]

**File**: `services/core/java/com/android/server/notification/ManagedServices.java` (line 1946)

**Issue**: Non-system NLS apps with `targetSdkVersion >= 21` (all modern apps) can see notifications from ALL current profiles — including work profile and Private Space:

```java
// ManagedServiceInfo.enabledAndUserMatches():
return supportsProfiles()                   // targetSdk >= LOLLIPOP
    && mUserProfiles.isCurrentProfile(nid)  // Work profile IS current profile!
    && isPermittedForProfile(nid);          // Only blocked if DPC sets restriction
```

`UserProfiles.isCurrentProfile()` returns true for ALL profiles of the current user, including work profiles and Private Space. Unless a DPC explicitly calls `setPermittedNotificationListeners`, all listeners have access.

**Attack**:
1. User grants NLS access to a personal-profile app
2. App reads all work-profile notifications (email content, Slack messages, corporate communications)
3. App reads Private Space notifications (sensitive apps, dating apps, etc.)
4. User is NEVER warned about cross-profile access when granting NLS

**Permission**: NotificationListenerService access (user-granted)  
**Impact**: Complete cross-profile notification surveillance without explicit consent  
**Bounty**: $3,000-$7,000

---

### V-387: Companion Device Association Grants Privileged Listener Status — Channel Manipulation [MEDIUM/EoP]

**File**: `NotificationManagerService.java` (lines 6865-6881)

**Issue**: Having ANY companion device association (including self-managed associations that don't require a real device) grants "privileged listener" status for notification channel operations:

```java
// verifyPrivilegedListener():
if (mCompanionManager != null && mCompanionManager.getAssociations(
        srec.info.getPackageName(), userId).size() > 0) {
    return;  // Passes verification!
}
```

A privileged listener can:
- Modify any app's notification channels (`updateNotificationChannelFromPrivilegedListener`)
- Silence critical notification channels (banking alerts, security warnings)
- Change notification importance for any app

**Attack**:
1. Malicious app creates self-managed companion device association (user sees a less alarming dialog than NLS grant)
2. App is granted NLS access via companion device flow
3. App gains privileged listener status
4. Silently lowers importance of banking/security app notification channels
5. User misses critical fraud alerts

**Permission**: NLS access + companion device association (both user-granted but via separate flows)  
**Impact**: Silent manipulation of other apps' notification channels  
**Bounty**: $2,000-$5,000

---

## Part B: CompanionDeviceManagerService (3 findings)

### V-388: Self-Managed Companion Association Enables Permanent Foreground Service Without Real Device [MEDIUM-HIGH/EoP]

**File**: `services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java`

**Issue**: Self-managed companion device associations allow apps to declare device presence/absence without actual BLE/Bluetooth detection. Calling `notifySelfManagedDeviceAppeared()` triggers:
- Companion app binding (foreground service privileges)
- Power exemptions via `mCompanionExemptionProcessor`
- Wake-from-doze capabilities

```java
@EnforcePermission(REQUEST_COMPANION_SELF_MANAGED)
public void notifySelfManagedDeviceAppeared(int associationId) {
    mDevicePresenceProcessor.notifySelfManagedDevicePresenceEvent(associationId, true);
}
```

An app can keep itself perpetually bound as a foreground service by notifying device appearance, even though no physical device exists.

**Permission**: `REQUEST_COMPANION_SELF_MANAGED` (normal permission, user-grantable) + user approval of association dialog  
**Impact**: Permanent foreground service + Doze exemption without actual companion device  
**Bounty**: $2,000-$5,000

---

### V-389: buildPermissionTransferUserConsentIntent Has No Permission Check [MEDIUM/EoP]

**File**: `CompanionDeviceManagerService.java`

**Issue**: `buildPermissionTransferUserConsentIntent` has NO permission enforcement:

```java
public PendingIntent buildPermissionTransferUserConsentIntent(String packageName,
        int userId, int associationId) {
    // NO permission check!
    return mSystemDataTransferProcessor.buildPermissionTransferUserConsentIntent(
            packageName, userId, associationId);
}
```

Any app with an existing association can build the permission transfer consent intent, potentially tricking users into approving permission synchronization they didn't intend.

**Permission**: Must have existing companion association  
**Impact**: Unauthorized permission transfer consent UI trigger  
**Bounty**: $1,000-$3,000

---

### V-390: canPairWithoutPrompt Leaks Association Timing Information — No Caller Check [LOW-MEDIUM/Info]

**File**: `CompanionDeviceManagerService.java`

**Issue**: `canPairWithoutPrompt` returns whether a pairing-without-prompt window is active for a given MAC address, with NO caller permission check:

```java
public boolean canPairWithoutPrompt(String packageName, String macAddress, int userId) {
    // Within 10-minute window of association approval
    return System.currentTimeMillis() - association.getTimeApprovedMs()
            < PAIR_WITHOUT_PROMPT_WINDOW_MS;
}
```

Any app can probe whether another app recently (within 10 minutes) had a companion device association approved, leaking timing information about device pairing activity.

**Permission**: ZERO  
**Impact**: Information disclosure about companion device pairing timing  
**Bounty**: $500-$1,000

---

## Part C: PackageInstallerService (1 finding)

### V-391: addChildSessionId Missing Child Session Ownership Check — Session Disruption [LOW-MEDIUM/EoP]

**File**: `services/core/java/com/android/server/pm/PackageInstallerSession.java` (lines 5069-5123)

**Issue**: `addChildSessionId` checks ownership only on the **parent** session (`assertCallerIsOwnerOrRoot`), not on the **child** session being added:

```java
// addChildSessionId:
assertCallerIsOwnerOrRoot();  // Only checks THIS (parent) session
// canBeAddedAsChild only checks structural constraints, NOT ownership:
if (childSession.getParentSessionId() != SessionInfo.INVALID_ID) return false;
if (childSession.isCommitted()) return false;
if (childSession.isDestroyed()) return false;
```

**Attack**:
1. Attacker learns a victim installer's session ID via `getAllSessions()` (session IDs are visible to package-queryable apps)
2. Attacker creates their own multi-package parent session
3. Calls `addChildSessionId(victimSessionId)` — passes because only parent ownership is checked
4. Victim's session is now a child of attacker's parent
5. Victim cannot commit their session (it's now part of a different parent)
6. OR: Attacker commits their parent, pulling victim's session into an unintended transaction

**Mitigations**: SecureRandom session IDs make blind guessing infeasible. Commit-time signature verification prevents code injection. Main impact is session disruption/DoS.

**Permission**: ZERO (must know or enumerate target session ID)  
**Impact**: Installation session disruption for other apps  
**Bounty**: $500-$1,500

---

## Part D: V-340 Status Update (Downgrade)

### V-340 (Previously CRITICAL) → MEDIUM: PendingIntent fillIn URI Grant — Mechanism Confirmed, Gadget Blocked

**Status**: The `Intent.fillIn()` flag ORing bug is confirmed, but **two independent defenses** prevent exploitation:
1. `checkGrantUriPermissionUnlocked()` blocks URI grant collection for SYSTEM_UID callers
2. `sendActivityResult` passes `callingUid = -1`, preventing grant application

No system-created mutable ACTIVITY_RESULT PendingIntents exposed to untrusted apps were found. The mechanism remains a latent bug that would become exploitable if either defense is weakened.

**Revised bounty**: $1,000-$3,000 (mechanism bug, no current gadget)

---

## Part E: Confirmed Secure (Audit Negative Results)

| Service | Result |
|---------|--------|
| PackageManager permission escalation during update | INSTALL_GRANT_RUNTIME_PERMISSIONS (signature) required |
| Shared UID manipulation | Signature verification + immutability checks |
| Split APK injection | Exact signature matching at commit time |
| Package downgrade | INSTALL_ALLOW_DOWNGRADE forcibly cleared for non-system |
| Cross-user package install | enforceCrossUserPermission in all paths |
| Post-install broadcast race | Permission state finalized under lock before broadcasts |
| V-340 ACTIVITY_RESULT gadgets | No exploitable gadgets found; defenses hold |

---

## Round 28 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 1 | NLS PendingIntent extraction (V-385) |
| MEDIUM-HIGH | 1 | Self-managed companion FGS (V-388) |
| MEDIUM | 3 | Cross-user NLS (V-386), NLS channel manipulation (V-387), Permission transfer (V-389) |
| LOW-MEDIUM | 2 | Association timing leak (V-390), Session hijacking (V-391) |
| **Total** | **7** | |

**Estimated bounty this round**: $14,000 - $37,500

---

## Cumulative Project Statistics (Reports 01-39)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~385 | +7 | **~392** |
| HIGH/CRITICAL | ~55 | +1 | **~56** |
| Bounty estimate (low) | $744.9k | +$14k | **$758.9k** |
| Bounty estimate (high) | $1.842M | +$37.5k | **$1.880M** |

---

## V-385 VRP Report Draft

### Title: Notification Listener PendingIntent Extraction Bypasses Sensitive Content Redaction — BAL Pivot to System App Identity

### Summary
The notification content redaction feature (`redactSensitiveNotificationsFromUntrustedListeners`) strips text content from notifications delivered to untrusted NotificationListenerService apps. However, it preserves ALL PendingIntents (contentIntent, deleteIntent, fullScreenIntent, and action PendingIntents). Since NMS automatically grants BAL privileges to all notification PendingIntents at enqueue time (V-338), an NLS-holding app can extract PendingIntents from system notifications and invoke them to achieve Background Activity Launch with system app identity.

### Root Cause
`redactStatusBarNotification()` redacts text content but does not strip PendingIntents from:
- `Notification.contentIntent`
- `Notification.deleteIntent`  
- `Notification.fullScreenIntent`
- `Notification.Action.actionIntent` (for all actions)

These PendingIntents carry BAL privilege (granted at enqueue time) and execute with the notification-posting app's identity.

### Steps to Reproduce
1. Register a NotificationListenerService (obtain NLS access via Settings or companion device)
2. Wait for system notification from Settings, SystemUI, or Phone app
3. Call `getActiveNotifications()` — receive "redacted" notification
4. Extract `notification.contentIntent` (PendingIntent with system app identity)
5. Call `pendingIntent.send(context, 0, fillInIntent)` from background
6. Activity launches with system app identity + BAL privilege, bypassing background restrictions

### Impact
- Background Activity Launch with system app identity
- Task injection into system app tasks (combined with task affinity)
- Potential UI overlay for credential phishing using system app appearance
- The "sensitive content" redaction creates false security assumption — NLS apps are told they can't read content, but can still invoke all notification actions

### Severity
HIGH (BAL bypass + system identity assumption via NLS)

---

*Generated by FuzzMind/CoreBreaker Round 28 — 2026-04-30*
