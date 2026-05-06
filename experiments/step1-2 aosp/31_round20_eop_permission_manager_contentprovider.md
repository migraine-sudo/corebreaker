# Report 31: Round 20 — EoP: PermissionManager, ContentProviderHelper, AccountManager, WindowManager

**Date**: 2026-04-30  
**Scope**: PermissionManagerServiceImpl, ContentProviderHelper, AccountManagerService, WindowManagerService, NotificationManagerService, InputManagerService  
**Method**: 6 deep background agents (EoP-focused) + manual source audit  
**Previous**: Reports 01-30, ~333 variants

---

## Part A: PermissionManagerServiceImpl (2 findings)

### V-333: updatePermissionFlagsForAllApps Inverted SYSTEM_FIXED Ternary — Non-System Caller Can Manipulate System-Fixed Permission Flags [HIGH/EoP]

**File**: `services/core/java/com/android/server/pm/permission/PermissionManagerServiceImpl.java` (lines 904-907)

**Issue**: The ternary operator for stripping `FLAG_PERMISSION_SYSTEM_FIXED` is **inverted** compared to the correct logic in `updatePermissionFlagsInternal`. Non-system UIDs (installer/verifier apps) can set or clear SYSTEM_FIXED flags on ALL apps' permissions, while the system UID itself is incorrectly blocked.

**Buggy code (lines 904-907):**
```java
// Only the system can change system fixed flags.  <-- COMMENT IS CORRECT
final int effectiveFlagMask = (callingUid != Process.SYSTEM_UID)
        ? flagMask : flagMask & ~PackageManager.FLAG_PERMISSION_SYSTEM_FIXED;
        // WRONG: strips from system, passes through for non-system!
final int effectiveFlagValues = (callingUid != Process.SYSTEM_UID)
        ? flagValues : flagValues & ~PackageManager.FLAG_PERMISSION_SYSTEM_FIXED;
```

**Correct code in updatePermissionFlagsInternal (lines 806-808):**
```java
if (callingUid != Process.SYSTEM_UID) {
    flagMask &= ~PackageManager.FLAG_PERMISSION_SYSTEM_FIXED;  // CORRECT
    flagValues &= ~PackageManager.FLAG_PERMISSION_SYSTEM_FIXED;
```

**Attack**:
1. Compromised installer/verifier app (holds `GRANT_RUNTIME_PERMISSIONS` — protection: signature|installer|verifier)
2. Calls `updatePermissionFlagsForAllApps(FLAG_PERMISSION_SYSTEM_FIXED, 0, userId)` to CLEAR system-fixed flag from ALL permissions for ALL apps on the device
3. Now system-fixed permissions (like INTERNET) can be revoked for any app
4. OR: Sets `FLAG_PERMISSION_SYSTEM_FIXED` on attacker's own permissions, making them permanently irrevocable (even by system updates)

**Severity**: The ternary logic is clearly a code bug (comment says "Only the system can change system fixed flags" but the implementation does the opposite). However, exploitation requires `GRANT_RUNTIME_PERMISSIONS` which is signature|installer|verifier level.

**Permission**: GRANT_RUNTIME_PERMISSIONS or REVOKE_RUNTIME_PERMISSIONS (signature|installer|verifier)  
**Impact**: Permission state manipulation for all apps, permanent permission lock/unlock  
**Bounty**: $5,000-$15,000 (logic bug in permission framework, requires privileged caller)

---

### V-334: updatePermissionFlagsForAllApps Missing Flag Sanitization vs updatePermissionFlagsInternal [MEDIUM-HIGH/EoP]

**File**: `PermissionManagerServiceImpl.java` (lines 904-907 vs 806-816)

**Issue**: Beyond the inverted ternary, `updatePermissionFlagsForAllApps` is MISSING sanitization of 5 additional sensitive flags that `updatePermissionFlagsInternal` properly strips for non-system callers:

Missing sanitization in `updatePermissionFlagsForAllApps`:
- `FLAG_PERMISSION_GRANTED_BY_DEFAULT` — prevents system from modifying grant state
- `FLAG_PERMISSION_RESTRICTION_SYSTEM_EXEMPT` — exempts from system restriction
- `FLAG_PERMISSION_RESTRICTION_INSTALLER_EXEMPT` — exempts from installer restriction
- `FLAG_PERMISSION_RESTRICTION_UPGRADE_EXEMPT` — exempts from upgrade restriction
- `FLAG_PERMISSION_APPLY_RESTRICTION` — applies restriction enforcement

**Attack**:
1. Non-system caller with GRANT_RUNTIME_PERMISSIONS
2. Calls `updatePermissionFlagsForAllApps(FLAG_PERMISSION_RESTRICTION_SYSTEM_EXEMPT, FLAG_PERMISSION_RESTRICTION_SYSTEM_EXEMPT, userId)`
3. All hard-restricted permissions (SEND_SMS, CALL_PHONE, READ_CALL_LOG) become exempted from restriction for ALL apps
4. Apps can now use these dangerous permissions without restriction enforcement

**Permission**: GRANT_RUNTIME_PERMISSIONS (signature|installer|verifier)  
**Impact**: Mass bypass of permission restrictions for all apps  
**Bounty**: $3,000-$7,000

---

## Part B: ContentProviderHelper (1 finding)

### V-335: getMimeTypeFilterAsync Clears Calling Identity Before Provider Permission Check — Permission Bypass [MEDIUM-HIGH/EoP]

**File**: `services/core/java/com/android/server/am/ContentProviderHelper.java` (lines 1027-1082)

**Issue**: `getMimeTypeFilterAsync()` calls `canClearIdentity()` then `Binder.clearCallingIdentity()` before calling `getContentProviderExternalUnchecked()`. Inside the provider acquisition path, `checkContentProviderPermission()` checks `Binder.getCallingUid()` which is now SYSTEM_UID. This means the provider's readPermission/writePermission check is bypassed.

```java
void getMimeTypeFilterAsync(Uri uri, int userId, RemoteCallback resultCallback) {
    mService.enforceNotIsolatedCaller("getProviderMimeTypeAsync");
    final String name = uri.getAuthority();
    final int callingUid = Binder.getCallingUid();
    final int callingPid = Binder.getCallingPid();
    final int safeUserId = mService.mUserController.unsafeConvertIncomingUser(userId);
    final long ident = canClearIdentity(callingPid, callingUid, safeUserId)
            ? Binder.clearCallingIdentity() : 0;  // Clears identity!
    final ContentProviderHolder holder;
    try {
        holder = getContentProviderExternalUnchecked(name, null, callingUid,
                "*getmimetype*", safeUserId);
        // Inside this: checkContentProviderPermission uses Binder.getCallingUid()
        // which is now SYSTEM_UID!
    } finally { ... }
}
```

**Attack**:
1. Any app calls `ContentResolver.getType(uri)` for a permission-protected ContentProvider
2. System acquires the provider on the caller's behalf under system identity
3. Provider permission check sees SYSTEM_UID → always passes
4. Provider's `getType()` is called, potentially disclosing MIME types for content the caller shouldn't access

**Permission**: ZERO (or normal, depending on provider visibility)  
**Impact**: Permission-protected ContentProvider can be queried for MIME type information without holding the provider's declared permissions. While limited to type information, some providers encode sensitive metadata in MIME types.  
**Bounty**: $1,000-$3,000

---

## Part C: AccountManagerService (2 findings)

### V-336: finishSessionAsUser appInfo Bundle Merge Overwrites Authenticated Session Keys [MEDIUM/EoP]

**File**: `services/core/java/com/android/server/accounts/AccountManagerService.java` (lines 3844-3846)

**Issue**: After decrypting the authenticated session bundle (integrity-protected via CryptoHelper), the caller-supplied `appInfo` bundle is merged INTO the decrypted session with `decryptedBundle.putAll(appInfo)`. This allows a caller to overwrite keys in the authenticated session that the authenticator trusts.

```java
// Line 3821: decryptedBundle = CryptoHelper.decrypt(sessionBundle);
// Line 3829: accountType = decryptedBundle.getString(AccountManager.KEY_ACCOUNT_TYPE);
// ...
if (appInfo != null) {
    decryptedBundle.putAll(appInfo);  // Caller OVERWRITES authenticated session keys!
}
// Line 3891: mAuthenticator.finishSession(this, mAccountType, decryptedBundle);
```

**Attack**:
1. Zero-permission app initiates `startAddAccountSession` → receives encrypted session bundle
2. Calls `finishSessionAsUser` with the encrypted session bundle and an `appInfo` bundle containing:
   - Keys that the target authenticator trusts from the session (e.g., server URL, account name, token type)
   - The authenticator processes the merged bundle, believing these keys are authenticated
3. If the authenticator performs privileged operations based on session keys, the attacker controls those operations

**Permission**: ZERO (public API)  
**Impact**: Depends on authenticator implementation. If authenticator trusts session bundle keys for server selection, credential storage, or account creation parameters, attacker can influence these.  
**Bounty**: $1,000-$3,000

---

### V-337: updateCredentials / confirmCredentials Zero-Permission Authenticator Trigger [LOW-MEDIUM]

**File**: `AccountManagerService.java` (lines 3940-4024)

**Issue**: `updateCredentials()` and `confirmCredentialsAsUser()` perform NO permission check for same-user operations. Any zero-permission app can trigger authenticator binding and UI for arbitrary account types, causing authenticator services to be started and potentially displaying phishing-eligible UI.

**Attack**: 
1. Zero-permission app calls `AccountManager.updateCredentials(account, authTokenType, options, null, null, null)`
2. System binds to the target authenticator service with SYSTEM identity
3. Authenticator's `updateCredentials()` method is invoked
4. If authenticator returns KEY_INTENT, user may see credential entry UI

**Permission**: ZERO  
**Impact**: Authenticator service trigger + potential UI confusion for social engineering  
**Bounty**: $500-$1,000

---

## Part D: WindowManagerService (2 findings)

### V-338: Notification PendingIntent Background Activity Start Allowlisting [MEDIUM/EoP]

**File**: `services/core/java/com/android/server/notification/NotificationManagerService.java` (lines 8186-8206)

**Issue**: When any notification is enqueued via `enqueueNotificationInternal`, NMS calls:
- `mAmi.setPendingIntentAllowBgActivityStarts()` with `FLAG_ACTIVITY_SENDER | FLAG_BROADCAST_SENDER | FLAG_SERVICE_SENDER`
- `mAmi.setPendingIntentAllowlistDuration()` for temporary FGS allowlist

This grants ALL PendingIntents in the notification (contentIntent, deleteIntent, actions) background activity launch (BAL) exemption at **enqueue time**, not at tap time. A background app maintaining a notification effectively has permanent BAL exemption.

**Attack**:
1. App posts a self-updating notification with a mutable PendingIntent
2. All PendingIntents in the notification get BAL exemption immediately
3. App fires its own PendingIntent from the background
4. Activity launches from background, bypassing BAL restrictions

**Permission**: POST_NOTIFICATIONS (normal/runtime on Android 13+)  
**Impact**: Background activity launch bypass — pop activities on screen from background  
**Bounty**: $1,000-$3,000

---

### V-339: Dynamic FLAG_SHOW_WHEN_LOCKED Toggle via relayoutWindow [LOW-MEDIUM/EoP]

**File**: `services/core/java/com/android/server/wm/WindowManagerService.java` (lines 2413-2416)

**Issue**: Window type is immutable after creation, but `FLAG_SHOW_WHEN_LOCKED` and `FLAG_DISMISS_KEYGUARD` can be dynamically toggled via `relayoutWindow`. An app with a foreground activity can toggle these flags to appear above the lockscreen after the device locks.

**Attack**:
1. Malicious app opens a normal foreground activity
2. User locks device
3. App toggles `FLAG_SHOW_WHEN_LOCKED` on its window
4. App's UI appears above lockscreen — presents phishing/lock screen mimicry

**Permission**: None (requires having a foreground activity)  
**Impact**: Lockscreen overlay for credential phishing  
**Bounty**: $500-$2,000 (depends on lifecycle restrictions)

---

## Part E: Confirmed Secure (Audit Negative Results)

| Service | Result |
|---------|--------|
| InstalldNativeService | All methods gated by ENFORCE_UID(AID_SYSTEM) — not reachable from apps |
| MediaProvider openFile | Identity restored before access check; FUSE layer provides defense-in-depth |
| DownloadProvider Helpers | Canonical path resolution + FAT sanitization + FUSE prevents symlinks |
| BackupManagerService | Only routes to per-user services; ParcelFileDescriptor not path-based |
| WindowManager addWindow | Type validation + INTERNAL_SYSTEM_WINDOW check for system types |
| WindowManager grantInputChannel | `mCanAddInternalSystemWindow ? privateFlags : 0` properly sanitizes |
| InputManager injectInputEvent | Requires INJECT_EVENTS (signature) — no bypass |
| PackageInstallerService sessions | SecureRandom IDs + isCallingUidOwner checks |
| RoleManagerService | All APIs properly gated by signature permissions |

---

## Round 20 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 1 | Inverted SYSTEM_FIXED ternary (V-333) |
| MEDIUM-HIGH | 2 | Flag sanitization gap (V-334), ContentProvider permission bypass (V-335) |
| MEDIUM | 2 | Session bundle merge (V-336), notification BAL (V-338) |
| LOW-MEDIUM | 2 | Authenticator trigger (V-337), lockscreen toggle (V-339) |
| **Total** | **7** | |

**Estimated bounty this round**: $12,000 - $34,000

**Highest value finding**: V-333 — The inverted ternary is a clear logic bug in the Android permission framework. The code comment explicitly states "Only the system can change system fixed flags" but the implementation does the opposite. This allows installer/verifier apps to permanently lock or unlock permission states for all apps on the device.

---

## Cumulative Project Statistics (Reports 01-31)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~333 | +7 | **~340** |
| HIGH/CRITICAL | ~49 | +1 | **~50** |
| Bounty estimate (low) | $651.9k | +$12k | **$663.9k** |
| Bounty estimate (high) | $1.596M | +$34k | **$1.630M** |

---

## V-333 VRP Report Draft

### Title: Inverted Ternary in updatePermissionFlagsForAllApps Allows Non-System Caller to Manipulate FLAG_PERMISSION_SYSTEM_FIXED

### Summary
`PermissionManagerServiceImpl.updatePermissionFlagsForAllApps()` (line 904) contains an inverted ternary operator that strips `FLAG_PERMISSION_SYSTEM_FIXED` from the **system UID** rather than from non-system callers. This is the exact opposite of the intended behavior (as stated in the comment) and the correct behavior in the sibling method `updatePermissionFlagsInternal()` (line 806). A caller with `GRANT_RUNTIME_PERMISSIONS` (held by installer/verifier apps) can set or clear SYSTEM_FIXED on all permissions for all packages.

### Steps to Reproduce
1. Create an app with installer/verifier certificate that holds `GRANT_RUNTIME_PERMISSIONS`
2. Call `PackageManager.updatePermissionFlagsForAllApps(FLAG_PERMISSION_SYSTEM_FIXED, FLAG_PERMISSION_SYSTEM_FIXED, userId)`
3. Observe that SYSTEM_FIXED is now set on ALL permissions for ALL apps (should have been blocked)
4. Alternatively, call with `flagValues=0` to CLEAR SYSTEM_FIXED from all permissions

### Expected Behavior
Non-system callers should have `FLAG_PERMISSION_SYSTEM_FIXED` stripped from `flagMask` and `flagValues`, matching the behavior in `updatePermissionFlagsInternal`.

### Impact
- Permission integrity: Installer/verifier apps can permanently lock arbitrary permissions (making them irrevocable)
- Permission denial: Can clear SYSTEM_FIXED from system-critical permissions (INTERNET), then revoke them for any app
- Security boundary violation: Non-system code manipulates system-level permission state

### Severity
HIGH (EoP: logic bug in permission framework core, though requires privileged caller)

---

*Generated by FuzzMind/CoreBreaker Round 20 — 2026-04-30*
