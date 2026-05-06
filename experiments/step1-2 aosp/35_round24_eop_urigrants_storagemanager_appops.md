# Report 35: Round 24 — EoP: UriGrantsManager, StorageManagerService, ContentProviderHelper, AppOpsService

**Date**: 2026-04-30  
**Scope**: UriGrantsManagerService, StorageManagerService, ContentProviderHelper, AppOpsService, ClipboardService, MediaProjectionManagerService  
**Method**: Deep background agents + manual source verification  
**Previous**: Reports 01-34, ~354 variants

---

## Part A: UriGrantsManagerService (2 findings)

### V-354: Recursive ClipData Intent URI Grant Escalation — Confused Deputy via Nested Intent [MEDIUM-HIGH/EoP]

**File**: `services/core/java/com/android/server/uri/UriGrantsManagerService.java`

**Issue**: `checkGrantUriPermissionFromIntentUnlocked()` recursively processes ClipData items containing nested Intents. When an activity is launched with ClipData containing Intent objects, the system recursively grants URI permissions for ALL URIs found in nested Intents' data fields. This creates a confused deputy scenario:

```java
// Recursive ClipData processing:
Intent clipIntent = clip.getItemAt(i).getIntent();
if (clipIntent != null) {
    NeededUriGrants newNeeded = checkGrantUriPermissionFromIntentUnlocked(
        callingUid, targetPkg, clipIntent, mode, needed, ...);
}
```

**Attack**:
1. App A holds URI grant to `content://contacts/1` (obtained via picker/SAF)
2. App B sends Intent to App A with crafted ClipData containing a nested Intent whose `data` field points to `content://contacts/1`
3. App A launches an activity (e.g., share intent) that processes this ClipData
4. System recursively grants URI permissions from App A's held grants to the share target
5. The share target (attacker-controlled or another app) receives unauthorized URI access

The caller (App A) may not realize that by launching a share intent with the crafted ClipData, it's inadvertently granting access to its own held URI permissions.

**Permission**: ZERO (requires tricking the target app into launching with attacker-crafted ClipData)  
**Impact**: Unauthorized URI permission propagation via confused deputy  
**Bounty**: $2,000-$5,000

---

### V-355: Downloads Authority Grant Persistence After Package Uninstall [MEDIUM/EoP]

**File**: `UriGrantsManagerService.java` — `removeUriPermissionsForPackageLocked()`

**Issue**: URI grants to the Downloads authority (`Downloads.Impl.AUTHORITY`) are explicitly exempted from cleanup during non-persistable grant revocation:

```java
if (Downloads.Impl.AUTHORITY.equals(perm.uri.uri.getAuthority())
    && !persistable) continue;  // Skips revocation!
```

This means when a granting app is uninstalled, its URI grants for Download content survive. If a new app is installed with the same package name, the old grants still exist pointing to content that may now belong to a different context.

**Attack**:
1. App A grants App B access to `content://downloads/public_downloads/42`
2. App A is uninstalled — but B's grant persists (Downloads authority exempted from cleanup)
3. A new app installs with same package name (or downloads authority reuses the ID)
4. App B retains access to content that should have been revoked

**Permission**: Must have initial URI grant to Downloads content  
**Impact**: Stale URI grants persist after the granting context is destroyed  
**Bounty**: $1,000-$2,000

---

## Part B: StorageManagerService (2 findings)

### V-356: Volume Mount User ID Race Condition — Cross-User Volume Access [MEDIUM/EoP]

**File**: `services/core/java/com/android/server/StorageManagerService.java`

**Issue**: `updateVolumeMountIdIfRequired()` modifies `vol.mountUserId` outside of consistent synchronization:

```java
if (!vol.isPrimary() && vol.isVisible() && vol.getMountUserId() != mCurrentUserId) {
    vol.mountUserId = mCurrentUserId;
}
```

This is called during user switching. Between the time `mCurrentUserId` changes and the volume mount is updated, there's a window where a volume could be mounted for the wrong user. Combined with the `onUserSwitching` callback that sets `mCurrentUserId`, a race exists where I/O operations could target the wrong user's storage.

**Attack**:
1. User switch from user 0 to user 10 is initiated
2. `mCurrentUserId` updates to 10
3. Before volume mount IDs are fully updated, an app on user 0 reads/writes through the stale mount
4. The data crosses user boundary during the transition window

**Permission**: Requires foreground process during user switch (timing-dependent)  
**Impact**: Brief cross-user storage access during user switching  
**Bounty**: $1,000-$3,000 (race condition, narrow window)

---

### V-357: Vold Reset CE Storage Unlock — Re-unlock Without Keyguard Verification [MEDIUM-HIGH/EoP]

**File**: `StorageManagerService.java` — `restoreSystemUnlockedUsers()`

**Issue**: When vold crashes and restarts, `restoreSystemUnlockedUsers` re-unlocks CE storage for previously-unlocked users WITHOUT re-verifying keyguard state:

```java
Slog.w(TAG, "UNLOCK_USER lost from vold reset, will retry, user:" + userId);
mVold.onUserStarted(userId);
// Posts H_COMPLETE_UNLOCK_USER → completeUnlockUser
```

The `restoreCeUnlockedUsers` method uses `appendAll` which bulk-adds users from vold's state without verifying they should still be unlocked at the framework level. If a user has locked their device between vold's crash and restart, CE storage gets re-unlocked based on stale state.

**Attack**:
1. User unlocks device (CE storage decrypted)
2. User locks device (keyguard shown, but CE remains unlocked in memory)
3. Vold crashes (or is triggered to crash via a separate vuln)
4. Vold restarts → `restoreSystemUnlockedUsers` re-unlocks CE using cached state
5. The "unlocked users" list includes users who should now be locked
6. CE storage remains accessible without keyguard verification

**Permission**: Requires ability to crash vold (separate vulnerability) or timing with natural vold restart  
**Impact**: CE storage remains accessible after device lock during vold restart  
**Bounty**: $3,000-$7,000 (requires vold crash trigger)

---

## Part C: ContentProviderHelper (1 finding)

### V-358: getContentProviderExternalUnchecked Bypass Chain — getMimeTypeFilterAsync Accesses Protected Providers [MEDIUM/EoP]

**File**: `services/core/java/com/android/server/am/ContentProviderHelper.java`

**Issue**: `getMimeTypeFilterAsync()` is a public API entry point that calls `getContentProviderExternalUnchecked()` which skips the `ACCESS_CONTENT_PROVIDERS_EXTERNALLY` permission check. Combined with the `canClearIdentity()` → `Binder.clearCallingIdentity()` pattern (confirmed in V-335), this allows any app to probe providers' MIME type responses:

```java
void getMimeTypeFilterAsync(Uri uri, ...) {
    final long ident = canClearIdentity(callingPid, callingUid, safeUserId)
            ? Binder.clearCallingIdentity() : 0;
    holder = getContentProviderExternalUnchecked(name, null, callingUid,
            "*getmimetype*", safeUserId);
    // Provider acquired under system identity for same-user
}
```

While the provider's permission check still runs, it runs with system identity when `canClearIdentity` is true (same user). This means a zero-permission app can cause system to acquire ANY same-user provider and call `getType()` on it.

**Deeper chain**: If a ContentProvider's `getType()` implementation has side effects (file creation, database access, network calls) or leaks information through MIME type strings, this is exploitable for both information disclosure and triggering privileged side effects.

**Permission**: ZERO (for same-user providers)  
**Impact**: System-identity provider acquisition for getType() calls on permission-protected providers  
**Bounty**: $1,000-$3,000

---

## Part D: AppOpsService (2 findings)

### V-359: Virtual Device Operations Bypass User Restrictions [MEDIUM/EoP]

**File**: `services/core/java/com/android/server/appop/AppOpsService.java`

**Issue**: User restrictions (set by device admins, parental controls, etc.) are only applied to the "default device" context. The code explicitly states: "Only notify default device as other devices are unaffected by restriction changes." This means operations performed on virtual devices (e.g., companion devices, virtual displays) bypass all user restrictions.

**Attack**:
1. Device admin sets restriction `DISALLOW_CAMERA` for managed user
2. App on managed user creates/uses a virtual device context
3. App performs camera operation specifying the virtual device ID
4. AppOps checks pass because restrictions are not applied to non-default devices
5. Camera access granted despite admin restriction

**Permission**: Must have access to a virtual device (COMPANION_DEVICE_MANAGER or similar)  
**Impact**: Bypass of device admin / parental control restrictions via virtual device context  
**Bounty**: $2,000-$5,000

---

### V-360: updateUidProcState Confused Deputy — Broadcast-Supplied UID Without Cross-User Validation [LOW-MEDIUM/EoP]

**File**: `AppOpsService.java`

**Issue**: The `mOnPackageUpdatedReceiver` processes broadcast intents containing UID information:

```java
int uid = intent.getIntExtra(Intent.EXTRA_UID, Process.INVALID_UID);
// ... used with system identity:
PackageInfo pi = getPackageManagerInternal().getPackageInfo(pkgName,
    PackageManager.GET_PERMISSIONS, Process.myUid(), UserHandle.getUserId(uid));
```

The UID from the broadcast is used under system identity for package queries. While system broadcasts are protected (only system_server can send `ACTION_PACKAGE_CHANGED`), if there's any path where a spoofed broadcast reaches this receiver, the UID parameter would be trusted.

Additionally, the `volatile` `CheckOpsDelegateDispatcher` creates a TOCTOU window between policy check and operation grant, as the delegate could change between these operations.

**Permission**: Requires broadcast spoofing capability (normally protected)  
**Impact**: Potential AppOps state manipulation for arbitrary UIDs  
**Bounty**: $500-$1,500

---

## Part E: Confirmed Secure (Audit Negative Results)

| Service | Result |
|---------|--------|
| ClipboardService cross-user | Properly gated by `ALLOW_FULL_ONLY`; cross-profile clipboard is by-design with admin controls |
| ClipboardService URI grants | Correct: checkDataOwner at set-time, grants from setter's UID |
| MediaProjection token replay | Properly mitigated: re-consent always required even for pre-U apps |
| UriGrants cross-user (specialCrossUserGrant) | Requires exported provider + still checks caller's own permissions + needs INTERACT_ACROSS_USERS |
| ContentProviderHelper clone redirect | Properly gated by system-configured profile properties; not caller-controllable |
| ClipboardService nested Intent URIs | Conservative design: only top-level URIs get grants (no escalation) |

---

## Round 24 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| MEDIUM-HIGH | 2 | Recursive ClipData grant (V-354), Vold CE re-unlock (V-357) |
| MEDIUM | 2 | Downloads grant persistence (V-355), Virtual device restriction bypass (V-359) |
| MEDIUM | 1 | Volume mount race (V-356) |
| MEDIUM | 1 | getMimeTypeFilterAsync bypass (V-358) |
| LOW-MEDIUM | 1 | AppOps confused deputy (V-360) |
| **Total** | **7** | |

**Estimated bounty this round**: $10,500 - $26,500

---

## Cumulative Project Statistics (Reports 01-35)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~354 | +7 | **~361** |
| HIGH/CRITICAL | ~52 | +0 | **~52** |
| Bounty estimate (low) | $689.9k | +$10.5k | **$700.4k** |
| Bounty estimate (high) | $1.695M | +$26.5k | **$1.722M** |

---

*Generated by FuzzMind/CoreBreaker Round 24 — 2026-04-30*
