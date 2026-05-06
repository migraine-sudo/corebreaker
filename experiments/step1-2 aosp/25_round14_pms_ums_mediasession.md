# Report 25: Round 14 — PackageInstallerSession, UserManagerService, CrossProfileApps, MediaSession

**Date**: 2026-04-29  
**Scope**: PackageInstallerSession/Service, UserManagerService, CrossProfileAppsServiceImpl, MediaSessionService  
**Method**: 2 deep background agents + manual source audit  
**Previous**: Reports 01-24, ~279 variants

---

## Part A: PackageInstallerSession (4 findings from agent)

### V-279: PackageInstallerSession.addChildSessionId Cross-Ownership DoS [MEDIUM-HIGH]

**File**: `services/core/java/com/android/server/pm/PackageInstallerSession.java` (lines 5069-5122)

**Issue**: `addChildSessionId(int childSessionId)` only validates that the PARENT session caller is the owner (`assertCallerIsOwnerOrRoot()`) but performs NO ownership check on the child session being added. Any app can claim another app's install session as its child, permanently locking it.

```java
public void addChildSessionId(int childSessionId) {
    final PackageInstallerSession childSession = mSessionProvider.getSession(childSessionId);
    // NO ownership check on childSession!
    try {
        acquireTransactionLock();
        childSession.acquireTransactionLock();
        if (!childSession.canBeAddedAsChild(sessionId)) { /* only checks non-sealed state */ }
        synchronized (mLock) {
            assertCallerIsOwnerOrRoot();  // Only checks PARENT ownership!
            childSession.setParentSessionId(this.sessionId);
            mChildSessions.put(childSessionId, childSession);
        }
    }
}
```

**Attack**:
1. Attacker creates a multi-package parent session
2. Enumerates victim's session IDs via `PackageInstaller.getAllSessions()`
3. Calls `addChildSessionId(victimSessionId)` — victim's session now has parentSessionId set
4. Victim cannot `commit()` or `abandon()` (both call `assertNotChild` which blocks)
5. Session stuck for 3 days (MAX_AGE_MILLIS), attack repeatable

**Additional**: No userId check — cross-user session DoS possible if session IDs are known.

**Permission**: ZERO (any app can create sessions)  
**Impact**: Denial of Service — prevents app installs/updates  
**Bounty**: $3,000-$5,000

---

### V-280: PackageInstallerSession.requestChecksums Path Traversal — File Checksum Oracle [MEDIUM]

**File**: `PackageInstallerSession.java` (lines 1768-1783)

**Issue**: `requestChecksums(@NonNull String name, ...)` passes `name` directly to `new File(stageDir, name)` without any validation. Compare with `openWrite()` which correctly calls `FileUtils.isValidExtFilename(name)`.

```java
public void requestChecksums(@NonNull String name, ...) {
    assertCallerIsOwnerRootOrVerifier();
    final File file = new File(stageDir, name);  // NO validation! Path traversal!
    mPm.requestFileChecksums(file, ...);
}
```

**Attack**:
1. Create install session (zero permissions)
2. Call `requestChecksums("../../system/build.prop", TYPE_WHOLE_SHA256, 0, null, listener)`
3. stageDir = `/data/app/vmdl<ID>.tmp/` → resolves to `/data/system/build.prop`
4. system_server computes and returns SHA256 of the target file
5. Oracle attacks: confirm file contents, fingerprint device state, verify patch levels

**Permission**: ZERO (session owner = creator)  
**Impact**: Information disclosure via hash comparison oracle  
**Bounty**: $2,000-$4,000

---

### V-281: PackageInstallerSession.transfer() Read FD Persistence [LOW-MEDIUM]

**File**: `PackageInstallerSession.java` (lines 2500-2507)

**Issue**: After `transfer()`, existing `RevocableFileDescriptor` objects opened by the original owner remain valid. `transfer()` calls `sealLocked()` which checks write FDs but not read FDs.

**Permission**: Session owner + target with INSTALL_PACKAGES  
**Bounty**: $500-$1,000

---

### V-282: disableVerificationForUid Race Condition [LOW]

**File**: `PackageInstallerService.java` (lines 226, 777-789)

**Issue**: `mDisableVerificationForUid` is `volatile` but lacks atomic read-then-reset. Concurrent session creation can race on the one-shot verification bypass.

**Permission**: system/root/shell only  
**Bounty**: $0-$500

---

## Part B: UserManagerService / Multi-User (4 findings from agent)

### V-283: Zero-Permission Private Space Detection via getUserSerialNumber + isQuietModeEnabled [HIGH]

**File**: `UserManagerService.java` (lines 7033-7037, 2082-2091)

**Issue**: Two fully public SDK APIs with ZERO permission checks enable detection of Private Space:

```java
// Line 7033 — NO PERMISSION CHECK
public int getUserSerialNumber(int userId) {
    synchronized (mUsersLock) {
        final UserInfo userInfo = getUserInfoLU(userId);
        return userInfo != null ? userInfo.serialNumber : -1;
    }
}

// Line 2082 — NO PERMISSION CHECK  
public boolean isQuietModeEnabled(int userId) {
    synchronized (mPackagesLock) {
        UserInfo info = getUserInfoLU(userId);
        if (info == null || !info.isProfile()) return false;
        return info.isQuietModeEnabled();
    }
}
```

**Attack**:
```java
for (int userId = 0; userId <= 20; userId++) {
    long serial = um.getSerialNumberForUser(UserHandle.of(userId));
    if (serial != -1) {
        boolean quiet = um.isQuietModeEnabled(UserHandle.of(userId));
        // serial != -1 → user exists; quiet=true → locked Private Space or work profile
    }
}
```

**Impact**: Completely undermines Android 15's Private Space privacy model. Any zero-permission app can detect:
- All existing user profiles
- Whether Private Space exists
- Whether Private Space is currently locked/unlocked
- Work profile presence and lock state

**Permission**: ZERO  
**Bounty**: $3,000-$5,000

---

### V-284: CrossProfileAppsServiceImpl checkCallingOrSelfPermission Return Value Ignored [MEDIUM-HIGH]

**File**: `CrossProfileAppsServiceImpl.java` (lines 604-610, 627-634)

**Issue**: Classic check-vs-enforce bug. `mContext.checkCallingOrSelfPermission()` returns an int but the return value is NEVER checked. Should be `enforceCallingOrSelfPermission()`.

```java
// Line 604 — RETURN VALUE IGNORED!
public boolean canConfigureInteractAcrossProfiles(int userId, String packageName) {
    if (mInjector.getCallingUserId() != userId) {
        mContext.checkCallingOrSelfPermission(INTERACT_ACROSS_USERS); // No-op!
    }
    return canConfigureInteractAcrossProfiles(packageName, userId);
}

// Line 627 — SAME BUG
public boolean canUserAttemptToConfigureInteractAcrossProfiles(int userId, String packageName) {
    if (mInjector.getCallingUserId() != userId) {
        mContext.checkCallingOrSelfPermission(INTERACT_ACROSS_USERS); // No-op!
    }
    return canUserAttemptToConfigureInteractAcrossProfiles(packageName, userId);
}
```

**Attack**: Any app can call these methods with arbitrary userId to learn:
- Whether specific packages are installed in other profiles
- Whether target users have profile groups
- Whether packages are cross-profile allowlisted

**Permission**: ZERO (Binder-accessible service)  
**Bounty**: $2,000-$4,000

---

### V-285: hasUserRestriction User Existence Oracle [LOW-MEDIUM]

**File**: `UserManagerService.java` (lines 3515-3521)

**Issue**: `userExists()` check before permission check creates timing oracle — returns false for non-existent users, throws SecurityException for existing users in other profile groups.

**Permission**: ZERO  
**Bounty**: $500-$1,000

---

### V-286: Foreground Launcher Can Force-Lock Private Space Without Confirmation [MEDIUM]

**File**: `UserManagerService.java` (lines 1825-1872, 1950-1986)

**Issue**: `ensureCanModifyQuietMode` allows the foreground default launcher to enable quiet mode (lock) any profile without credential verification. Combined with V-283 (Private Space detection), a malicious launcher can repeatedly lock Private Space.

**Permission**: Default launcher role (no Android permission)  
**Impact**: DoS against Private Space privacy feature  
**Bounty**: $1,000-$2,000

---

## Part C: Manual Audit — MediaSessionService (1 finding)

### V-287: dispatchMediaKeyEvent/dispatchVolumeKeyEvent — asSystemService Flag Unchecked [MEDIUM]

**File**: `services/core/java/com/android/server/media/MediaSessionService.java` (lines 1774-1830, 2143-2220)

**Issue**: `dispatchMediaKeyEvent(packageName, boolean asSystemService, keyEvent, needWakeLock)` and `dispatchVolumeKeyEvent(packageName, opPackageName, boolean asSystemService, keyEvent, stream, musicOnly)` accept `asSystemService` boolean directly from the caller via Binder IPC (AIDL interface `ISessionManager`) without any server-side permission validation.

When `asSystemService=true`, volume adjustments use system_server's UID:
```java
if (asSystemService) {
    callingOpPackageName = mContext.getOpPackageName();
    callingUid = Process.myUid();      // system_server UID!
    callingPid = Process.myPid();
} else {
    callingOpPackageName = opPackageName;
    callingUid = uid;
    callingPid = pid;
}
mAudioManager.adjustSuggestedStreamVolumeForUid(suggestedStream,
    direction, flags, callingOpPackageName, callingUid, callingPid, ...);
```

**Attack**: Any app can call `ISessionManager.dispatchVolumeKeyEvent(pkg, opPkg, true, volumeKeyEvent, stream, musicOnly)` via Binder reflection, causing volume adjustments as system_server.

**Impact**:
- Bypass per-app volume restrictions
- Bypass DND volume policies (system UID exempt from some checks)
- Control audio stream volumes without MODIFY_AUDIO_SETTINGS
- Potential to mute/unmute ringer

**Permission**: ZERO (AIDL interface accessible, `@hide` but no server-side enforcement)  
**Bounty**: $1,000-$3,000

---

## Round 14 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 1 | Private Space zero-perm detection (V-283) |
| MEDIUM-HIGH | 2 | Install session hijack DoS (V-279), CrossProfileApps permission bypass (V-284) |
| MEDIUM | 3 | requestChecksums path traversal (V-280), launcher Private Space lock (V-286), MediaSession asSystemService (V-287) |
| LOW-MEDIUM | 2 | hasUserRestriction oracle (V-285), transfer FD persistence (V-281) |
| LOW | 1 | disableVerification race (V-282) |
| **Total** | **9** | |

**Estimated bounty this round**: $13,500 - $25,500

---

## Cumulative Project Statistics (Reports 01-25)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~279 | +9 | **~288** |
| HIGH/CRITICAL | ~39 | +1 | **~40** |
| Bounty estimate (low) | $581k | +$13.5k | **$594.5k** |
| Bounty estimate (high) | $1.44M | +$25.5k | **$1.465M** |

---

*Generated by FuzzMind/CoreBreaker Round 14 — 2026-04-29*
