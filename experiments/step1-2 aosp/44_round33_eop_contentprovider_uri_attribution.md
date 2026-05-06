# Report 44: Round 33 — EoP: ContentProvider Attribution Bug, Cross-User URI Grant Escalation, BiometricService HAL Trust

**Date**: 2026-04-30  
**Scope**: ContentProviderHelper, UriGrantsManagerService, BiometricService, DevicePolicyManagerService, InputMethodManagerService  
**Method**: Deep background agents + manual source verification  
**Previous**: Reports 01-43, ~421 variants

---

## Part A: ContentProviderHelper (2 findings)

### V-421: checkContentProviderUriPermission Misattributes Package After clearCallingIdentity — System Package Trust Escalation [MEDIUM-HIGH/EoP]

**File**: `services/core/java/com/android/server/am/ContentProviderHelper.java` (lines 1196-1201)

**Issue**: After `Binder.clearCallingIdentity()`, the code calls `Binder.getCallingUid()` which returns `SYSTEM_UID` (1000) instead of the original caller's UID. The resolved package ("android") is then placed in the `AttributionSource`:

```java
final long ident = Binder.clearCallingIdentity();
try {
    holder = getContentProviderExternalUnchecked(name, null, callingUid, ...);
    if (holder != null) {
        // BUG: After clearCallingIdentity, getCallingUid() returns SYSTEM_UID!
        final AndroidPackage androidPackage = mService.getPackageManagerInternal()
                .getPackage(Binder.getCallingUid());  // Returns "android" package!
        
        final AttributionSource attributionSource = new AttributionSource(
                callingUid,                          // Correct UID
                androidPackage.getPackageName(),      // WRONG: "android" instead of caller's package
                null);
        
        // Provider sees request from "android" package with non-system UID
        return holder.provider.checkUriPermission(attributionSource, uri, uid, modeFlags);
    }
}
```

This creates an `AttributionSource` with the correct `callingUid` but package name = "android" (the framework package). When passed to `holder.provider.checkUriPermission()`, the provider sees a request attributed to the system package.

**Attack**:
1. App triggers a URI permission check through the `UriGrantsManagerService.checkHoldingPermissionsInternalUnlocked` path (which calls `checkContentProviderUriPermission` when `pi.forceUriPermissions` is true)
2. The ContentProvider receives `checkUriPermission` with `AttributionSource(uid=attackerUid, packageName="android")`
3. If the provider trusts package="android" with special access (e.g., returns PERMISSION_GRANTED for system callers based on package name), access is granted
4. Potential targets: MediaProvider and ContactsProvider2 (both use `forceUriPermissions`)

**Permission**: ZERO (requires existing URI grant to trigger the code path)  
**Impact**: If a forceUriPermissions provider trusts the "android" package name, arbitrary URI access escalation  
**Bounty**: $1,500-$5,000

---

### V-422: checkAuthorityGrants Escalates Single Cross-User URI Grant to Full Provider Access [MEDIUM/EoP]

**File**: `services/core/java/com/android/server/uri/UriGrantsManagerService.java` — `checkAuthorityGrantsLocked`

**Issue**: When checking whether a caller has access to a cross-user ContentProvider, `checkAuthorityGrants` only checks if ANY URI grant exists matching the authority — not the specific path:

```java
private boolean checkAuthorityGrantsLocked(int callingUid, ProviderInfo cpi, int userId,
        boolean checkUser) {
    final ArrayMap<GrantUri, UriPermission> perms = mGrantedUriPermissions.get(callingUid);
    if (perms != null) {
        for (int i = perms.size() - 1; i >= 0; i--) {
            GrantUri grantUri = perms.keyAt(i);
            if (grantUri.sourceUserId == userId || !checkUser) {
                if (matchesProvider(grantUri.uri, cpi)) {
                    return true;  // ANY matching grant = full provider access!
                }
            }
        }
    }
    return false;
}
```

This is used in `checkContentProviderPermission()` for cross-user access:
```java
if (mService.mUgmInternal.checkAuthorityGrants(callingUid, cpi, tmpTargetUserId, checkUser)) {
    return null;  // ALLOWED - grants full provider access
}
```

**Attack**:
1. App on user 0 receives legitimate URI grant to `content://10@com.example.provider/public/item1` (via cross-user share intent)
2. App calls `getContentResolver().acquireContentProviderClient(Uri.parse("content://10@com.example.provider"))`
3. `checkAuthorityGrants` finds the existing grant → returns true → full provider access granted
4. App can now query/insert/update/delete ANY path on the cross-user provider, not just the granted URI
5. The provider's own path-level permissions are the only remaining defense

**Permission**: Must have at least one URI grant from the target cross-user provider  
**Impact**: Single URI grant escalates to full cross-user provider access at system level  
**Bounty**: $1,000-$3,000

---

## Part B: BiometricService (1 finding)

### V-423: Weak Biometric HAL Can Dismiss BiometricPrompt Without Strong Authentication [LOW-MEDIUM/EoP]

**File**: `services/core/java/com/android/server/biometrics/BiometricService.java`

**Issue**: When a weak biometric sensor's HAL reports success, it cannot be used for crypto operations (properly gated by `isStrongBiometric(sensorId)`), but it CAN dismiss the BiometricPrompt UI. The `onAuthenticationSucceeded` handler:

```java
session.onAuthenticationSucceeded(sensorId, isStrongBiometric(sensorId), token);
```

If a non-strong biometric sensor (face unlock without depth, or a downgraded sensor) falsely reports success, the BiometricPrompt dismisses even though the authentication shouldn't be considered secure. Apps using `BiometricPrompt` with `BIOMETRIC_STRONG` authenticator requirement expect only strong biometrics to pass, but if the sensor was once strong and was downgraded (e.g., via `resetLockout`), there's a window where weak authentication could be accepted.

**Mitigations**: The `BiometricStrengthController` properly downgrades sensors, and apps checking `authenticators & BIOMETRIC_STRONG` should see the correct strength. The risk is during sensor strength transition windows.

**Permission**: Requires compromised/spoofed biometric HAL (very high bar)  
**Impact**: BiometricPrompt dismissal without proper authentication level  
**Bounty**: $500-$1,500

---

## Part C: InputMethodManagerService — Confirmed Hardened (No findings)

The IMMS audit found **no exploitable EoP vulnerabilities**. Key hardening measures:

| Defense | Detail |
|---------|--------|
| `setInputMethod` removed from AIDL | Primary IME switching vector eliminated |
| Cross-user isolation | Per-user binding controllers, `bindServiceAsUser` enforcement |
| IME picker anti-tapjacking | `setHideOverlayWindows(true)` on picker dialog |
| Window type enforcement | Token-based TYPE_INPUT_METHOD management |
| Content URI scoping | Read-only grants with automatic revocation |

---

## Part D: DevicePolicyManagerService — Confirmed Hardened (No findings)

The DPMS audit (~24,900 lines) found **no exploitable EoP vulnerabilities**. Key defenses:

| Defense | Detail |
|---------|--------|
| CallerIdentity binding | UID/package verified at method entry |
| DPC type hierarchy | PO cannot reach DO paths |
| getLockObject() synchronization | Prevents TOCTOU races |
| CROSS_USER_PERMISSIONS map | Appropriate cross-user enforcement |
| Transfer ownership journaling | Crash-safe with revert capability |
| Delegation scope isolation | Delegates cannot escalate own scope |

---

## Part E: Confirmed Secure (Additional Audit Negative Results)

| Service | Result |
|---------|--------|
| UriGrantsManagerService cross-user grant | INTERACT_ACROSS_USERS properly enforced at line 1111 |
| grantUriPermissionFromOwner confused deputy | ExternalToken extends Binder prevents cross-process token forgery |
| takePersistableUriPermission cross-user | Grant lookup uses caller's own UID — can only take own grants |
| ContentProviderHelper publishContentProviders | Provider name must match pre-assigned mapping — no injection |
| DPMS profile owner vs device owner | Type hierarchy with independent checks on each path |
| DPMS cross-user admin operations | hasFullCrossUsersPermission checks on all cross-user paths |
| DPMS delegation escalation | setDelegatedScopes requires PO/DO; delegates cannot self-escalate |
| DPMS wipeData bypass | Multi-layer checks + DISALLOW_FACTORY_RESET defense-in-depth |
| IMMS IME switching | setInputMethod removed from public AIDL interface |
| IMMS cross-user IME access | Per-user state + INTERACT_ACROSS_USERS_FULL enforcement |
| IMMS direct boot capture | System IMEs preferred as defaults + non-persistent settings during direct boot |
| BiometricService cross-user | Strictly per-userId state throughout |
| BiometricService result replay | IBiometricSensorReceiver is system-internal; not exposed to apps |

---

## Round 33 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| MEDIUM-HIGH | 1 | Attribution misattribution bug (V-421) |
| MEDIUM | 1 | URI grant → full provider access (V-422) |
| LOW-MEDIUM | 1 | Weak biometric prompt dismissal (V-423) |
| HARDENED (no findings) | 2 | IMMS, DPMS |
| **Total new variants** | **3** | |

**Estimated bounty this round**: $3,000 - $9,500

---

## Cumulative Project Statistics (Reports 01-44)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~421 | +3 | **~424** |
| HIGH/CRITICAL | ~57 | +0 | **~57** |
| Bounty estimate (low) | $816.9k | +$3k | **$819.9k** |
| Bounty estimate (high) | $2.046M | +$9.5k | **$2.055M** |

---

## V-421 VRP Report Draft

### Title: ContentProviderHelper.checkContentProviderUriPermission Uses Binder.getCallingUid() After clearCallingIdentity — Wrong Package in AttributionSource

### Summary
In `ContentProviderHelper.checkContentProviderUriPermission()`, after calling `Binder.clearCallingIdentity()`, the code calls `Binder.getCallingUid()` (which now returns SYSTEM_UID) to resolve the caller's package. This causes the `AttributionSource` passed to `ContentProvider.checkUriPermission()` to contain packageName="android" instead of the actual caller's package name. Providers that check the package name in the AttributionSource may grant elevated access to the system package, enabling unauthorized URI access.

### Root Cause
```java
final long ident = Binder.clearCallingIdentity();
try {
    // ...
    final AndroidPackage androidPackage = mService.getPackageManagerInternal()
            .getPackage(Binder.getCallingUid());  // BUG: returns SYSTEM_UID after clear!
    final AttributionSource attributionSource = new AttributionSource(
            callingUid, androidPackage.getPackageName(), null);
    // attributionSource has correct uid but wrong package ("android")
```

Should use `callingUid` (which is stored correctly from before the clear) instead of `Binder.getCallingUid()`.

### Steps to Reproduce
1. Find a ContentProvider with `forceUriPermissions=true` that grants special access to package "android"
2. Trigger `checkHoldingPermissionsInternalUnlocked` → `checkContentProviderUriPermission` flow (via URI grant check)
3. Provider receives `checkUriPermission(AttributionSource(uid=attackerUid, pkg="android"), ...)`
4. Provider trusts "android" package → returns PERMISSION_GRANTED
5. Caller gains unauthorized URI access

### Impact
- Potential URI access escalation on forceUriPermissions providers (MediaProvider, ContactsProvider2)
- The bug is confirmed — the wrong UID is used for package resolution after clearCallingIdentity
- Practical exploitability depends on whether target providers check package name vs UID

### Severity
MEDIUM-HIGH (Confirmed code bug in system_server with potential for URI permission bypass)

---

*Generated by FuzzMind/CoreBreaker Round 33 — 2026-04-30*
