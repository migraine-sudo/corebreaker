# Report 27: Round 16 — ActivityManagerService, AutofillManager, CredentialManager, DeviceIdleController

**Date**: 2026-04-29  
**Scope**: ActivityManagerService, AutofillManagerService, CredentialManagerService, DeviceIdleController, DevicePolicyManager  
**Method**: 3 deep background agents + manual source audit  
**Previous**: Reports 01-26, ~302 variants

---

## Part A: CredentialManagerService (2 findings)

### V-302: getCandidateCredentials Missing enforceCallingPackage — Zero-Perm Credential Enumeration [HIGH]

**File**: `services/credentials/java/com/android/server/credentials/CredentialManagerService.java` (lines 486-539)

**Issue**: `getCandidateCredentials()` does NOT call `enforceCallingPackage(callingPackage, callingUid)` — compare to `executeGetCredential()` (line 554) which correctly enforces. This allows any app to spoof `callingPackage` to any arbitrary package name. Additionally, `validateGetCredentialRequest(request)` is not called, so `request.getOrigin()` can be set to any website without `CREDENTIAL_MANAGER_SET_ORIGIN` permission.

```java
public ICancellationSignal getCandidateCredentials(
        GetCredentialRequest request,
        IGetCandidateCredentialsCallback callback,
        IBinder clientBinder,
        final String callingPackage) {
    final int userId = UserHandle.getCallingUserId();
    final int callingUid = Binder.getCallingUid();
    // NOTE: No enforceCallingPackage(callingPackage, callingUid) call!
    // NOTE: No validateGetCredentialRequest(request) call!
    
    final GetCandidateRequestSession session =
            new GetCandidateRequestSession(
                    getContext(), mSessionManager, mLock, userId, callingUid,
                    callback, request,
                    constructCallingAppInfo(callingPackage, userId, request.getOrigin()),
                    getEnabledProvidersForUser(userId), ...);
```

**Compare to `executeGetCredential` (line 554)**:
```java
enforceCallingPackage(callingPackage, callingUid);  // Present here
validateGetCredentialRequest(request);               // Present here
```

**Attack**:
1. Malicious app binds to ICredentialManager (available via `Context.CREDENTIAL_SERVICE`)
2. Calls `getCandidateCredentials()` with `callingPackage = "com.whatsapp"` or any victim
3. Sets `request.getOrigin()` to `https://accounts.google.com` (no CREDENTIAL_MANAGER_SET_ORIGIN check)
4. `constructCallingAppInfo()` builds CallingAppInfo with victim's package + signing cert
5. Credential providers see a request appearing to come from the victim app
6. Providers return matching credential metadata (passkeys, passwords, types)

**Impact**: Cross-app credential enumeration. Reveals what credentials exist for any app/origin.

**Permission**: ZERO  
**Bounty**: $5,000-$10,000

---

### V-303: registerCredentialDescription Missing Provider Validation [MEDIUM]

**File**: `CredentialManagerService.java` (lines 1041-1057) + `CredentialDescriptionRegistry.java` (lines 130-148)

**Issue**: Any app can call `registerCredentialDescription` to register credential descriptions without verifying the caller is actually an enabled credential provider. The `NonCredentialProviderCallerException` is declared but never thrown.

```java
public void registerCredentialDescription(
        RegisterCredentialDescriptionRequest request, String callingPackage)
        throws IllegalArgumentException, NonCredentialProviderCallerException {
    if (!isCredentialDescriptionApiEnabled()) {
        throw new UnsupportedOperationException("Feature not supported");
    }
    enforceCallingPackage(callingPackage, Binder.getCallingUid());
    CredentialDescriptionRegistry session =
            CredentialDescriptionRegistry.forUser(UserHandle.getCallingUserId());
    session.executeRegisterRequest(request, callingPackage);
    // NO check that callingPackage is an enabled credential provider!
}
```

**Attack**: Register credential descriptions for common types → system routes credential requests to malicious app during `getFilteredResultFromRegistry` → credential phishing.

**Permission**: ZERO (requires feature flag enabled)  
**Bounty**: $1,000-$3,000

---

## Part B: ActivityManagerService (2 findings)

### V-304: getProcessPss() NullPointerException — system_server Crash [MEDIUM]

**File**: `services/core/java/com/android/server/am/ActivityManagerService.java` (line 4061)

**Issue**: When `proc` is null (PID not in `mPidsSelfLocked`) AND `allUids=true` (has REAL_GET_TASKS) AND `allUsers=false` (lacks INTERACT_ACROSS_USERS_FULL), the expression `proc.uid` throws NPE in system_server.

```java
if (!allUids || (!allUsers && UserHandle.getUserId(proc.uid) != userId)) {
    //                                                ^^^^^^^^ NPE when proc is null!
    continue;
}
```

**Compare to `getProcessMemoryInfo()` (line 3995) which correctly handles null**:
```java
final int targetUid = (proc != null) ? proc.uid : -1;
final int targetUserId = (proc != null) ? UserHandle.getUserId(targetUid) : -1;
```

**Attack**: Pre-installed privileged app (launcher) with REAL_GET_TASKS but not INTERACT_ACROSS_USERS_FULL calls `ActivityManager.getProcessPss(new int[]{99999})` → crashes system_server → soft reboot.

**Permission**: REAL_GET_TASKS (signature|privileged)  
**Impact**: Local DoS — system_server crash  
**Bounty**: $500-$1,000

---

### V-305: registerUidObserver/addUidToObserver Cross-User Process State Monitoring [MEDIUM-HIGH]

**File**: `ActivityManagerService.java` (lines 8006-8054)

**Issue**: `addUidToObserver(IBinder observerToken, String callingPackage, int uid)` accepts arbitrary UID without cross-user validation. An app with PACKAGE_USAGE_STATS (user-grantable via Settings) can monitor process state changes for UIDs in OTHER user profiles.

```java
public void addUidToObserver(IBinder observerToken, String callingPackage, int uid) {
    if (!hasUsageStatsPermission(callingPackage)) {
        enforceCallingPermission(PACKAGE_USAGE_STATS, "registerUidObserver");
    }
    mUidObserverController.addUidToObserver(observerToken, uid);
    // NO handleIncomingUser() check on uid's userId!
}
```

**Attack**:
1. App requests Usage Stats permission (user grants via Settings > Special Access)
2. Calls `registerUidObserverForUids(observer, UID_OBSERVER_ACTIVE|UID_OBSERVER_PROCSTATE, 0, pkg, new int[]{workProfileUid})`
3. Receives real-time notifications of work profile app activity
4. Determines exactly when enterprise apps (email, calendar) are in use
5. Also: `isUidActive(uid)`, `getUidProcessState(uid)`, `getUidProcessCapabilities(uid)` — all cross-user without check

**Permission**: PACKAGE_USAGE_STATS (user-grantable appop)  
**Impact**: Cross-user process state information disclosure (work profile monitoring)  
**Bounty**: $2,000-$4,000

---

## Part C: DeviceIdleController (2 findings)

### V-306: getAppIdTempWhitelist Zero-Permission Real-Time Push Notification Oracle [MEDIUM]

**File**: `services/core/java/com/android/server/DeviceIdleController.java` (lines 2229-2243)

**Issue**: `getAppIdTempWhitelist()` returns int[] of all app IDs currently temp-whitelisted (meaning they recently received high-priority FCM push). NO permission check, NO `filterAppAccess()` applied.

```java
public int[] getAppIdTempWhitelist() {
    return getAppIdTempWhitelistInternal();
}
// Compare to string-based getFullPowerWhitelistExceptIdle() which requires 
// DEVICE_POWER or CHANGE_DEVICE_IDLE_TEMP_WHITELIST
```

**Attack**:
1. Any zero-permission app polls `getAppIdTempWhitelist()` periodically
2. When a new appId appears → that app just received a push notification
3. Reveals real-time messaging activity for ANY app on the device
4. Detect when user receives messages on Signal, WhatsApp, banking alerts

**Permission**: ZERO  
**Impact**: Real-time activity oracle revealing push notification receipt for all apps  
**Bounty**: $1,000-$2,000

---

### V-307: getAppIdWhitelist Zero-Permission Battery Optimization Bypass List [LOW-MEDIUM]

**File**: `DeviceIdleController.java` (adjacent to V-306)

**Issue**: `getAppIdWhitelist()` returns int[] of permanently whitelisted app IDs without permission check. Reveals which apps have battery optimization disabled.

**Permission**: ZERO  
**Bounty**: $500-$1,000

---

## Part D: AutofillManagerService (2 findings)

### V-308: Mutable PendingIntent in Autofill Delayed Fill [LOW-MEDIUM]

**File**: `services/autofill/java/com/android/server/autofill/Session.java` (lines 1162-1184)

**Issue**: `createPendingIntent()` uses `PendingIntent.FLAG_MUTABLE` for the delayed fill broadcast. While the autofill service is already trusted, this is a defense-in-depth violation.

```java
pendingIntent = PendingIntent.getBroadcast(
        mContext, this.id, intent,
        PendingIntent.FLAG_MUTABLE          // Should be IMMUTABLE
                | PendingIntent.FLAG_ONE_SHOT
                | PendingIntent.FLAG_CANCEL_CURRENT);
```

**Permission**: Must be selected autofill service  
**Bounty**: $500-$1,000

---

### V-309: getCredentialProviderServices Cross-User userId Without Validation [LOW-MEDIUM]

**File**: `CredentialManagerService.java` (lines 923-936)

**Issue**: `userId` parameter passed to `getCredentialProviderServices` is not validated against the caller via `handleIncomingUser()`. An app with QUERY_ALL_PACKAGES can enumerate credential providers for other user profiles.

**Permission**: QUERY_ALL_PACKAGES or LIST_ENABLED_CREDENTIAL_PROVIDERS  
**Bounty**: $500-$1,500

---

## Part E: Manual Audit — AudioService (1 finding)

### V-310: WifiInfo Frequency/RSSI/IP Not Redacted Without Location — Coarse Location Oracle [MEDIUM]

**File**: `packages/modules/Wifi/framework/java/android/net/wifi/WifiInfo.java` (lines 605-610)

**Issue**: In the redaction copy constructor, `mFrequency`, `mRssi`, `mIpAddress`, `mLinkSpeed`, `mTxLinkSpeed`, `mRxLinkSpeed` are all copied unconditionally — NOT gated by `shouldRedactLocationSensitiveFields()`. Available to any app with `ACCESS_WIFI_STATE` (normal permission).

```java
// Line 605-610 in WifiInfo(WifiInfo source, long redactions):
mRssi = source.mRssi;               // NOT redacted!
mLinkSpeed = source.mLinkSpeed;      // NOT redacted!
mTxLinkSpeed = source.mTxLinkSpeed;  // NOT redacted!
mRxLinkSpeed = source.mRxLinkSpeed;  // NOT redacted!
mFrequency = source.mFrequency;      // NOT redacted! → coarse location
mIpAddress = source.mIpAddress;      // NOT redacted! → network fingerprint
```

**Attack**:
- `mFrequency` reveals WiFi channel (2.4GHz vs 5GHz band + specific channel) — combined with public AP databases, this is a coarse location indicator
- `mRssi` reveals signal strength — distance from AP
- `mIpAddress` reveals local network IP assignment
- All available with only `ACCESS_WIFI_STATE` (auto-granted normal permission)

**Note**: SSID and BSSID ARE properly redacted. This may be considered "by design" but the frequency+RSSI combination is known to enable coarse geolocation without location permission (published research).

**Permission**: ACCESS_WIFI_STATE (normal permission, no location)  
**Bounty**: $500-$2,000

---

## Round 16 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 1 | getCandidateCredentials zero-perm credential enumeration (V-302) |
| MEDIUM-HIGH | 1 | Cross-user UID observer without cross-user permission (V-305) |
| MEDIUM | 4 | registerCredentialDescription (V-303), getProcessPss NPE (V-304), push notification oracle (V-306), WiFi freq/RSSI leak (V-310) |
| LOW-MEDIUM | 3 | AppId whitelist leak (V-307), mutable PendingIntent (V-308), cross-user credential providers (V-309) |
| **Total** | **9** | |

**Estimated bounty this round**: $11,500 - $25,500

---

## Cumulative Project Statistics (Reports 01-27)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~302 | +9 | **~311** |
| HIGH/CRITICAL | ~41 | +1 | **~42** |
| Bounty estimate (low) | $605.5k | +$11.5k | **$617k** |
| Bounty estimate (high) | $1.493M | +$25.5k | **$1.518M** |

---

*Generated by FuzzMind/CoreBreaker Round 16 — 2026-04-29*
