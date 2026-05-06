# Report 26: Round 15 — CompanionDeviceManager, NotificationManager, AccountManager, ContentProvider

**Date**: 2026-04-29  
**Scope**: CompanionDeviceManagerService, NotificationManagerService, AccountManagerService, UriGrantsManagerService  
**Method**: 2 deep background agents  
**Previous**: Reports 01-25, ~288 variants

---

## Part A: CompanionDeviceManager + NotificationManager (8 findings)

### V-288: canPairWithoutPrompt Zero-Permission MAC Association Oracle [MEDIUM]

**File**: `services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java` (lines 685-694)

**Issue**: AIDL-exposed method with ZERO permission checks. Any app can determine if a specific package has a CDM association with a given MAC address, plus timing info (was it approved within the last 10 minutes).

```java
public boolean canPairWithoutPrompt(String packageName, String macAddress, int userId) {
    final AssociationInfo association =
            mAssociationStore.getFirstAssociationByAddress(userId, packageName, macAddress);
    if (association == null) return false;
    return System.currentTimeMillis() - association.getTimeApprovedMs()
            < PAIR_WITHOUT_PROMPT_WINDOW_MS;
}
```

**Attack**: Enumerate known BT/WiFi MAC addresses against target packages to build device association graph. Reveals user's wearables, car connections, IoT devices.

**Permission**: ZERO  
**Bounty**: $500-$1,500

---

### V-289: isCompanionApplicationBound Zero-Permission Presence Oracle [MEDIUM]

**File**: `CompanionDeviceManagerService.java` (lines 651-653)

**Issue**: No permission check. Any app can determine if any other package currently has a companion device actively bound (indicating device nearby/connected).

```java
public boolean isCompanionApplicationBound(String packageName, int userId) {
    return mCompanionAppBinder.isCompanionApplicationBound(userId, packageName);
}
```

**Attack**: Stalkerware detects when user's smartwatch disconnects. Cross-user probing possible.

**Permission**: ZERO  
**Bounty**: $500-$1,500

---

### V-290: CDM Privileged Listener Cross-App Notification Channel Silencing [HIGH]

**File**: `NotificationManagerService.java` (lines 6775-6786, 3217-3234)

**Issue**: A CDM companion app with NLS access (user consent) can set ANY other app's notification channel importance to `IMPORTANCE_NONE`, which triggers `cancelAllNotificationsInt` silently killing all notifications on that channel.

```java
public void updateNotificationChannelFromPrivilegedListener(INotificationListener token,
        String pkg, UserHandle user, NotificationChannel channel) {
    verifyPrivilegedListener(token, user, true);  // CDM app passes this
    updateNotificationChannelInt(pkg, getUidForPackageAndUser(pkg, user), channel, true);
}

// Then at line 3219:
if (channel.getImportance() == IMPORTANCE_NONE) {
    cancelAllNotificationsInt(MY_UID, MY_PID, pkg, channel.getId(), 0, 0,
            UserHandle.getUserId(uid), REASON_CHANNEL_BANNED);
}
```

**Attack**:
1. Malicious companion app obtains CDM association (user confirms BT pairing) + NLS
2. Silences banking 2FA notifications, security alert channels
3. Enables phishing: suppress "login from new device" notifications during account takeover

**Permission**: CDM association + NLS (both user-consent)  
**Impact**: Cross-app notification manipulation enabling downstream attacks  
**Bounty**: $3,000-$5,000

---

### V-291: CDM Watch Profile Global DND Control [MEDIUM-HIGH]

**File**: `NotificationManagerService.java` (lines 6156-6165)

**Issue**: `canManageGlobalZenPolicy()` allows CDM apps with WATCH or AUTOMOTIVE_PROJECTION profile to set global DND mode, bypassing implicit-rule restrictions.

```java
private boolean canManageGlobalZenPolicy(String callingPkg, int callingUid) {
    return !isCompatChangeEnabled || isCallerSystemOrSystemUi()
            || hasCompanionDevice(callingPkg, userId,
                    Set.of(DEVICE_PROFILE_WATCH, DEVICE_PROFILE_AUTOMOTIVE_PROJECTION));
}
```

**Attack**: Companion app with watch profile enables DND silencing all calls/messages/alarms.

**Permission**: `REQUEST_COMPANION_PROFILE_WATCH` (NORMAL permission!) + CDM + NLS  
**Bounty**: $1,000-$3,000

---

### V-292: Hardcoded "CDM" Encryption Key on Debug/Userdebug Builds [MEDIUM]

**File**: `services/companion/java/com/android/server/companion/transport/CompanionTransportManager.java` (lines 229-233)

**Issue**: On userdebug/eng builds, all CDM secure transport uses 3-byte key "CDM".

```java
} else if (Build.isDebuggable()) {
    final byte[] testKey = "CDM".getBytes(StandardCharsets.UTF_8);
    transport = new SecureTransport(associationId, fd, mContext, testKey, null);
}
```

**Permission**: Physical/network proximity to userdebug device  
**Bounty**: $500-$1,000

---

### V-293: enableSystemDataSync Consent Bypass [MEDIUM]

**File**: `CompanionDeviceManagerService.java` (lines 601-608)

**Issue**: `enableSystemDataSync` has no dedicated permission — only checks that caller owns the association. Arbitrary sync flags can be enabled post-association without user consent.

**Permission**: Own CDM association  
**Bounty**: $1,000-$2,000

---

### V-294: getConsolidatedNotificationPolicy Zero-Permission DND Info Leak [LOW-MEDIUM]

**File**: `NotificationManagerService.java` (lines 6383-6390)

**Issue**: No permission check. Reveals priority categories, sender priorities, suppressed visual effects.

**Permission**: ZERO  
**Bounty**: $250-$500

---

### V-295: CDM Privileged Listener Cross-App Channel Enumeration [MEDIUM]

**File**: `NotificationManagerService.java` (lines 6789-6798)

**Issue**: CDM companion with NLS can enumerate ALL notification channels of ANY package, revealing app feature structure, user per-channel settings, conversation IDs.

**Permission**: CDM + NLS  
**Bounty**: $500-$1,000

---

## Part B: AccountManager + ContentProvider (6 findings)

### V-296: AccountManagerService.invalidateAuthToken Zero-Permission DoS [LOW-MEDIUM]

**File**: `services/core/java/com/android/server/accounts/AccountManagerService.java` (lines 2627-2662)

**Issue**: `invalidateAuthToken` performs NO permission check. Any app can invalidate any authentication token for any account type if it knows the token value.

**Permission**: ZERO (but requires knowing token value)  
**Bounty**: $500-$1,000

---

### V-297: finishSessionAsUser appInfo Bundle Injection [MEDIUM]

**File**: `AccountManagerService.java` (lines 3840-3850)

**Issue**: Caller-controlled `appInfo` bundle is merged into the authenticated session bundle via `putAll()` BEFORE being passed to the authenticator. While KEY_CALLER_UID/PID are overwritten, other session keys can be spoofed.

```java
if (appInfo != null) {
    decryptedBundle.putAll(appInfo);  // Attacker-controlled overwrites session keys
}
decryptedBundle.putInt(KEY_CALLER_UID, callingUid);  // Only these are re-overwritten
decryptedBundle.putInt(KEY_CALLER_PID, pid);
```

**Attack**: Inject keys that confuse authenticator's session finalization (e.g., override callback URLs).

**Permission**: Must have started a valid session  
**Bounty**: $1,000-$3,000

---

### V-298: Account.accessId Auto-Grant on Deserialization [MEDIUM]

**File**: `AccountManagerService.java` (lines 6281-6283, 4969-4991)

**Issue**: Account's `accessId` UUID, when deserialized from a Parcel, automatically calls `onAccountAccessed()` which permanently grants account visibility. If UUID leaks, any app gains permanent account access.

**Attack**: Obtain accessId UUID via logs/shared storage/side channel → permanent account visibility escalation.

**Permission**: Must obtain UUID through side channel  
**Bounty**: $1,000-$3,000

---

### V-299: DownloadManager URI Grant Revocation Exemption [LOW-MEDIUM]

**File**: `services/core/java/com/android/server/uri/UriGrantsManagerService.java` (lines 536-540)

**Issue**: Non-persistable URI grants to DownloadManager authority are explicitly SKIPPED during revocation sweeps.

```java
if (Downloads.Impl.AUTHORITY.equals(perm.uri.uri.getAuthority())
        && !persistable) continue;  // "Hacky solution" — exempt from revocation!
```

**Permission**: Must first obtain DownloadManager URI grant  
**Bounty**: $500-$1,500

---

### V-300: ContentProvider.Transport.call() Systemic No-Permission Enforcement [MEDIUM]

**File**: `core/java/android/content/ContentProvider.java` (lines 630-645)

**Issue**: Unlike query/insert/update/delete/openFile which all call `enforceReadPermission()` or `enforceWritePermission()`, the `call()` method has NO permission enforcement at the Transport layer. Individual providers must self-enforce.

**Impact**: Systemic bypass of manifest-declared provider permissions through `call()` for providers that don't implement their own checks.

**Permission**: Varies per provider  
**Bounty**: $500-$5,000 per exploitable provider

---

### V-301: getAccountsByTypeForPackage Authenticator Visibility Enumeration [LOW]

**File**: `AccountManagerService.java` (lines 4780-4802)

**Issue**: An authenticator can use `getAccountsByTypeForPackage(ownType, victimPackage, ...)` to learn which of its accounts are visible to any arbitrary package, revealing user's per-package visibility preferences.

**Permission**: Must be registered authenticator  
**Bounty**: $250-$500

---

## Round 15 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| HIGH | 1 | CDM privileged listener notification channel silencing (V-290) |
| MEDIUM-HIGH | 1 | Watch profile DND control (V-291) |
| MEDIUM | 7 | MAC oracle, presence oracle, consent bypass, bundle injection, accessId auto-grant, call() bypass, hardcoded key |
| LOW-MEDIUM | 4 | DND info leak, invalidateAuthToken DoS, URI revocation exemption, visibility enum |
| **Total** | **14** | |

**Estimated bounty this round**: $11,000 - $27,500

---

## Cumulative Project Statistics (Reports 01-26)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~288 | +14 | **~302** |
| HIGH/CRITICAL | ~40 | +1 | **~41** |
| Bounty estimate (low) | $594.5k | +$11k | **$605.5k** |
| Bounty estimate (high) | $1.465M | +$27.5k | **$1.493M** |

**Milestone**: Crossed 300 total vulnerability variants.

---

*Generated by FuzzMind/CoreBreaker Round 15 — 2026-04-29*
