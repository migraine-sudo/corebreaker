# V-344/V-346: Private Space Zero-Permission Existence Detection and State Monitoring

## Vulnerability Details

Android 15 introduced **Private Space** — a hidden user profile (`PROFILE_API_VISIBILITY_HIDDEN`) designed so that no third-party app can detect its existence. However, the public `UserManager` API `getProfileIdsWithDisabled()` returns the Private Space userId to any zero-permission app in the same profile group. Combined with `isUserRunning()` / `isUserUnlocked()`, this enables real-time behavioral monitoring of Private Space usage.

**Root Cause**: When Private Space was implemented, Google created `getProfileIdsExcludingHidden()` for internal callers. But the original PUBLIC `getProfileIds()` was never updated — it hardcodes `excludeHidden=false`, exposing hidden profiles to any app without permission.

**Source**: `services/core/java/com/android/server/pm/UserManagerService.java`

```java
// Line 1568 — PUBLIC API, excludeHidden=false:
public int[] getProfileIds(@UserIdInt int userId, boolean enabledOnly) {
    return getProfileIds(userId, null, enabledOnly, /* excludeHidden */ false);
}

// Line 1666 — INTERNAL secure variant:
public int[] getProfileIdsExcludingHidden(@UserIdInt int userId, boolean enabledOnly) {
    return getProfileIds(userId, null, enabledOnly, /* excludeHidden */ true);
}
```

For same-profile-group queries, `isUserRunning()` and `isUserUnlocked()` skip permission checks entirely (line 2805):

```java
private void checkManageOrInteractPermissionIfCallerInOtherProfileGroup(...) {
    if (callingUserId == userId || isSameProfileGroupNoChecks(callingUserId, userId)) {
        return;  // NO CHECK — Private Space IS in same profile group!
    }
}
```

## Impact

### Attack Conditions
- Target device: Android 15+ with Private Space configured
- Attacker: Any installed app with **ZERO permissions** (no user prompt, no consent)
- No interaction required after install

### Impact Effects
1. **Existence detection**: Any app can discover that Private Space is configured (reveals user is hiding something)
2. **Real-time state monitoring**: App can poll `isUserRunning()`/`isUserUnlocked()` to know exactly when the user opens, unlocks, and closes their Private Space
3. **Behavioral pattern analysis**: By logging timestamps, stalkerware can build activity profiles ("victim accesses hidden apps at 11:47pm, 2:13am...")

### What CANNOT be accessed (boundaries confirmed)
- Cannot enumerate apps installed inside Private Space (`INTERACT_ACROSS_USERS` required)
- Cannot read Private Space data (contacts, files, etc.)
- Cannot determine which specific apps are hidden

### Attack Scenario: Stalkerware
1. Stalkerware installs as utility app (zero permissions, no user prompt)
2. Calls `getProfileIdsWithDisabled(0)` → returns `[0, 11]` — Private Space detected
3. Polls `isUserRunning(UserHandle.of(11))` every 2 seconds
4. Detects state transitions: `running=false` → `running=true, unlocked=true` → `running=false`
5. Reports to attacker: precise timestamps of all Private Space access

### Severity
- **Information Disclosure** — defeats Android 15 flagship privacy feature's core guarantee
- Enables real-time behavioral surveillance without any permission or user awareness

## Reproduction Steps

### Prerequisites
- Pixel device running Android 15+ (tested on Android 16, SDK 36)
- Private Space configured (Settings → Security & privacy → Private Space)

### App-based verification (definitive test)
1. Build and install `apk/` project (**ZERO permissions** in manifest)
2. Launch "Private Space Leak PoC"
3. Tap "4. Full Chain (All Steps)"
4. Observe output:
   - `Profile IDs returned: [0, 11]` — Private Space userId leaked
   - `running=true, unlocked=true` — Real-time state exposed
5. Lock Private Space, tap "4" again → observe `running=false`

### Minimal ADB verification
```bash
# Confirm Private Space exists:
adb shell pm list users
# Output: UserInfo{11:Private space:1010}

# From app context (UID 10486, zero permissions):
# getProfileIdsWithDisabled(0) returns [0, 11]
# isUserRunning(UserHandle.of(11)) returns true/false
# isUserUnlocked(UserHandle.of(11)) returns true/false
# ALL without SecurityException
```

**Expected (vulnerable)**: Profile IDs include Private Space userId; state queries return values
**Expected (patched)**: Only `[0]` returned; SecurityException on state queries for hidden profiles

## Device Fingerprint

| Field | Value |
|-------|-------|
| AOSP Source | `services/core/java/com/android/server/pm/UserManagerService.java` |
| Vulnerable Method (Detection) | `getProfileIds(int, boolean)` — line 1568, hardcoded `excludeHidden=false` |
| Vulnerable Method (Monitoring) | `isUserRunning(int)` / `isUserUnlocked(int)` — lines 2578-2587 |
| Permission Bypass | `checkManageOrInteractPermissionIfCallerInOtherProfileGroup()` — line 2805, returns without check for same profile group |
| Secure Variant (unused by public API) | `getProfileIdsExcludingHidden()` — line 1666 |
| Private Space User Type | `android.os.usertype.profile.PRIVATE` |
| Private Space Visibility | `PROFILE_API_VISIBILITY_HIDDEN` (0x4) |
| Affected Versions | Android 15+ (Private Space introduction) through Android 16 |
| Tested On | Pixel, Android 16 (SDK 36), `UserInfo{11:Private space:1010}` |
| PoC App UID | 10486 (regular untrusted app) |
| Permissions Required | NONE |

## Suggested Fix

`getProfileIds()` should filter hidden profiles for non-system callers:

```java
public int[] getProfileIds(int userId, boolean enabledOnly) {
    boolean excludeHidden = Binder.getCallingUid() >= Process.FIRST_APPLICATION_UID;
    return getProfileIds(userId, null, enabledOnly, excludeHidden);
}
```

`isUserRunning()`/`isUserUnlocked()` should enforce `INTERACT_ACROSS_USERS` when the target has `PROFILE_API_VISIBILITY_HIDDEN`, regardless of profile group membership.
