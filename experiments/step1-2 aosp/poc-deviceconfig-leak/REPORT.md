# V-415: SettingsProvider DeviceConfig Zero-Permission Read — Full System Configuration Disclosure

## Vulnerability Details

Android's `SettingsProvider` exposes `DeviceConfig` (server-pushed feature flags) to any installed app without enforcing `READ_DEVICE_CONFIG` permission at the server side.

**Root Cause**: The `SettingsProvider.call()` method handler dispatches `CALL_METHOD_GET_CONFIG`, `CALL_METHOD_LIST_CONFIG`, and `CALL_METHOD_LIST_NAMESPACES_CONFIG` requests directly to the config store without any permission check. The `@RequiresPermission(READ_DEVICE_CONFIG)` annotation on the client-side SDK API is a lint-time warning only — it is NOT enforced at runtime by either the ContentProvider framework or the SettingsProvider implementation.

**Source**: `packages/providers/SettingsProvider/src/com/android/providers/settings/SettingsProvider.java`

```java
// Line 437-440 — NO permission check before returning config:
case Settings.CALL_METHOD_GET_CONFIG -> {
    Setting setting = getConfigSetting(name);  // Direct store read
    return packageValueForCallResult(SETTINGS_TYPE_CONFIG, name, requestingUserId, setting, ...);
}
```

The `ContentProvider.Transport.call()` framework path does NOT enforce AppOps or read/write URI permissions for `call()` method dispatch — only `query()`, `insert()`, `update()`, `delete()` are protected by the standard framework permission enforcement.

## Impact

### Who is affected
All Android devices running versions with DeviceConfig (Android 10+). Tested on Android 15/16 (Pixel).

### Attack scenario
1. A zero-permission app (masquerading as a utility, game, etc.) is installed
2. At runtime, it calls `ContentResolver.call("content://settings", "GET_config", ...)` to read all DeviceConfig flags
3. No SecurityException, no user prompt, no permission required

### What is disclosed
- **Security feature kill-switches**: Whether BAL restrictions, permission hub, enhanced confirmation mode, biometric checks, credential manager, device policy engine are enabled/disabled
- **A/B test state**: Internal feature rollout percentages and gate conditions
- **Device fingerprinting**: Unique combination of enabled/disabled flags across namespaces creates a persistent device fingerprint
- **Exploit enablement**: Knowledge of which security features are disabled allows an attacker to craft targeted follow-on exploits (e.g., if `bg_activity_starts_enabled=false`, proceed with BAL bypass attacks knowing they won't be blocked)

### Severity
- **Information Disclosure** → **EoP Enabler** (MEDIUM-HIGH)
- The disclosed information directly enables elevation of privilege by revealing which security defenses are inactive

## Reproduction Steps

### Minimal (ADB, no app install)
```bash
# Read a single DeviceConfig flag:
adb shell content call --uri content://settings --method GET_config --arg "privacy/device_identifier_access_restrictions_enabled"

# List all namespaces:
adb shell content call --uri content://settings --method LIST_NAMESPACES_config

# Dump all flags in a namespace:
adb shell content call --uri content://settings --method LIST_config --arg "privacy"
```

### App-based verification
1. Build and install `apk/` project (ZERO permissions in manifest)
2. Launch "DeviceConfig Leak PoC"
3. Tap "1. List All Namespaces" — observe all DeviceConfig namespaces returned
4. Tap "2. Read Security-Critical Flags" — observe values of security feature toggles
5. Tap "4. Dump ALL Namespaces" — observe full configuration dump

**Expected result (vulnerable)**: Values returned without SecurityException
**Expected result (patched)**: SecurityException with "READ_DEVICE_CONFIG required"

## Fingerprint

| Field | Value |
|-------|-------|
| AOSP Source | `packages/providers/SettingsProvider/src/com/android/providers/settings/SettingsProvider.java` |
| Vulnerable Method | `call()` handler for `CALL_METHOD_GET_CONFIG` (line 437), `CALL_METHOD_LIST_CONFIG`, `CALL_METHOD_LIST_NAMESPACES_CONFIG` |
| Internal Method | `getConfigSetting()` (line 1169) |
| Missing Check | `enforceHasAtLeastOnePermission()` or `checkCallingPermission(READ_DEVICE_CONFIG)` |
| ContentResolver URI | `content://settings` |
| Call Methods | `"GET_config"`, `"LIST_config"`, `"LIST_namespaces_config"` |
| Permission Supposed | `android.permission.READ_DEVICE_CONFIG` (signature\|privileged) |
| Permission Enforced | NONE (lint-only annotation on client) |
| Affected Versions | Android 10+ (DeviceConfig introduction) through Android 16 |
| Tested On | Pixel, Android 15 QPR |

## Suggested Fix

Add server-side permission enforcement in `SettingsProvider.call()` before dispatching config read methods:

```java
case Settings.CALL_METHOD_GET_CONFIG -> {
    getContext().enforceCallingOrSelfPermission(
        Manifest.permission.READ_DEVICE_CONFIG,
        "getCo fig requires READ_DEVICE_CONFIG");
    Setting setting = getConfigSetting(name);
    return packageValueForCallResult(...);
}
```
