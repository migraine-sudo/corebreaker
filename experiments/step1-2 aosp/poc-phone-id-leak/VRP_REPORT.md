# Android Security Vulnerability Report: getTypeAllocationCode Zero-Permission Device Identifier Leak

## Title

Missing permission enforcement in TelephonyManager.getTypeAllocationCode() allows zero-permission apps to read persistent hardware identifier (IMEI TAC)

## Severity

MEDIUM — Persistent device identifier accessible without any permission, enabling device fingerprinting and tracking

## Affected Component

- **Service**: `phone` (com.android.internal.telephony.ITelephony)
- **Module**: services.jar + phone process
- **Implementation**: `com.android.phone.PhoneInterfaceManager`
- **Method**: `getTypeAllocationCode()` / `getTypeAllocationCodeForSlot()` (lines ~3728-3741)

## Affected Version

- Android 16 (CP1A.260405.005)
- Security Patch Level: 2026-04-05
- Device: Pixel 10

## Summary

`TelephonyManager.getTypeAllocationCode()` returns the Type Allocation Code (TAC) — the first 8 digits of the device's IMEI — without requiring `READ_PRIVILEGED_PHONE_STATE` or any permission check. The closely related `getImei()` correctly enforces `READ_PRIVILEGED_PHONE_STATE`, demonstrating the inconsistency.

| API | Permission Check | Behavior |
|-----|-----------------|----------|
| `getTypeAllocationCode()` | **NONE** | Returns TAC "35815482" |
| `getTypeAllocationCode(slotIndex)` | **NONE** | Returns TAC "35815482" |
| `getImei()` | READ_PRIVILEGED_PHONE_STATE | SecurityException |
| `getDeviceId()` | READ_PRIVILEGED_PHONE_STATE | SecurityException |
| `getMeid()` | READ_PRIVILEGED_PHONE_STATE | SecurityException |

## Impact

1. **Persistent device identifier**: TAC is derived from IMEI hardware and persists across factory resets, app reinstalls, and user account changes. It cannot be changed by the user.

2. **Device model fingerprinting**: TAC uniquely identifies the device manufacturer, model, and hardware revision. Combined with other identifiers, narrows identification to a specific batch of devices.

3. **Cross-app tracking**: Multiple zero-permission apps from the same ad network can correlate users by comparing TAC values, creating a tracking vector that bypasses Android's advertising ID reset.

4. **Permission model violation**: Android 10+ restricted device identifiers behind `READ_PRIVILEGED_PHONE_STATE` (signature|privileged protection level). TAC being the first 8 digits of IMEI should receive the same protection.

## Proof of Concept

### Prerequisites
- Android 16 device with SIM (tested: Pixel 10, CP1A.260405.005)
- Zero-permission APK (provided: phone-id-leak.apk)

### Steps to Reproduce

1. Install the PoC APK: `adb install phone-id-leak.apk`
2. Launch: `adb shell am start -n com.poc.phoneidleak/.MainActivity`
3. Observe TAC value displayed on screen

### Expected Behavior
`getTypeAllocationCode()` should throw `SecurityException` requiring `READ_PRIVILEGED_PHONE_STATE` (or at minimum `READ_PHONE_STATE`), consistent with `getImei()`.

### Actual Behavior
Returns the TAC string "35815482" without any permission check or user consent.

### PoC Output (zero-permission app, UID 10500)

```
=== PH-1: TAC/MEID Zero-Permission Leak PoC ===
Package: com.poc.phoneidleak
UID: 10500
Permissions: NONE

--- Test 1: getTypeAllocationCode() ---
[VULN] TAC returned: 35815482
  → This is the first 8 digits of IMEI!
  → Identifies exact device model/manufacturer
  → Persistent hardware identifier leaked WITHOUT permission!

--- Test 2: getTypeAllocationCode(0) ---
[VULN] TAC for slot 0: 35815482

--- Control: getImei() (should require permission) ---
[EXPECTED] SecurityException: getImeiForSlot: The uid 10500 does not meet the requirements to access device identifiers.
  → getImei correctly requires READ_PRIVILEGED_PHONE_STATE
```

## Root Cause

In `PhoneInterfaceManager.java`, `getTypeAllocationCode()` (line ~3728) does not call `enforceReadPrivilegedPhoneStatePermissionOrShell()` or `TelephonyPermissions.checkCallingOrSelfReadDeviceIdentifiers()` before accessing the IMEI and extracting its first 8 digits.

Compare with `getImei()` which correctly enforces:
```java
public String getImeiForSlot(int slotIndex, String callingPackage, String callingFeatureId) {
    TelephonyPermissions.checkCallingOrSelfReadDeviceIdentifiers(mApp,
            getSubIdForSlotIndex(slotIndex), callingPackage, callingFeatureId,
            "getImei");
    // ...
}
```

While `getTypeAllocationCode()`:
```java
public String getTypeAllocationCode(int slotIndex) {
    // NO permission check!
    String imei = phone.getImei();
    return imei != null ? imei.substring(0, TYPE_ALLOCATION_CODE_LENGTH) : null;
}
```

## Suggested Fix

Add the same permission enforcement as `getImei()`:

```java
public String getTypeAllocationCode(int slotIndex) {
    TelephonyPermissions.checkCallingOrSelfReadDeviceIdentifiers(mApp,
            getSubIdForSlotIndex(slotIndex), callingPackage, callingFeatureId,
            "getTypeAllocationCode");
    // ... existing logic
}
```

Alternatively, at minimum enforce `READ_PHONE_STATE`:
```java
mApp.enforceCallingOrSelfPermission(
        android.Manifest.permission.READ_PHONE_STATE,
        "getTypeAllocationCode");
```

## TAC Information

- TAC = Type Allocation Code (first 8 digits of 15-digit IMEI)
- Assigned by GSMA to identify device manufacturer and model
- Example: 35815482 → identifies this specific Pixel 10 hardware revision
- Cannot be changed by user or factory reset
- GSMA TAC database maps codes to manufacturer/model/band support
