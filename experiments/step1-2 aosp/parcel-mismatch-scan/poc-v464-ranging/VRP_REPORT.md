# Android Security Vulnerability Report: IRangingAdapter Permissionless Access

## Title

Missing permission enforcement in Android 16 unified Ranging service allows zero-permission apps to register OOB data listeners, enumerate capabilities, and inject fake lifecycle events

## Severity

HIGH — Bypass of runtime (dangerous) permission requirement for security-sensitive ranging operations

## Affected Component

- **Service**: `ranging` (android.ranging.IRangingAdapter)
- **Module**: com.android.uwb APEX (service-ranging.jar)
- **Implementation**: `com.android.server.ranging.RangingServiceImpl`
- **Introduced**: Android 16 (new unified Ranging service)

## Affected Version

- Android 16 (CP1A.260405.005)
- Security Patch Level: 2026-04-05
- Device: Pixel 10

## Summary

The new unified Ranging service in Android 16 inconsistently enforces the `android.permission.RANGING` permission (protection level: `dangerous`/runtime). Of 13 Binder methods, 6 properly call `enforceRangingPermission()` or `enforceRangingPermissionForPreflight()` before processing, but **7 methods skip permission enforcement entirely**. A zero-permission app can:

1. Register to receive Out-of-Band (OOB) ranging data sent by legitimate ranging sessions
2. Enumerate device ranging capabilities (UWB, BLE CS, WiFi RTT)
3. Inject fake OOB lifecycle events (close/disconnect/reconnect) to disrupt active sessions
4. Inject arbitrary OOB data into the ranging service state machine

## Proof of Concept

### Prerequisites
- Android 16 device (tested: Pixel 10, CP1A.260405.005)
- Zero-permission APK (provided: poc-v464-ranging.apk)

### Steps to Reproduce

1. Install the PoC APK: `adb install poc-v464-ranging.apk`
2. Launch: `adb shell am start -n com.poc.rangingleak/.MainActivity`
3. Observe the results on screen

### Expected Behavior
All ranging operations should require `android.permission.RANGING` (user must explicitly grant this dangerous/runtime permission).

### Actual Behavior
The PoC app (with ZERO permissions declared) successfully:
- Registers an OOB data send listener (TX=13) — returns SUCCESS
- Registers a capabilities callback (TX=7) — returns SUCCESS
- Signals OOB channel closed (TX=12) — returns SUCCESS
- Injects fake OOB data (TX=9) — returns SUCCESS

While the control test (startRanging, TX=1) correctly fails with permission enforcement.

### PoC Output (from zero-permission app, UID 10498)
```
=== V-464: IRangingAdapter Permission Bypass PoC ===
Package: com.poc.rangingleak
UID: 10498
No permissions declared in manifest.

[OK] Got ranging service binder

--- Test 1: registerOobSendDataListener (TX=13) ---
Expected: Permission denial (RANGING is dangerous/runtime)
Result: SUCCESS (no exception)
>>> VULNERABLE — registered OOB listener WITHOUT permission!

--- Test 2: registerCapabilitiesCallback (TX=7) ---
Expected: Permission denial (RANGING is dangerous/runtime)
Result: SUCCESS (no exception)
>>> VULNERABLE — registered capabilities callback WITHOUT permission!

--- Test 3: deviceOobClosed (TX=12) ---
Expected: Permission denial
Result: SUCCESS (no exception)
>>> VULNERABLE — can close OOB channels WITHOUT permission!

--- Test 4: oobDataReceived (TX=9) ---
Expected: Permission denial
Result: SUCCESS (no exception)
>>> VULNERABLE — injected fake OOB data WITHOUT permission!

--- Control: startRanging (TX=1) ---
Expected: Permission enforcement (enforceRangingPermissionForPreflight)
Result: Exception code=-1 msg=Calling uid: 10498 doesn't match source uid: 7274595
>>> CORRECTLY PROTECTED
```

## Root Cause

In `RangingServiceImpl`, methods that perform active ranging operations (start/stop/reconfigure/add/remove) call `enforceRangingPermission()` before delegating to `RangingServiceManager`. However, registration methods and OOB lifecycle methods skip this enforcement:

**Protected (correct):**
```java
// RangingServiceImpl.startRanging
void startRanging(AttributionSource, SessionHandle, RangingPreference, IRangingCallbacks) {
    mRangingInjector.enforceRangingPermissionForPreflight(attributionSource);  // ✓
    mRangingInjector.getRangingServiceManager().startRanging(...);
}
```

**Unprotected (vulnerable):**
```java
// RangingServiceImpl.registerCapabilitiesCallback
void registerCapabilitiesCallback(IRangingCapabilitiesCallback callback) {
    // NO permission check
    mRangingInjector.getRangingServiceManager().registerCapabilitiesCallback(callback);
}

// RangingServiceImpl.registerOobSendDataListener
void registerOobSendDataListener(IOobSendDataListener listener) {
    // NO permission check
    mRangingInjector.getRangingServiceManager().registerOobSendDataListener(listener);
}
```

## Unprotected Methods (7 of 13)

| Runtime TX | Method | Impact |
|---|---|---|
| 7 | registerCapabilitiesCallback | Enumerate UWB/BLE CS/WiFi RTT capabilities |
| 8 | unregisterCapabilitiesCallback | — |
| 9 | oobDataReceived | Inject fake OOB data into ranging state machine |
| 10 | deviceOobDisconnected | Signal disconnection (DoS) |
| 11 | deviceOobReconnected | Inject reconnection events |
| 12 | deviceOobClosed | Signal channel close (DoS) |
| 13 | registerOobSendDataListener | Intercept OOB ranging data |

## Security Impact

### 1. OOB Data Interception
`registerOobSendDataListener` allows any app to register as a receiver of Out-of-Band ranging data. OOB data includes device pairing and ranging configuration exchanged between devices before starting a ranging session. This could expose:
- BLE/WiFi channel information used to bootstrap UWB sessions
- Ranging session configuration parameters
- Data that enables relay attacks on UWB secure ranging

### 2. Ranging Session DoS
`deviceOobClosed` / `deviceOobDisconnected` allow any app to inject fake lifecycle events, potentially disrupting active ranging sessions. UWB ranging is used for:
- Digital car keys
- FindMy-style device tracking
- Secure physical access control

### 3. Capability Fingerprinting
`registerCapabilitiesCallback` reveals all ranging technologies supported by the device (UWB hardware capabilities, BLE Channel Sounding support, WiFi RTT parameters), enabling device fingerprinting.

### 4. OOB Data Injection
`oobDataReceived` allows any app to inject arbitrary data as if it came from an OOB channel, potentially corrupting the ranging service state machine.

## Suggested Fix

Add `enforceRangingPermission()` call at the beginning of all 7 unprotected methods in `RangingServiceImpl`, matching the pattern used by the 6 protected methods:

```java
void registerCapabilitiesCallback(IRangingCapabilitiesCallback callback) {
    mRangingInjector.enforceRangingPermission();  // ADD THIS
    mRangingInjector.getRangingServiceManager().registerCapabilitiesCallback(callback);
}
```

## Files

- `poc-v464-ranging.apk` — Zero-permission PoC APK
- `poc_screenshot.png` — Screenshot of PoC output on Pixel 10
- `app/src/main/java/com/poc/rangingleak/MainActivity.java` — PoC source code
